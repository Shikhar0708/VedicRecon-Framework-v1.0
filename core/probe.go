package main

import (
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RunRecon handles Phase 2, 4, and 5 sequentially and updates the central registry
func RunRecon(target string, id string, flags string, registryPath string, port string) {
	fmt.Printf("\n--- [ PHASE 2: BASELINE RECON | %s ] ---\n", id)

	// 1. Execute Nmap and capture the output
	args := []string{}

	if flags != "" {
		args = append(args, strings.Fields(flags)...)
	}

	// 🔬 SINGLE-PORT OVERRIDE (diagnostic-safe)
	if port != "" && !strings.Contains(flags, "-p-") {
		args = append(args, "-p", port)
	}

	args = append(args, target)
	//debug the nmap command
	fmt.Printf("[DEBUG] Final nmap args: %v\n", args)

	out, err := exec.Command("nmap", args...).CombinedOutput()
	nmapOutput := string(out)

	if err != nil {
		fmt.Printf("[!] Nmap returned warnings for %s (continuing): %v\n", target, err)
	}

	// --- DATA EXTRACTION ---
	foundPorts := "FILTERED"
	foundServices := "TBD"
	osTech := "DETECTION_FAILED"

	var ports []string
	var services []string

	lines := strings.Split(nmapOutput, "\n")
	for _, line := range lines {
		// Extract Open Ports & Service Names (e.g., "22/tcp open ssh")
		if strings.Contains(line, "/tcp") && (strings.Contains(line, "open") || strings.Contains(line, "tcpwrapped")) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ports = append(ports, parts[0])

				// tcpwrapped has no service column
				if parts[1] == "tcpwrapped" {
					services = append(services, "tcpwrapped")
				} else if len(parts) >= 3 {
					services = append(services, parts[2])
				}
			}

		}
		// Extract OS Guess
		if strings.Contains(line, "OS details:") || strings.Contains(line, "Running:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				osTech = strings.TrimSpace(parts[1])
			}
		}
	}

	if len(ports) > 0 {
		foundPorts = strings.Join(ports, "|")
	}
	if len(services) > 0 {
		foundServices = strings.Join(services, "|")
	}

	// --- PHASE 4 & 5: Web Routing (HTTPS First Logic) ---
	fmt.Printf("[*] Launching Phase 4/5: Banner & WAF Grabbing for %s\n", target)
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			// InsecureSkipVerify is vital for internal/lab pentesting
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var resp *http.Response
	var webErr error

	// Try HTTPS first
	url := "https://" + target
	if port != "" && port != "443" {
		url = fmt.Sprintf("https://%s:%s", target, port)
	}

	resp, webErr = client.Get(url)
	if webErr != nil {
		url = "http://" + target
		if port != "" && port != "80" {
			url = fmt.Sprintf("http://%s:%s", target, port)
		}
		resp, webErr = client.Get(url)
	}

	if webErr == nil && resp != nil {
		defer resp.Body.Close()
		serverHeader := resp.Header.Get("Server")

		// Identify WAF / CDN signals for the Logic Engine
		wafSignal := ""
		if resp.Header.Get("CF-RAY") != "" {
			wafSignal = "Cloudflare"
		}
		if resp.Header.Get("X-Akamai-Transformed") != "" {
			wafSignal = "Akamai"
		}
		if strings.Contains(strings.ToLower(serverHeader), "cloudflare") {
			wafSignal = "Cloudflare"
		}

		if serverHeader != "" {
			if osTech == "DETECTION_FAILED" {
				osTech = serverHeader
			} else {
				osTech = fmt.Sprintf("%s (%s)", osTech, serverHeader)
			}
		}

		// Annotate OS_Tech with WAF detection if present
		if wafSignal != "" {
			osTech = fmt.Sprintf("%s [EDGE: %s]", osTech, wafSignal)
		}
	}

	// --- THE CRITICAL STEP: Update the CSV ---
	err = UpdateRegistry(registryPath, id, osTech, foundPorts, foundServices, "ACTIVE")

	if err != nil {
		fmt.Printf("[!] CSV Update Failed for %s: %v\n", id, err)
	} else {
		fmt.Printf("[+] Registry Synchronized: %s -> Ports: [%s] | Services: [%s]\n", id, foundPorts, foundServices)
	}
}

// UpdateRegistry opens the CSV, finds the Target_ID, and overwrites TBD values
func UpdateRegistry(path string, id string, osTech string, ports string, services string, status string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	f.Close()
	if err != nil {
		return err
	}

	found := false
	for i, row := range records {
		if row[0] == id {
			records[i][3] = status   // Scope_Status
			records[i][5] = osTech   // OS_Tech
			records[i][6] = ports    // Open_Ports
			records[i][7] = services // Services
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("Target ID %s not found in registry", id)
	}

	// Write back to the CSV
	f, err = os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	err = writer.WriteAll(records)
	if err != nil {
		return err
	}
	writer.Flush()
	return nil
}
