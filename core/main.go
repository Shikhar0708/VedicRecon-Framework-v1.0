package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
)

// --- CONFIG STRUCT (must match profiles.json) ---
type Config struct {
	Nmap struct {
		ScanProfiles map[string]struct {
			Flags string `json:"flags"`
		} `json:"scan_profiles"`
	} `json:"nmap"`

	Ffuf struct {
		Profiles map[string]struct {
			Threads    int     `json:"threads"`
			Delay      float64 `json:"delay"`
			Extensions string  `json:"extensions"`
		} `json:"profiles"`
	} `json:"ffuf"`
}

func main() {
	// ---------------- FLAGS ----------------
	registryPath := flag.String("registry", "", "Path to targets.csv (required)")
	configPath := flag.String("config", "config/profiles.json", "Path to profiles.json")
	wordlistPath := flag.String("wordlist", "", "Path to wordlist (Phase 6)")
	fuzzEnabled := flag.Bool("fuzz", false, "Execute Phase 6 enumeration")
	port := flag.String("port", "", "Scan a single port only (diagnostic mode)")

	flag.Parse()

	// ---------------- VALIDATION ----------------
	if *registryPath == "" {
		fmt.Println("[!] Error: --registry path is required.")
		os.Exit(1)
	}

	// ---------------- LOAD CONFIG ----------------
	cfgFile, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Printf("[!] Critical: Could not read config at %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	var cfg Config
	if err := json.Unmarshal(cfgFile, &cfg); err != nil {
		fmt.Printf("[!] Critical: Invalid JSON in %s: %v\n", *configPath, err)
		os.Exit(1)
	}

	// ---------------- OPEN REGISTRY ----------------
	file, err := os.Open(*registryPath)
	if err != nil {
		fmt.Printf("[!] Critical: Could not open registry at %s: %v\n", *registryPath, err)
		os.Exit(1)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Read() // skip header

	// ---------------- CONCURRENCY CONTROL ----------------
	// Hard cap: 5 concurrent scans (safe for laptops / VPS)
	semaphore := make(chan struct{}, 5)
	var wg sync.WaitGroup

	// ---------------- PROCESS TARGETS ----------------
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 3 {
			continue
		}

		targetID := record[0]
		targetIP := record[2]

		wg.Add(1)
		go func(id, ip string) {
			defer wg.Done()

			semaphore <- struct{}{}        // acquire
			defer func() { <-semaphore }() // release

			if !*fuzzEnabled {
				// --- PHASES 2 / 4 / 5 ---
				RunRecon(
					ip,
					id,
					cfg.Nmap.ScanProfiles["framework_aggressive"].Flags,
					*registryPath,
					*port, // diagnostic override (may be empty)
				)
			} else {
				// --- PHASE 6: ENUMERATION ---
				if *wordlistPath != "" {
					profile := cfg.Ffuf.Profiles["stealth"]
					RunEnumeration(
						ip,
						*wordlistPath,
						"stealth",
						profile.Extensions,
						profile.Threads,
						profile.Delay,
					)
				}
			}
		}(targetID, targetIP)
	}

	wg.Wait()
	fmt.Println("\n[+] All targets in registry processed.")
}
