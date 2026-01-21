from src import __version__ as VERSION
import platform
import sys
import subprocess
import time
from pathlib import Path
import json
import shutil
import ctypes
import os
import pandas as pd
import re
import ipaddress
from markdown_pdf import MarkdownPdf, Section
from rich.console import Console
from rich.markdown import Markdown
from src.logic_engine import run_logic_engine, build_fleet_exposure_table
from src.scrubbing import PrivacyScrubber
from src.ai_handler import run_ai_reporting
from src import display_legal_boundary, registry, bulk_input_registry, bulk_vms_runner
from src.vms_engine import calculate_vms

# --- PATH CONFIGURATION ---
BASE_DIR = Path(__file__).resolve().parent
GO_BINARY = BASE_DIR / "bin" / ("vr_core_linux" if platform.system() == "Linux" else "vr_core_win.exe")
WORDLIST_DIR = BASE_DIR / "config" / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "common.txt"

# Configurations
AI_PROFILE = BASE_DIR / "config" / "ai_profile.json"
PRIVACY_JSON = BASE_DIR / "config" / "privacy.json"

# Data Storage
OUTPUT_DIR = BASE_DIR / "output"
REPORTS_DIR = BASE_DIR / "reports"

# ANSI Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


if platform.system() == "Windows":
    # This enables ANSI processing in the Windows console
    os.system('color')
#domain_validation
DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_REGEX.fullmatch(value))

#ipv4-look-alike issue resolved

def looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() for p in parts)


#Root/admin validation

def is_privileged():
    if platform.system() == "Windows":
        try: return ctypes.windll.shell32.IsUserAnAdmin()
        except: return False
    return os.geteuid() == 0

def system_detection():
    current_os = platform.system()
    print(f"{BLUE}[+]{RESET} Detected operating system: {current_os}")
    if current_os == "Darwin":
        print(f"{RED}[-]{RESET} Error: VedicRecon is not available for macOS.")
        sys.exit(1)
    return current_os.lower()

def verify_required_tools(os_type):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH = BASE_DIR / "config" / "wrapper.json"
    try:
        with open(CONFIG_PATH, 'r') as file:
            config = json.load(file)
        packages = config.get(f"Packages_{os_type}", [])
        print(f"{BLUE}[*]{RESET} Checking requirements for {os_type}...")
        for tool in packages:
            if shutil.which(tool) is None:
                print(f"    {RED}[!] {tool} not found!{RESET}")
                return False
            print(f"    {GREEN}[OK]{RESET} {tool} found.")
        return True
    except FileNotFoundError:
        return False

def stream_go_process(args, prefix="> "):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in process.stdout:
        line_str = line.strip()
        if "open port" in line_str.lower(): print(f"    {GREEN}[PORT FOUND]{RESET} {line_str}")
        elif "os details" in line_str.lower(): print(f"    {CYAN}{BOLD}OS DETECTED: {line_str}{RESET}")
        else: print(f"  {prefix} {line_str}")
    process.stdout.close()
    process.wait()
    return process.returncode

def run_discovery_pipeline():
    if not GO_BINARY.exists():
        print(f"{RED}[!] Error: Go binary missing.{RESET}")
        return

    print(f"\n{BLUE}[*]{RESET} Discovery mode selection")

    mode = input(
        f"{YELLOW}[?]{RESET} Select scan mode:\n"
        "  1. Full scan (default)\n"
        "  2. Single-port diagnostic scan (-port)\n"
        "Choice [1/2]: "
    ).strip()

    cmd = [str(GO_BINARY), "--registry", str(registry.CSV_FILE)]

    if mode == "2":
        port = input(f"{YELLOW}[?]{RESET} Enter port number (1–65535): ").strip()

        if not port.isdigit() or not (1 <= int(port) <= 65535):
            print(f"{RED}[!] Invalid port. Aborting scan.{RESET}")
            return

        cmd.extend(["--port", port])
        print(f"{BLUE}[*]{RESET} Running single-port diagnostic scan on port {port}...")
    else:
        print(f"{BLUE}[*]{RESET} Running aggressive discovery (Phases 2, 4, 5)...")

    stream_go_process(cmd)

    # 2. Consent Gate (Phase 6)
    print("\n" + "="*50)
    time.sleep(0.5) # Buffer synchronization
    if platform.system() == "Windows":
        consent="n"
    else:
        consent = input(f"{YELLOW}[?]{RESET} Baseline complete. Perform noisy directory enumeration? (y/n): ").lower()
    
        if consent == 'y':
            print(f"{BLUE}[*]{RESET} Launching Phase 6 Muscle (High-Speed Fuzzing)...")
            stream_go_process([str(GO_BINARY), "--registry", str(registry.CSV_FILE), "--fuzz"])

    handoff_to_ai()

def run_bulk_discovery_pipeline():
    if not GO_BINARY.exists():
        print("[!] Go binary missing.")
        return

    df = pd.read_csv(registry.CSV_FILE)
    if df.empty:
        print("[!] Registry is empty. Add targets first.")
        return

    print(
        f"\n{CYAN}{BOLD}[+] Starting BULK fleet discovery "
        f"({len(df)} targets){RESET}"
    )

    # SINGLE INVOCATION — Go handles ports internally
    cmd = [
        str(GO_BINARY),
        "--registry",
        str(registry.CSV_FILE),
    ]

    stream_go_process(cmd)

    print(f"\n{GREEN}[+] Bulk discovery completed for all targets.{RESET}")
    handoff_to_ai()


def handoff_to_ai():
    """Surgical Intelligence Orchestration: RAW DATA → BULK VMS → AI → SCRUBBER."""
    print("\n" + "=" * 50)
    print(f"{CYAN}{BOLD}[*] STARTING SURGICAL INTELLIGENCE LAYER{RESET}")
    print("=" * 50)

    analysis_json = OUTPUT_DIR / "analysis_summary.json"

    # --- Phase 7: Logic Correlation ---
    print(f"{BLUE}[+]{RESET} Phase 7: Correlating infrastructure patterns...")
    analysis = run_logic_engine(registry.CSV_FILE, analysis_json)

    # --- Phase 8: BULK VMS (AUTHORITATIVE) ---
    analysis["inventory"] = bulk_vms_runner.run_bulk_vms(analysis["inventory"])
    node_count = len(analysis["inventory"])

    if node_count == 0:
        print(f"{RED}[!] Error: No valid targets to score.{RESET}")
        return

    # --- Fleet Exposure Table (Deterministic) ---
    analysis["fleet_exposure"] = build_fleet_exposure_table(
        analysis["inventory"]
    )

    # CRITICAL: Persist FINAL analysis for AI consumption
    with open(analysis_json, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=4)

    # --- Reporting Anchor Selection ---
    # Strategy: worst-scoring node (most critical exposure)
    primary_node = min(
        analysis["inventory"],
        key=lambda n: n.get("vms", {}).get("score", 100)
    )

    primary_vms = primary_node["vms"]

    # --- UI Continuity (non-authoritative) ---
    display_vms_gauge({
        "score": primary_vms["score"],
        "label": (
            "EXCELLENT" if primary_vms["score"] >= 80 else
            "DEVELOPING" if primary_vms["score"] >= 50 else
            "CRITICAL"
        ),
        "justifications": primary_vms["findings"]
    })

    # --- Phase 10: AI Intelligence Generation ---
    print(f"{BLUE}[+]{RESET} Phase 10: Generating Intelligence Report (Bulk Context)...")
    raw_markdown_report = run_ai_reporting(
        analysis_json,
        REPORTS_DIR,
        AI_PROFILE,
        primary_vms["score"],
        node_count=node_count,
        edge_opacity=primary_vms["edge_opacity"]
    )

    if not raw_markdown_report:
        print(f"{RED}[!] Reporting failed. Skipping Phase 11.{RESET}")
        return

    # --- Phase 11: Privacy Scrubbing (Final Gate) ---
    print(f"{BLUE}[+]{RESET} Phase 11: Applying privacy filters to final report...")
    final_report_path = REPORTS_DIR / f"VedicRecon_Surgical_Report_{int(time.time())}.md"

    scrubber = PrivacyScrubber(PRIVACY_JSON)
    clean_report = scrubber.scrub(raw_markdown_report)

    with open(final_report_path, "w", encoding="utf-8") as f:
        f.write(clean_report)

    print(f"\n{GREEN}{BOLD}[!] Final Intelligence Report lodged in: {final_report_path}{RESET}")
    print(f"[*] Opening report:{final_report_path}")
    time.sleep(2)
    prettified_markdown(final_report_path)



def display_vms_gauge(vms_data):
    bar_width = 20
    filled = int((vms_data['score'] / 100) * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)
    color = GREEN if vms_data['score'] >= 80 else YELLOW if vms_data['score'] >= 50 else RED
    print(f"\n{BOLD}Infrastructure Maturity Assessment (VMS v1.0){RESET}")
    print(f"{color}[{bar}] {vms_data['score']}/100{RESET} ({BOLD}{vms_data['label']}{RESET})")
    for f in vms_data['justifications']: print(f"  └─ {f}")

def prettified_markdown(filename):
    console = Console(width=100)
    try:
        # 1. Read the raw text for the PDF engine
        with open(filename, "r") as report:
            raw_markdown_text = report.read()
        
        # 2. Prepare the Rich object for terminal viewing
        rich_content = Markdown(raw_markdown_text)
        
        print("[*] Finalising contents...")
        time.sleep(2) # Reduced sleep for better UX
        
        print("\n[?] Action Required:")
        print("1. Generate PDF Report")
        print("2. View in Terminal Only")
        consent_input = input("Choice: ").strip()
        
        if consent_input == "1":
            print("[+] Generating Consolidated PDF...")
            
            # Initialize PDF engine
            pdf = MarkdownPdf()
            
            # Add the entire report as one section
            pdf.add_section(Section(raw_markdown_text))
            
            # Define output path (Cleaned .md extension)
            pdf_out = REPORTS_DIR / "pdf-converted-reports" / f"{Path(filename).stem}.pdf"
            
            # Ensure directory exists
            pdf_out.parent.mkdir(parents=True, exist_ok=True)
            
            # Save the single PDF
            pdf.save(str(pdf_out))
            print(f"[+] Report exported: {pdf_out.name}")
            
        elif consent_input == "2":
            print("[*] Skipping PDF generation.")
        else:
            print("[-] Invalid choice. Proceeding to terminal view.")

        # 3. Always display the beautiful terminal version
        console.print(rich_content)

    except Exception as e:
        print(f"[!] Reporting Error: {e}")

def main():
    if not is_privileged():
        print(f"{RED}[!] Error: Run as Root/Admin for raw socket access.{RESET}")
        sys.exit(1)

    print(f"\n{CYAN}{BOLD}--- VedicRecon {VERSION} ---{RESET}")
    os_type = system_detection()
        # Level 1: Legal Check
    if display_legal_boundary.check_status():
        
        # Level 2: Tool Check (Only runs if Legal passed)
        if verify_required_tools(os_type):
            print(f"{GREEN}[+]{RESET} System integrity verified. Launching...")
            # Continue to Session Handling
            
        else:
            print(f"{RED}[!] Error: Required tools (Nmap/FFUF) are missing.{RESET}")
            sys.exit(1)
            
    else:
        print(f"{RED}[!] Error: Legal boundary must be accepted.{RESET}")
        sys.exit(1)


    session_signal = registry.session_handler()
    if session_signal == "RUN_NOW":
        run_discovery_pipeline()
        sys.exit(0)

    while True:
        print(f"\n{BOLD}[VedicRecon Station]{RESET}")
        print("1. Add New Target(s)")
        print("2. Bulk input(expected file type : txt)")
        print("3. Clear Workspace (/output)")
        print("0. Exit")
        
        choice = input(f"\n{YELLOW}[?]{RESET} Select Option: ").strip()
        if choice == "1":

            raw_val = input(
                f"\n{YELLOW}[?]{RESET} Enter target (IP / CIDR / Domain): "
            ).strip()

            if not raw_val:
                print("[-] Empty input. Aborting.")
                continue

            try:
                ipaddress.ip_address(raw_val)
                target_type = "IP"

            except ValueError:
                try:
                    ipaddress.ip_network(raw_val, strict=False)
                    target_type = "CIDR"

                except ValueError:
                    # block IPv4-shaped garbage
                    if looks_like_ipv4(raw_val):
                        print("[-] Invalid IPv4 address.")
                        continue

                    if is_valid_domain(raw_val):
                        target_type = "DOMAIN"
                    else:
                        print("[-] Invalid target format.")
                        continue

            target_entry = {
                "Target_Name": raw_val,
                "Input_Value": raw_val,
                "Notes": f"Declared as {target_type}"
            }

            registry.add_targets_to_registry([target_entry])

            if input(
                f"{YELLOW}[?]{RESET} Launch discovery pipeline now? (y/n): "
            ).lower() == "y":
                run_discovery_pipeline()

            break

        elif choice == "2":
            file_name=input("[+] Enter file name (from /targets):").strip()
            file_path=BASE_DIR/"targets"/file_name
            if file_path.exists():
                print(f"[+] Found file {file_path}")
                bulk_input_registry.bulk_input_file(file_path)
                if input(
                    f"{YELLOW}[?]{RESET} Launch discovery pipeline now? (y/n): "
                ).lower() == "y":
                    run_bulk_discovery_pipeline()
                break
            else:
                print(f"[!] File not found: {file_path}")
                continue
        elif choice == "3":
            if input(f"{RED}[!] Clear workspace? (y/n): {RESET}").lower() == 'y':
                for f in OUTPUT_DIR.glob('*'): f.unlink() if f.is_file() else None
                print(f"{GREEN}[+]{RESET} Workspace cleaned.")
        elif choice == "0": break

if __name__ == "__main__":
    main()