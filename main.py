VERSION = "1.0.1-alpha"

import platform
import sys
import subprocess
from pathlib import Path
import json
import shutil
import ctypes
import os
from src.logic_engine import run_logic_engine
from src.scrubbing import run_scrubbing_phase
from src.ai_handler import run_ai_reporting
from src import display_legal_boundary, registry
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

# ANSI Colors for "World-Class" UI
GREEN = "\033[92m"
CYAN = "\033[96m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def is_privileged():
    """
    Check if the script is running with elevated privileges (root on Linux/macOS, 
    administrator on Windows).
    """
    system = platform.system()
    
    if system == "Windows":
        try:
            # Returns True if running with admin rights
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        # On Linux/macOS, check for effective user ID 0 (root)
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
        print(f"{RED}[!] config/wrapper.json missing!{RESET}")
        return False

def stream_go_process(args, prefix="> "):
    """Captures Go binary output and prints it with pretty formatting."""
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    for line in process.stdout:
        line_str = line.strip()
        # Pretty Interceptors for Nmap discovery
        if "open port" in line_str.lower():
            print(f"    {GREEN}[PORT FOUND]{RESET} {line_str}")
        elif "os details" in line_str.lower() or "os match" in line_str.lower():
            print(f"    {CYAN}{BOLD}💻 OS DETECTED: {line_str}{RESET}")
        elif "phase 6 hit" in line_str.lower():
            print(f"    {YELLOW}{BOLD}[FUZZ HIT]{RESET} {line_str}")
        else:
            print(f"  {prefix} {line_str}")

    process.wait()
    return process.returncode

def run_discovery_pipeline():
    if not GO_BINARY.exists():
        print(f"{RED}[!] Error: Go binary missing at {GO_BINARY}{RESET}")
        return

    # 1. Baseline Discovery (Aggressive Nmap via Go)
    print(f"\n{BLUE}[*]{RESET} Running Aggressive Discovery (Phases 2, 4, 5)...")
    stream_go_process([str(GO_BINARY), "--registry", str(registry.CSV_FILE)])

    # 2. THE CONSENT GATE (Phase 6)
    print("\n" + "="*50)
    consent = input(f"{YELLOW}[?]{RESET} Baseline complete. Perform noisy directory enumeration? (y/n): ").lower()
    
    if consent == 'y':
        if not DEFAULT_WORDLIST.exists():
            print(f"{RED}[!] Wordlist missing at {DEFAULT_WORDLIST}. Skipping Phase 6.{RESET}")
        else:
            print(f"{BLUE}[*]{RESET} Launching Phase 6 Muscle (High-Speed Fuzzing)...")
            stream_go_process([
                str(GO_BINARY), 
                "--registry", str(registry.CSV_FILE),
                "--wordlist", str(DEFAULT_WORDLIST),
                "--fuzz" 
            ])

    # 3. Intelligence Layer Handoff
    handoff_to_ai()

def handoff_to_ai():
    print("\n" + "="*50)
    print(f"{CYAN}{BOLD}[*] STARTING INTELLIGENCE LAYER{RESET}")
    print("="*50)

    analysis_json = OUTPUT_DIR / "analysis_summary.json"
    print(f"{BLUE}[+]{RESET} Phase 7: Correlating infrastructure patterns...")
    analysis = run_logic_engine(registry.CSV_FILE, analysis_json)

    if not isinstance(analysis, dict):
        raise ValueError("Logic engine did not return analysis summary dict")

    # ✅ Compute VMS ONCE, after analysis exists
    vms_score = calculate_vms(analysis)

    # Trigger the VMS Gauge visually
    if "target_registry_snapshot" in analysis:
        display_vms_gauge({
            "score": vms_score,
            "label": (
                "EXCELLENT" if vms_score >= 80 else
                "DEVELOPING" if vms_score >= 50 else
                "CRITICAL"
            ),
            "justifications": ["Derived from observable infrastructure signals"]
        })

    scrubbed_txt = OUTPUT_DIR / "scrubbed_analysis.txt"
    print(f"{BLUE}[+]{RESET} Phase 9: Anonymizing identifiers...")
    run_scrubbing_phase(analysis_json, scrubbed_txt, PRIVACY_JSON)

    print(f"{BLUE}[+]{RESET} Phase 10: Generating Intelligence Report...")
    print(f"{BLUE}[+]{RESET} Computed VMS Score: {vms_score}/100")

    run_ai_reporting(scrubbed_txt, REPORTS_DIR, AI_PROFILE, vms_score)

    print(f"\n{GREEN}{BOLD}[!] Final Intelligence Report lodged in: {REPORTS_DIR}{RESET}")

def display_vms_gauge(vms_data):
    bar_width = 20
    filled = int((vms_data['score'] / 100) * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)
    
    color = RED
    if vms_data['score'] >= 80: color = GREEN
    elif vms_data['score'] >= 50: color = YELLOW

    print(f"\n{BOLD}Infrastructure Maturity Assessment (VMS v1.0){RESET}")
    print(f"{color}[{bar}] {vms_data['score']}/100{RESET} ({BOLD}{vms_data['label']}{RESET})")
    for note in vms_data['justifications']:
        print(f"  └─ {note}")
    print("")

def main():
    if is_privileged():
        print(f"\n{CYAN}{BOLD}--- VedicRecon {VERSION} ---{RESET}")
        os_type = system_detection()

        if not display_legal_boundary.check_status():
            sys.exit(0)

        if not verify_required_tools(os_type):
            sys.exit(1)

        session_signal = registry.session_handler()

        if session_signal == "RUN_NOW":
            run_discovery_pipeline()
            sys.exit(0)

        while True:
            print(f"\n{BOLD}[VedicRecon Station]{RESET}")
            print("1. Add New Target(s)")
            print("2. Run Pipeline on All Registered Targets")
            print("3. Clear Workspace (/output)")
            print("0. Exit")
            
            choice = input(f"\n{YELLOW}[?]{RESET} Select Option: ").strip()

            if choice == "1":
                raw_val = input(f"\n{YELLOW}[?]{RESET} Enter IP, CIDR, or File Path: ").strip()
                from src.registry import parse_bulk_input
                expanded_targets = parse_bulk_input(raw_val)
                if expanded_targets:
                    targets_to_add = [{"Target_Name": f"Import_{i+1}", "Input_Value": t} for i, t in enumerate(expanded_targets)]
                    registry.add_targets_to_registry(targets_to_add)
                    if input(f"{YELLOW}[?]{RESET} Launch discovery pipeline now? (y/n): ").lower() == 'y':
                        run_discovery_pipeline()
                        break
            elif choice == "2":
                run_discovery_pipeline()
                break
            elif choice == "3":
                if input(f"{RED}[!] Clear all files in /output? (y/n): {RESET}").lower() == 'y':
                    for file in OUTPUT_DIR.glob('*'):
                        if file.is_file(): file.unlink()
                    print(f"{GREEN}[+]{RESET} Workspace cleaned.")
            elif choice == "0":
                break
    else:
        print("[*] Admin/Root privilege is needed.")

if __name__ == "__main__":
    main()