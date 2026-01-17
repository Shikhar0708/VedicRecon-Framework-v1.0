VERSION = "1.0-BETA"

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
from src.logic_engine import run_logic_engine
from src.scrubbing import PrivacyScrubber
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

# ANSI Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

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
        elif "os details" in line_str.lower(): print(f"    {CYAN}{BOLD}💻 OS DETECTED: {line_str}{RESET}")
        else: print(f"  {prefix} {line_str}")
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
    consent = input(f"{YELLOW}[?]{RESET} Baseline complete. Perform noisy directory enumeration? (y/n): ").lower()
    
    if consent == 'y':
        print(f"{BLUE}[*]{RESET} Launching Phase 6 Muscle (High-Speed Fuzzing)...")
        stream_go_process([str(GO_BINARY), "--registry", str(registry.CSV_FILE), "--fuzz"])

    handoff_to_ai()

def handoff_to_ai():
    """Surgical Intelligence Orchestration: RAW DATA → SCORE → AI → SCRUBBER."""
    print("\n" + "=" * 50)
    print(f"{CYAN}{BOLD}[*] STARTING SURGICAL INTELLIGENCE LAYER{RESET}")
    print("=" * 50)

    analysis_json = OUTPUT_DIR / "analysis_summary.json"
    print(f"{BLUE}[+]{RESET} Phase 7: Correlating infrastructure patterns...")
    analysis = run_logic_engine(registry.CSV_FILE, analysis_json)

    # --- Registry sanity check ---
    df = pd.read_csv(registry.CSV_FILE)
    if df.empty or not analysis.get("inventory"):
        print(f"{RED}[!] Error: No valid targets to score.{RESET}")
        return

    # --- Canonical Target Selection (SINGLE SOURCE OF TRUTH) ---
    target = analysis["inventory"][-1]  # last processed target

    # --- Canonical VMS Input (schema-locked) ---
    vms_input = {
        "ports": target["technical_details"]["ports"],
        "services": target["technical_details"]["services"],
        "banners": target["technical_details"]["os"],
        "is_edge_protected": analysis["global_stats"]["defense_landscape"]["is_edge_protected"],
        "defensive_density": analysis["global_stats"]["defense_landscape"]["defensive_density"],
    }


    # --- Phase 8: Deterministic Scoring ---
    vms_score, findings, edge_opacity = calculate_vms(vms_input)
    analysis["edge_opacity"] = edge_opacity

    # Persist score back to registry (UI / continuity)
    df.at[df.index[-1], "VMS_Score"] = vms_score
    df.to_csv(registry.CSV_FILE, index=False)

    display_vms_gauge({
        "score": vms_score,
        "label": "EXCELLENT" if vms_score >= 80 else "DEVELOPING" if vms_score >= 50 else "CRITICAL",
        "justifications": findings
    })

    # --- Phase 10: AI Intelligence Generation ---
    print(f"{BLUE}[+]{RESET} Phase 10: Generating Intelligence Report (Raw Logic Context)...")
    raw_markdown_report = run_ai_reporting(
        analysis_json,
        REPORTS_DIR,
        AI_PROFILE,
        vms_score,
        node_count=1,
        edge_opacity=edge_opacity
    )

    if not raw_markdown_report:
        print(f"{RED}[!] Reporting failed. Skipping Phase 11.{RESET}")
        return

    # --- Phase 11: Privacy Scrubbing (Post-AI, Final Gate) ---
    print(f"{BLUE}[+]{RESET} Phase 11: Applying privacy filters to final report...")
    final_report_path = REPORTS_DIR / f"VedicRecon_Surgical_Report_{int(time.time())}.md"

    scrubber = PrivacyScrubber(PRIVACY_JSON)
    clean_report = scrubber.scrub(raw_markdown_report)

    with open(final_report_path, "w", encoding="utf-8") as f:
        f.write(clean_report)

    print(f"\n{GREEN}{BOLD}[!] Final Intelligence Report lodged in: {final_report_path}{RESET}")

def display_vms_gauge(vms_data):
    bar_width = 20
    filled = int((vms_data['score'] / 100) * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)
    color = GREEN if vms_data['score'] >= 80 else YELLOW if vms_data['score'] >= 50 else RED
    print(f"\n{BOLD}Infrastructure Maturity Assessment (VMS v1.0){RESET}")
    print(f"{color}[{bar}] {vms_data['score']}/100{RESET} ({BOLD}{vms_data['label']}{RESET})")
    for f in vms_data['justifications']: print(f"  └─ {f}")

def main():
    if not is_privileged():
        print(f"{RED}[!] Error: Run as Root/Admin for raw socket access.{RESET}")
        sys.exit(1)

    print(f"\n{CYAN}{BOLD}--- VedicRecon {VERSION} ---{RESET}")
    os_type = system_detection()

    if not display_legal_boundary.check_status() or not verify_required_tools(os_type):
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
                targets_to_add = [{"Target_Name": f"T_{i}", "Input_Value": t} for i, t in enumerate(expanded_targets)]
                registry.add_targets_to_registry(targets_to_add)
                if input(f"{YELLOW}[?]{RESET} Launch discovery pipeline now? (y/n): ").lower() == 'y':
                    run_discovery_pipeline()
                    break
        elif choice == "2":
            run_discovery_pipeline()
            break
        elif choice == "3":
            if input(f"{RED}[!] Clear workspace? (y/n): {RESET}").lower() == 'y':
                for f in OUTPUT_DIR.glob('*'): f.unlink() if f.is_file() else None
                print(f"{GREEN}[+]{RESET} Workspace cleaned.")
        elif choice == "0": break

if __name__ == "__main__":
    main()