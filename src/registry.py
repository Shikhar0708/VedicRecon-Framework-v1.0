import pandas as pd
from pathlib import Path
import hashlib
import os
import sys
import json
import ipaddress
import time

# --- CONFIGURATIONS ---

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = BASE_DIR / "output" / "VedicRecon_targets.csv"

# Integrity and session management
INTEGRITY_DIR = BASE_DIR / ".runtime_integrity"
HASH_FILE = INTEGRITY_DIR / "integrity.sha256"
META_FILE = INTEGRITY_DIR / "session.meta.json"
LOCK_FILE = INTEGRITY_DIR / ".lock"

CI_MODE = os.getenv("VEDIRECON_CI", "false").lower() == "true"
TOOL_VERSION = "1.0.0-alpha"
SCHEMA_VERSION = "1.0"

SCHEMA_HEADERS = [
    "Target_ID", "Target_Name", "Input_Value", "Scope_Status",
    "Resolved_IP", "OS_Tech", "Open_Ports", "Services",
    "Auth_Method", "Notes"
]

# --- UTILITIES ---

def exit_with(code: int, msg: str):
    print(msg)
    sys.exit(code)

def calculate_hash(path: Path) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def schema_hash() -> str:
    return hashlib.sha256(",".join(SCHEMA_HEADERS).encode()).hexdigest()

# --- LOCKING ---

def acquire_lock():
    INTEGRITY_DIR.mkdir(mode=0o700, exist_ok=True)
    if LOCK_FILE.exists():
        # Check if PID is still active; if not, stale lock
        try:
            pid = int(LOCK_FILE.read_text())
            os.kill(pid, 0)
            exit_with(30, "[!] Registry lock exists. Another process is running.")
        except (ProcessLookupError, ValueError):
            LOCK_FILE.unlink()
    LOCK_FILE.write_text(str(os.getpid()))

def release_lock():
    if LOCK_FILE.exists():
        LOCK_FILE.unlink()

# --- SESSION STATE ---

def get_session_state():
    if not CSV_FILE.exists():
        return "NEW"
    if not HASH_FILE.exists() or not META_FILE.exists():
        return "CORRUPTED"

    try:
        meta = json.loads(META_FILE.read_text())
        current_hash = calculate_hash(CSV_FILE)
        
        if current_hash != meta.get("sha256") or meta.get("schema_hash") != schema_hash():
            return "CORRUPTED"
    except Exception:
        return "CORRUPTED"

    return "HEALTHY"

# --- SESSION MANAGEMENT ---

def seal_session():
    """Calculates hash and metadata for the current CSV state."""
    if not CSV_FILE.exists():
        return
    sha = calculate_hash(CSV_FILE)
    meta = {
        "sha256": sha,
        "size": CSV_FILE.stat().st_size,
        "schema_hash": schema_hash(),
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    HASH_FILE.write_text(sha)
    META_FILE.write_text(json.dumps(meta, indent=2))

def initialize_new_session():
    """Forces a fresh registry creation."""
    INTEGRITY_DIR.mkdir(mode=0o700, exist_ok=True)
    CSV_FILE.parent.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(columns=SCHEMA_HEADERS)
    df.to_csv(CSV_FILE, index=False)
    seal_session()
    print("[+] New registry session initialized.")

def session_handler():
    """Handles the logic of Resume vs New at startup."""
    acquire_lock()
    try:
        state = get_session_state()

        if state == "CORRUPTED":
            print("[!] Registry corruption detected!")
            initialize_new_session()
            return "NEW"

        if state == "HEALTHY":
            while True:
                choice = input("[?] Existing registry found. (R)esume or (N)ew session? ").lower()
                if choice == "n":
                    initialize_new_session()
                    return "NEW"
                elif choice == "r":
                    print("[+] Resuming verified registry.")
                    run_now = input("[?] Pipeline all resumed targets now? (y/n): ").lower()
                    return "RUN_NOW" if run_now == 'y' else "RESUMED"
                else:
                    print("[-] Invalid selection.")
        
        # State is NEW
        initialize_new_session()
        return "NEW"

    finally:
        release_lock()

# --- TARGET MANAGEMENT ---

def add_targets_to_registry(targets_data: list):
    """Appends new targets. Initializes the CSV if missing."""
    if not targets_data:
        return

    acquire_lock()
    try:
        # Self-healing: If the file is missing, initialize it
        if not CSV_FILE.exists():
            df = pd.DataFrame(columns=SCHEMA_HEADERS)
        else:
            df = pd.read_csv(CSV_FILE)
        
        start_id = len(df) + 1
        new_entries = []
        
        for i, target in enumerate(targets_data):
            entry = {h: "TBD" for h in SCHEMA_HEADERS}
            entry.update(target)
            entry["Target_ID"] = f"TR-{start_id + i:03}"
            entry["Scope_Status"] = "PENDING"
            new_entries.append(entry)

        updated_df = pd.concat([df, pd.DataFrame(new_entries)], ignore_index=True)
        updated_df.to_csv(CSV_FILE, index=False)
        seal_session()
        print(f"[+] Successfully registered {len(new_entries)} targets.")
        
    finally:
        release_lock()