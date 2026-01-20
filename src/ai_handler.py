import json
import time
import sys
import threading
import re
import random
from pathlib import Path
from datetime import datetime
from google import genai
from google.genai import types
from .policy_compiler import PolicyCompiler



# === HARD ZERO-KNOWLEDGE AI BOUNDARY ===
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

VENDOR_BLOCKLIST = [
    "cloudflare",
    "akamai",
    "fastly",
    "imperva",
    "aws",
    "azure",
    "gcp",
]

def enforce_zero_knowledge(text: str) -> str:
    text = IPV4_REGEX.sub("T_0", text)
    text = IPV6_REGEX.sub("T_0", text)

    for vendor in VENDOR_BLOCKLIST:
        text = re.sub(
            rf"\b{vendor}\b",
            "an opaque edge provider",
            text,
            flags=re.IGNORECASE
        )
    return text

def enforce_semantic_safety(text: str) -> str:
    # Prevent hard assertions on low-confidence services
    text = re.sub(
        r"\b(ppp|rpcbind|unknown)\b.*?(exploitable|vulnerable|dangerous)",
        "an unverified service with indeterminate risk",
        text,
        flags=re.IGNORECASE
    )
    return text

class ProgressDisplay:
    """Handles foreground animation and time estimation for the Intelligence Layer."""
    def __init__(self, estimate=20):
        self.estimate = estimate
        self.stop_event = threading.Event()
        self.start_time = time.time()

    def animate(self):
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0
        while not self.stop_event.is_set():
            elapsed = int(time.time() - self.start_time)
            percent = min(99, int((elapsed / self.estimate) * 100))
            bar_size = 20
            pos = elapsed % bar_size
            bar = ["-"] * bar_size
            bar[pos] = "#"
            bar_str = "".join(bar)

            sys.stdout.write(
                f"\r  {chars[idx % len(chars)]} [ {bar_str} ] {percent}% | ETC: {max(0, self.estimate - elapsed)}s remaining... "
            )
            sys.stdout.flush()
            idx += 1
            time.sleep(0.1)

    def stop(self):
        self.stop_event.set()
        sys.stdout.write("\r" + " " * 85 + "\r")
        sys.stdout.flush()


class AIHandler:
    """Policy-governed AI reporting handler."""

    def __init__(self, profile_path: Path):
        self.profile_path = profile_path
        self.config = self._load_profile()
        self.client = None
        self.compiler = PolicyCompiler(self.config) # Initialize compiler ONCE (policy is immutable at runtime)

    def _load_profile(self):
        with open(self.profile_path, 'r') as f:
            return json.load(f)

    def _save_profile(self):
        with open(self.profile_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def verify_api_key(self):
        """Ensures API key is active and initializes the unified GenAI client."""
        api_key = self.config["api_configuration"].get("api_key", "").strip()
        if not api_key:
            print("\n[!] AI Reporting: No Google Gemini API Key found.")
            api_key = input("[?] Please enter your Gemini API Key: ").strip()
            self.config["api_configuration"]["api_key"] = api_key
            self._save_profile()
            print("[+] API Key saved to config.")

        self.client = genai.Client(api_key=api_key)

# FIX: Added node_count parameter to method signature
    def generate_report(self, scrubbed_data: str, vms_score: int, node_count: int = 1, edge_opacity:str="low"):
        """Compiles policy → prompt and generates a deterministic intelligence report."""
        active_p = self.config.get("active_profile", "strategic_architect")
        profile_data = self.config["profiles"].get(active_p)

        if not profile_data:
            raise ValueError(f"Active profile '{active_p}' not found")

        # FIX: Pass node_count to the compiler
        system_instruction = self.compiler.compile_prompt(
            profile_data=profile_data,
            vms_score=vms_score,
            node_count=node_count,
            edge_opacity=self.config.get("analysis", {}).get("edge_opacity", "low")
        )

        self.last_prompt_fingerprint = hash(system_instruction)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                safe_payload = enforce_zero_knowledge(scrubbed_data)

                # FAIL FAST — PROTECTS YOUR REPUTATION
                if IPV4_REGEX.search(safe_payload) or IPV6_REGEX.search(safe_payload):
                    raise RuntimeError(
                        "[FATAL] ZERO-KNOWLEDGE VIOLATION: Identifier leaked to AI boundary"
                    )
                response = self.client.models.generate_content(
                    model=self.config["api_configuration"]["model_name"],
                    contents=f"ANONYMIZED INFRASTRUCTURE DATA:\n{safe_payload}",
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        temperature=self.config["api_configuration"]["temperature"],
                        top_p=self.config["api_configuration"]["top_p"],
                        candidate_count=1
                    )
                )
                return response.text if response.text else "[!] Empty Response"
            except Exception as e:
                # ... (retry logic remains same) ...
                return f"[!] AI Engine Error: {str(e)}"

def normalize_governance_noise(text: str) -> str:
    """
    Collapses runaway governance / advisory repetitions
    without weakening policy or AI constraints.
    """
    # Collapse excessive advisory spam
    text = re.sub(
        r'(ONLY_ADVISORY[_ ]?){3,}',
        'ONLY_ADVISORY',
        text
    )

    # Prevent duplicated NOTICE blocks
    text = re.sub(
        r'(> \*\*NOTICE:\*\* Findings are advisory and require manual validation before remediation\.){2,}',
        r'\1',
        text
    )

    # Trim absurd horizontal rule spam
    text = re.sub(
        r'\n-{10,}\n',
        '\n---\n',
        text
    )

    return text

def normalize_markdown_tables(text: str) -> str:
    """
    Repairs malformed markdown tables produced by LLMs.
    Ensures headers, separators, and row termination.
    """
    lines = text.splitlines()
    text = re.sub(r"\|\s*Rationale\s*\(\s*\|", "| Rationale |", text)
    fixed = []
    in_table = False
    header_seen = False

    for line in lines:
        if line.strip().startswith("|"):
            in_table = True

            # Ensure row ends with pipe
            if not line.rstrip().endswith("|"):
                line = line.rstrip() + " |"

            # Detect header row
            if not header_seen:
                fixed.append(line)
                col_count = line.count("|") - 1
                fixed.append("|" + " --- |" * col_count)
                header_seen = True
                continue

            fixed.append(line)
        else:
            in_table = False
            header_seen = False
            fixed.append(line)

    return "\n".join(fixed)


# FIX: Added node_count=1 to function signature
def run_ai_reporting(
    scrubbed_file: Path,
    report_dir: Path,
    profile_path: Path,
    vms_score: int,
    node_count: int = 1,
    edge_opacity: str = "low"
):
    """Phase 10: Policy-governed Intelligence Generation."""
    handler = AIHandler(profile_path)
    handler.verify_api_key()
    
    # Initialize as empty string to prevent "UnboundLocalError"
    final_md = "" 

    try:
        with open(scrubbed_file, 'r') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"\033[91m[!] Error: Analysis file not found at {scrubbed_file}\033[0m")
        return "" # Return empty so main.py scrubber doesn't crash

    line_count = len(data.splitlines())
    etc_seconds = max(20, 15 + (line_count // 5))

    print(f"[*] Analyzing infrastructure ({node_count} nodes) and drafting intelligence report...")
    progress = ProgressDisplay(estimate=etc_seconds)
    anim_thread = threading.Thread(target=progress.animate)
    anim_thread.start()

    try:
        # Pass node_count to generate_report
        raw_report = handler.generate_report(data, vms_score, node_count=node_count, edge_opacity=edge_opacity)

        if not raw_report or raw_report.startswith("[!]"):
            print(raw_report)
            return ""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        footer = (
            "\n\n---\n"
            f"*Generated by VedicRecon 1.1 Beta| {timestamp}*\n"
            "> **NOTICE:** Findings are advisory and require manual validation before remediation."
        )

        final_md = (raw_report.strip() + footer).rstrip()
        final_md = normalize_governance_noise(final_md)
        final_md = normalize_markdown_tables(final_md)
        final_md = enforce_semantic_safety(final_md)
        final_md = re.sub(r' {5,}', ' ', final_md)
        final_md = re.sub(r'\s+$', '\n', final_md)

        # Save the report
        report_path = report_dir / f"VedicRecon_Intelligence_Report_{int(time.time())}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(final_md)

        print(f"[+] Intelligence report successfully lodged at: {report_path}")

    except Exception as e:
        print(f"[!] Critical reporting failure: {e}")
    finally:
        progress.stop()
        if anim_thread.is_alive():
            anim_thread.join()
            
    return final_md # Now guaranteed to return either the report or an empty string
