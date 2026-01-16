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

        # Initialize compiler ONCE (policy is immutable at runtime)
        self.compiler = PolicyCompiler(self.config)

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

    def generate_report(self, scrubbed_data: str, vms_score: int):
        """Compiles policy → prompt and generates a deterministic intelligence report."""
        active_p = self.config.get("active_profile", "strategic_architect")
        profile_data = self.config["profiles"].get(active_p)

        if not profile_data:
            raise ValueError(
                f"Active profile '{active_p}' not found in ai_profile.json"
            )

        system_instruction = self.compiler.compile_prompt(
            profile_data=profile_data,
            vms_score=vms_score
        )

        # 🔐 Prompt fingerprint for audit / reproducibility
        prompt_fingerprint = hash(system_instruction)
        print(f"[i] Prompt Fingerprint: {prompt_fingerprint}")

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=self.config["api_configuration"]["model_name"],
                    contents=f"ANONYMIZED INFRASTRUCTURE DATA:\n{scrubbed_data}",
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                        temperature=self.config["api_configuration"]["temperature"],
                        top_p=self.config["api_configuration"]["top_p"],
                        candidate_count=1  # deterministic output
                    )
                )

                if not response.text:
                    raise ValueError("AI Engine returned an empty response.")

                return response.text

            except Exception as e:
                err = str(e).lower()
                if any(x in err for x in ["503", "overloaded", "429"]):
                    if attempt < max_retries - 1:
                        time.sleep(((attempt + 1) * 5) + random.uniform(1, 3))
                        continue
                return f"[!] AI Engine Error: {str(e)}"


def run_ai_reporting(
    scrubbed_file: Path,
    report_dir: Path,
    profile_path: Path,
    vms_score: int
):
    """Phase 10: Policy-governed Intelligence Generation."""
    handler = AIHandler(profile_path)
    handler.verify_api_key()

    with open(scrubbed_file, 'r') as f:
        data = f.read()

    line_count = len(data.splitlines())
    etc_seconds = max(20, 15 + (line_count // 5))

    print("[*] Analyzing infrastructure and drafting intelligence report...")
    progress = ProgressDisplay(estimate=etc_seconds)
    anim_thread = threading.Thread(target=progress.animate)
    anim_thread.start()

    try:
        raw_report = handler.generate_report(data, vms_score)

        if raw_report.startswith("[!]"):
            print(raw_report)
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        footer = (
            "\n\n---\n"
            f"*Generated by VedicRecon 1.0.1-alpha | {timestamp}*\n"
            "> **NOTICE:** Findings are advisory and require manual validation before remediation."
        )

        final_md = (raw_report.strip() + footer).rstrip()
        final_md = re.sub(r' {5,}', ' ', final_md)
        final_md = re.sub(r'\s+$', '\n', final_md)

        report_path = report_dir / f"VedicRecon_Intelligence_Report_{int(time.time())}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(final_md)

        print(f"[+] Intelligence report successfully lodged at: {report_path}")

    except Exception as e:
        print(f"[!] Critical reporting failure: {e}")

    finally:
        progress.stop()
        anim_thread.join()
