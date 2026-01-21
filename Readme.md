# VedicRecon — Surgical Infrastructure Reconnaissance Engine

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Go](https://img.shields.io/badge/Go-Deterministic_Core-cyan)
![Recon](https://img.shields.io/badge/Recon-External_Only-critical)
![AI](https://img.shields.io/badge/AI-Narration_Only-lightgrey)
![License](https://img.shields.io/badge/License-GPLv3-blue)


**Version:** 1.3-beta  
**Status:** Advisory-only | External-Posture Intelligence  
**Author:** Shikhar Kant Sinha 

---

## 1. What is VedicRecon?

VedicRecon is a surgical reconnaissance and infrastructure posture analysis engine designed to transform raw external scan data into governed, uncertainty-aware intelligence reports.

Unlike traditional vulnerability scanners that attempt to enumerate and exploit everything, VedicRecon focuses on:

- Externally observable posture

- Defensive abstraction & opacity

- Attack surface reasoning

- What can and cannot be known from outside

It does not claim vulnerabilities unless they are externally verifiable.

VedicRecon sits between raw recon tools and human analysis, acting as a structured reasoning layer.

👉 **Don’t want to read everything?**  
Jump straight to the **[Installation & Usage](#how-to-run-vedicrecon)** section.

---
## 2. What VedicRecon is NOT

This is critical.

VedicRecon is NOT:

❌ A vulnerability scanner

❌ An exploitation framework

❌ A replacement for Nmap, Burp, Metasploit, or manual testing

❌ A CVE auto-mapper

❌ A “critical findings generator”

If you expect automated exploitation or guaranteed vulnerabilities — this tool is not for you.
---
## 3. Core Philosophy

“If something cannot be externally verified, it must not be asserted.”

VedicRecon enforces epistemic discipline:

- Observability ≠ Absence

- Ambiguity is explicitly stated

- Heuristic attribution is labeled as such

- Defensive controls that intentionally obscure themselves are treated conservatively

This prevents:

- Over-reporting

- False confidence

- Vendor hallucinations

- Legal and professional misrepresentation

- Budget Friendly 
---

### Cost & Efficiency Considerations

VedicRecon is intentionally designed to be **cost-efficient per execution**.

- AI usage is limited strictly to **final narrative synthesis**
- Deterministic logic, scoring, and analysis are performed **locally**
- The selected model (**Gemini 2.5 Flash**) is optimized for fast summarization and low token usage

As a result, a typical VedicRecon run consumes approximately **~1 RPD (request per day unit)**.

This predictable, minimal consumption model ensures that:
- The tool remains practical for repeated use
- Costs do not scale with scan size or port count
- AI usage never becomes a bottleneck or hidden expense

Cost efficiency is a **design constraint**, not an optimization afterthought.

## 4. What VedicRecon CAN do

VedicRecon can:

- Perform baseline network discovery using trusted tools (Nmap, ffuf)

- Detect edge abstraction patterns (opaque / non-attributable behavior)

- Classify service exposure vs defensive density

- Reason about attack surface shape, not just port counts

- Generate human-readable intelligence reports

It clearly separates:

- Verifiable facts

- Non-verifiable elements

- Hypothetical attack paths

- Produce executive-safe, audit-safe reports
---
## 5. High-Level Architecture

VedicRecon uses a strict, multi-stage pipeline:
```text
Recon → Registry → Logic Engine → Deterministic Scoring → AI Narration → Privacy Enforcement → Final Report
```

## Why this structure exists

Each stage has **one responsibility**:

| Stage | Purpose |
|-----|--------|
| Recon (Go core) | Fast, deterministic data collection |
| Registry | Single source of truth |
| Logic Engine | Correlation, edge detection, posture inference |
| VMS Engine | Deterministic scoring (non-AI) |
| AI Engine | Narrative synthesis only |
| Privacy Scrubber | Post-generation enforcement |

This prevents AI hallucination and enforces governance **before narration**.
---
## 6. Why AI is used (and why it is constrained)

AI is **never** used to:

- Detect vulnerabilities

- Identify vendors

- Infer internal architecture

- Make claims about unseen systems

AI is used **only** to:

- Convert structured logic into clear human language
- Write professional security narratives
- Generate hypothesis-based attack reasoning

All sensitive data is scrubbed **post-generation**.

This is **deliberate and non-negotiable**.
---
## 7. Who should use VedicRecon?

### ✅ Designed for

**Penetration Testers**
- Early-phase recon
- External posture analysis
- Client-safe reporting

**Security Engineers / Blue Teams**
- Attack surface visibility
- Defensive abstraction analysis

**Consultants / Auditors**
- Advisory-only assessments
- Professional defensibility

### ❌ Not suitable for

- Script-kiddie automation  
- Exploit chaining  
- Vulnerability farming  
- Red team automation without human analysis  

---

## 8. How VedicRecon fits into a real pentest workflow

1. Scope confirmation  
2. Run VedicRecon  
3. Review posture report  
4. Decide where to focus manual testing  
5. Proceed with targeted exploitation using other tools  

VedicRecon answers:

> **“Where does this infrastructure appear weak or exposed from the outside?”**

It intentionally does **not** answer:

> **“How do I break in automatically?”**

---

## 9. Scan Modes

### Full Infrastructure Scan (default)
- All ports
- OS fingerprinting
- Service enumeration

### Single-Port Diagnostic Mode
- Focused analysis (`-p`)
- Sensitive environments
- Noise reduction

---

## 10. Legal & Ethical Notice

VedicRecon enforces:

- Scope awareness  
- Advisory-only output  
- Non-exploitative posture  

All findings are:

- Externally observable  
- Non-assertive  
- Hypothesis-based  

**Authorization is your responsibility.**

---

## 11. Why the name “VedicRecon”?

“Vedic” refers to **structured knowledge**, not mythology.

The tool emphasizes:

- Clarity  
- Order  
- Truth boundaries  
- Knowing what is known vs unknowable  

---

## 12. Current Status (BETA)

Design limitations (intentional):

- External posture only  
- No authenticated scanning  
- No internal visibility  
- No exploitation  

---

## 13. Final Note

VedicRecon is not built to impress with noise.  
It is built to **think clearly under uncertainty**.

If you value:

- Accuracy over drama  
- Discipline over hype  
- Intelligence over automation  

**This tool is for you.**

---

# How to Run VedicRecon

## Supported Operating Systems

- ✅ Kali Linux  
- ✅ Ubuntu 20.04+  
- ⚠️ Arch Linux (advanced users only)  

macOS is not supported due to raw socket limitations.

---

## Prerequisites

### Required Tools

- `nmap`
- `ffuf`
- `go`
- `python3` (>= 3.10)

Verify:

```bash
nmap --version
ffuf -V
go version
python3 --version
```
## Clone the Repository
```bash
git clone https://github.com/Shikhar0708/VedicRecon-Framework.git
cd VedicRecon-Framework
```
## Build the Go Recon Core

VedicRecon uses a Go binary for fast, deterministic discovery.
```bash
cd core
go build -o ../bin/vr_core_linux .
cd ..
```

Verify:
```bash
ls bin/vr_core_linux
```
## Python Environment Setup

Create and activate a virtual environment:
```bash
python3 -m venv vedic-framework
source vedic-framework/bin/activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```
## Configuration Files Overview
| File | Purpose |
| ---- | ------- |
| config/profiles.json | Defines the specific arguments and flags for Nmap and ffuf scan profiles. |
| config/ai_profile.json | Sets the boundaries and stylistic constraints for AI-generated narratives. |
| config/privacy.json | Contains the Zero-knowledge scrubbing rules to strip PII and sensitive data. |
| config/wrapper.json | Handles OS tool verification to ensure dependencies like Nmap are present. |

You typically do not need to modify these unless customizing behavior.

### Custom Wordlists

VedicRecon allows users to supply their own directory or endpoint wordlists.

To ensure compatibility with the discovery pipeline, any custom wordlist **must be named**:

```text
common.txt
```
and placed in the following directory:
```text
config/wordlists/common.txt
```
This design choice ensures:
- A predictable, deterministic execution path
- No dynamic file loading or unsafe path handling
- Consistent behavior across environments

If you wish to use a different wordlist, simply replace the contents of `common.txt` with your own entries.


## Running VedicRecon (Interactive Mode)

Launch the framework as root:
```bash
sudo -E vedic-framework/bin/python main.py
```
⚠️ **Boundary License Acceptance Required (first run only)**  
You must explicitly accept the operational boundary license before use.

After that you will see the VedicRecon Station menu. 

## Adding Targets

From the menu:

```bash
1. Add New Target(s)
```

You can enter:
```bash
A single IP: 192.x.x.x

A CIDR: 192.168.x.x/24

A file path containing targets. Unstable for now
```
Targets are stored in the central registry.

## Choosing Scan Mode

When launching discovery, you will be prompted whether to:
```bash
Scan Entire Host (Default)

Full port discovery
```

Single-Port Diagnostic Mode

Used for:

- Sensitive environments

- Service validation

- Noise reduction

Example:
```bash
Scan a single port only? (y/n): y
Enter port number: 3000
```

*This uses Nmap’s -p flag internally without changing Go binaries.*

## Discovery Phases Executed

VedicRecon automatically executes:

| Phase | Description |
|------:|-------------|
| Phase 2 | Baseline Network Discovery |
| Phase 4 | Banner Grabbing |
| Phase 5 | Edge / WAF Signal Detection |
| Phase 6 | Optional Directory Enumeration (ffuf) |
| Phase 7 | Logic Correlation |
| Phase 8 | Deterministic Scoring (VMS) |
| Phase 10 | AI Intelligence Synthesis |
| Phase 11 | Privacy Scrubbing |

---

## AI Model & API Key Requirement

VedicRecon uses an external Large Language Model (LLM) **only for narrative synthesis**.

### Model Used
- **Provider:** Google Gemini
- **Model:** Gemini 2.5 Flash

### When is the API key required?
On first run, VedicRecon will prompt for a Gemini API key **only if AI narration is enabled**.

### What the AI is used for
The AI is used strictly to:
- Convert structured, deterministic findings into clear human-readable language
- Generate professional security narratives
- Describe hypothesis-based attack reasoning

### What the AI is NOT used for
The AI is **never** used to:
- Detect vulnerabilities
- Identify vendors
- Infer internal architecture
- Make claims about unseen systems
- Assign risk scores

### Privacy & Data Handling
- Sensitive identifiers (IPs, hostnames, banners, vendor names) are **sanitized before AI ingestion**
- A second privacy enforcement pass is applied **after AI output**
- The AI never receives raw scan data

If no API key is provided, VedicRecon can still perform reconnaissance and scoring, but **it will fail loudly and no ai-report generation will happen**.


## Viewing Results

***Registry***
```bash
output/targets.csv
```
***Intelligence Reports***
```bash
reports/VedicRecon_Surgical_Report_<timestamp>.md
```

## These reports are:

**Advisory-only**

**Externally observable**

Safe to share with stakeholders

## Typical Workflow Example

1. Define scope
2. Add target(s)
3. Run discovery
4. Review posture report
5. Decide where to manually test
6. Proceed with exploitation using other tools

## Common Issues

### Nmap shows exit status 1

Often occurs with:
- OS detection failures
- Permission issues
- Filtered environments

VedicRecon continues safely unless critical data is missing.

## Cleanup

To reset the workspace:
```bash
Clear Workspace (/output)
```
## Ethical Reminder

**You must have authorization to scan any target.**

**VedicRecon does not bypass protections and does not exploit systems.**

---
## License
Licensed under the GNU General Public License v3.0 (GPL-3.0).
