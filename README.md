# SOC Casefile #02: Mirai on VirusTotal (10/62 detection)

**Date:** 21 Nov 2026 · **Sources:** MalwareBazaar, VirusTotal (lookup only, sample not downloaded)
**Family:** Mirai / Svirtu (trojan, DDoS botnet) · **Platform:** Linux ELF, ARM (IoT devices)

## 1. Learned
Threat intelligence platforms crowdsource indicators so one organisation's detection
protects everyone. MalwareBazaar and VirusTotal are two of the free ones I used here.

## 2. Investigated
**Step 1: what is the internet seeing right now?**
On MalwareBazaar, Mirai was the most-seen malware family of the past 24 hours.

| Metric (21 Nov 2026, morning IST) | Value |
|---|---|
| Submissions, past 24 hours | 572 |
| Most seen family, past 24 hours | Mirai |
| Samples in corpus | 1,176,849 |
| Latest 15 samples tagged `mirai` | 15 / 15 |
| ...also tagged `gafgyt` (another IoT botnet) | 2 / 15 |
| ...captured by Cowrie honeypots | 2 / 15 |

Evidence: `evidence/01_malwarebazaar_dashboard.png`, `evidence/02_malwarebazaar_recent_samples.png`

**Step 2: pick the newest sample and look it up on VirusTotal**

| Field | Value |
|---|---|
| SHA256 | `3f8f9be5f8e8cdffc8bf9b3e5b54d0a906217050803b3e1a37112231f019dd25` |
| First seen (MalwareBazaar) | 2026-11-21 01:48:30 UTC |
| File name | `2gkdmdn8.exe` |
| Size | 131.23 KB |
| Type | ELF, ARM, UPX-packed |
| Detection | **10 / 62 vendors** |
| Community score | -11 |
| Popular threat label | trojan.mirai/svirtu |
| Family labels | mirai, svirtu, ddos |
| VT tags | elf, upx, arm, detect-debug-environment |

Vendors that flagged it: Antiy-AVL, Avast, AVG, Avira, Cynet, DrWeb, Huorong,
Kaspersky, Microsoft, WithSecure. Evidence: `evidence/03_virustotal_detection.png`

## 3. Found
1. **52 of 62 engines did not flag the most common malware family of the day.**
   A fresh hash plus UPX packing is enough to slip past signature-based detection
   on a brand-new sample. (Detection counts usually rise as vendors catch up, so I
   recorded the score at the time of my lookup.)
2. **A Linux binary named `.exe`.** The file is an ARM ELF that will never run on Windows.
   The name is a disguise for anyone glancing at a file listing.
3. **It checks whether it's being analysed** (`detect-debug-environment`).
4. **The target is IoT, not laptops.** ARM builds run on routers, cameras and DVRs, which
   Mirai historically compromises by guessing default Telnet credentials.

## 4. Mapped to MITRE ATT&CK
Based on VirusTotal tags and known Mirai behaviour (no sandbox run of my own):

| Technique | ID | Evidence |
|---|---|---|
| Software Packing | T1027.002 | `upx` tag |
| Debugger Evasion | T1622 | `detect-debug-environment` tag |
| Masquerade File Type | T1036.008 | ELF binary named `.exe` |
| Password Guessing | T1110.001 | Mirai's known default-credential spreading |
| Network Denial of Service | T1498 | `ddos` family label |

Pyramid of Pain triage (my tool from Casefile #01): 7 of 8 indicators sit at the top of
the pyramid. Only 1 is a hash. Full output: [`triage_output.txt`](triage_output.txt)

## 5. Detected
Two detections built on **behaviour and structure**, so they keep working when the hash changes:

| File | Type | What it catches |
|---|---|---|
| `detections/mirai_upx_arm_elf.yar` | YARA (hunting) | UPX-packed ARM ELF binaries under 2 MB |
| `detections/mirai_telnet_bruteforce.spl` | Splunk SPL | One source hitting 20+ hosts or 100+ attempts on Telnet/SSH in 5 minutes |

`tools/hunt_upx_arm_elf.py` is a Python version of the YARA rule for machines without YARA.
Tested against harmless fake headers in `tools/test_fixtures/`: 1 hit (ARM + UPX), and correctly
no hit on ARM-without-UPX or x86-with-UPX.

```
python3 tools/hunt_upx_arm_elf.py tools/test_fixtures
```

## 6. Verdict (what I'd tell my L2)
Block the hash, but treat it as a footnote: tomorrow's Mirai build will have a new one and
most engines won't know it yet. The real controls are:
- Alert on Telnet/SSH scanning patterns (SPL above)
- Hunt for packed ARM binaries on IoT/edge storage (YARA above)
- Disable Telnet and change default credentials on every IoT device on the network

## Limitations
- Lookup only: I didn't download or detonate the sample, so behaviour is inferred from VT tags and public Mirai reporting.
- The YARA rule is a hunting rule; legitimate embedded firmware can also be UPX-packed.

## Next steps
- Pull the Relations and Behavior tabs for C2 IPs/domains and add them to `iocs.csv`
- Compare detection ratios across 5 recent Mirai samples
