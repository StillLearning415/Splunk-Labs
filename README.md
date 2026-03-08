# 🛡️ Splunk + Sysmon Detection Labs

A portfolio of blue team detection engineering labs built from scratch using **Sysmon** and **Splunk Enterprise**. Each lab simulates a real attacker technique, captures telemetry through a custom Sysmon configuration, and surfaces it through hand-written SPL queries — no pre-built content packs, no guided walkthroughs.

> **Stack:** Sysmon v14+ · Splunk Enterprise · Windows 10 · PowerShell · MITRE ATT&CK

---

## 🗂️ Lab Index

| Lab | Technique | MITRE | Sysmon Event IDs |
|-----|-----------|-------|-----------------|
| [Lab 1 — Sysmon + Splunk Baseline Correlation](Lab-01_Sysmon-Correlation.md) | Process, DNS & network correlation | — | 1, 3, 22 |
| [Lab 2 — Multi-Stage PowerShell Correlation](Lab-02-Multi-Stage-PowerShell-Correlation.md) | Multi-stage execution chain | — | 1, 3, 11, 22 |
| [Lab 3 — File Timestamp Manipulation](Lab-03-File-Timestamp-Manipulation.md) | Timestomping / anti-forensics | T1070.006 | 2 |
| [Lab 4 — Registry Persistence Detection](Lab-04-Registry-Persistence-Detection.md) | Run key persistence | T1547.001 | 13 |
| [Lab 5 — LSASS Credential Access Detection](Lab-05-LSASS-Credential-Access-Detection.md) | Credential dumping detection | T1003.001 | 10 |

---

## 🔬 Lab Summaries

### Lab 1 — Sysmon + Splunk Baseline Correlation
Validated that Sysmon and Splunk are correctly configured end-to-end. Triggered process creation, DNS resolution, and outbound network activity from a single PowerShell session and confirmed all three event types appeared correlated in Splunk.

**Key SPL:** Multi-EventCode query with `coalesce` field normalization across EventCodes 1, 3, and 22.

---

### Lab 2 — Multi-Stage PowerShell Correlation
Simulated a realistic download-and-execute chain using `Invoke-WebRequest`. Correlated four Sysmon event types back to a single PowerShell PID — demonstrating how a single process can generate a full attack footprint across process, file, DNS, and network telemetry.

**Key SPL:** Regex-based field redaction, multi-source `eval` normalization, process tree correlation.

---

### Lab 3 — File Timestamp Manipulation (T1070.006)
Simulated timestomping — a common anti-forensic technique — by backdating a file's creation timestamp three years using PowerShell. Sysmon Event ID 2 captures both the forged and original timestamps, enabling defenders to detect the discrepancy.

**Key SPL:** `coalesce` across multiple timestamp field name variants, `rex` extraction from raw events for field normalization.

---

### Lab 4 — Registry Persistence Detection (T1547.001)
Added a benign Run key entry to simulate post-exploitation persistence, then detected it via Sysmon Event ID 13 in Splunk. Query filters out noisy legitimate entries (e.g. Microsoft Edge autolaunch) to focus on suspicious modifications.

**Key SPL:** SID redaction via regex, Run key path normalization, exclusion filtering for known-good entries.

---

### Lab 5 — LSASS Credential Access Detection (T1003.001)
Accessed LSASS process information via PowerShell and analyzed the resulting Sysmon Event ID 10 logs. Documented `GrantedAccess` values to distinguish benign enumeration (`0x1000`) from high-risk access patterns associated with tools like Mimikatz (`0x1fffff`, `0x1010`).

**Key SPL:** `TargetImage` filter on lsass.exe, `GrantedAccess` field analysis, CallTrace extraction.

---

## ⚙️ Environment

| Component | Details |
|-----------|---------|
| OS | Windows 10 |
| Sysmon | v14+ (schema 4.90), custom `sysmon_lab.xml` config |
| SIEM | Splunk Enterprise, `windows` index |
| Log Source | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |

---

## 🔐 Privacy & Redaction

All lab outputs have been sanitized:
- Usernames replaced with `REDACTED_USER`
- File paths normalized to `C:\REDACTED_PATH\`
- IP addresses replaced with `REDACTED_IP`
- SIDs replaced with `REDACTED_SID`
- DNS queries normalized to `example.com`

Redaction was performed inline via SPL `eval` + `replace()` and `rex mode=sed` — maintaining analytical integrity while removing personally identifiable information.

---

## 🎯 Purpose

These labs were built independently to develop and demonstrate practical blue team skills:

- Endpoint telemetry collection and validation
- SIEM query development and field normalization
- Detection of real attacker techniques mapped to MITRE ATT&CK
- Behavioral baselining and false positive reduction
- Evidence handling and documentation practices

Each lab reflects skills directly applicable to SOC Analyst and Detection Engineering roles.
