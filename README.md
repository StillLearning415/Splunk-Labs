# 🧠 Splunk + Sysmon Correlation Labs

This repository demonstrates endpoint telemetry correlation using **Sysmon** and **Splunk Enterprise**, showing how system activity can be captured, normalized, and analyzed through custom SPL queries.

Each lab focuses on specific event relationships and PowerShell-driven behaviors to simulate realistic attacker telemetry while ensuring safe, contained testing.

---

## 🔍 Lab Index

### [Lab 1 – Correlating Sysmon Events in Splunk](Lab-1-Sysmon-Correlation.md)
**Objective:** Validate that Splunk and Sysmon are correctly configured to capture and correlate basic endpoint activities.  
**Scenario:**  
A PowerShell session executes basic user-level actions (DNS queries, network connections, and process creation).  
**Key Event Codes:** `1 (Process Creation)`, `3 (Network Connection)`, `22 (DNS Query)`  
**Outcome:**  
All correlated Sysmon events appeared in Splunk within the same PowerShell process window, confirming visibility into process, network, and DNS telemetry.

---

### [Lab 2 – Correlating Multi-Stage PowerShell Activity in Splunk](SysmonLab2.md)
**Objective:** Demonstrate correlation of a multi-stage PowerShell command sequence involving file creation, DNS resolution, and outbound network traffic.  
**Scenario:**  
A PowerShell command downloads a file and writes it to disk (`Invoke-WebRequest`), producing file, DNS, and network activity.  
**Key Event Codes:** `1 (Process Creation)`, `3 (Network Connection)`, `11 (File Create)`, `22 (DNS Query)`  
**Outcome:**  
Splunk successfully linked all four telemetry points to the same PowerShell PID, verifying complete cross-layer correlation between Sysmon and Splunk.

---

## 🧰 Tools Used
- **Sysmon v14.0** (schema 4.90)
- **Splunk Enterprise (Windows index)**
- **Sysmon Configuration:** `sysmon_lab.xml`
- **Windows 10 test environment**

---

## 🧩 Purpose
These labs serve as a portfolio showcase for:
- Endpoint data visibility and telemetry validation  
- Query development and field normalization in Splunk  
- Demonstrating SIEM correlation logic using safe, local event data  

Each lab highlights practical blue-team detection techniques for process and network correlation — foundational for SOC and DFIR work.

---

## 📂 Repository Structure
