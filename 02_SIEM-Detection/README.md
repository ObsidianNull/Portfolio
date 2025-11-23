# SIEM Detection Engineering – Splunk

## 📌 Overview
This project showcases SIEM analytics and detection engineering by creating Splunk dashboards, correlation rules, and alerting logic to detect common attack patterns.

## 🎯 Objectives
- Ingest Windows and Linux logs  
- Build dashboards for monitoring  
- Create correlation searches for suspicious activity  
- Map detections to MITRE ATT&CK  

## 🛠 Tools Used
- Splunk Free  
- Sysmon  
- Windows 10 VM  
- Ubuntu Server  
- Atomic Red Team (log generation)

---

## 📊 Use Cases Implemented

### 1. **Brute Force Detection**
- Monitor repeated failed login attempts  
- Correlate with eventual successful login  

### 2. **Privilege Escalation Monitoring**
- Detect `SeDebugPrivilege` and Administrator role changes  

### 3. **DNS Exfiltration Detection**
- Identify irregular DNS query patterns  

Screenshots included in `/screenshots/`.

---

## 📄 Contents
- `splunk-dashboards/` – JSON exports  
- `correlation-rules/` – SPL detection logic  
- `logs-sample/` – Sanitized logs used in testing  

---

## 🧠 Lessons Learned
- Small log sources can generate meaningful detections  
- MITRE mapping clarifies detection coverage gaps  
- Dashboards improve SOC visibility significantly  

