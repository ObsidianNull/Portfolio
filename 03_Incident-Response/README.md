# Incident Response Scenario – Phishing to Execution

## 📌 Overview
This project simulates an end-to-end incident response scenario involving phishing, credential theft, and suspicious PowerShell execution.

## 🎯 Objectives
- Analyze system logs to identify malicious behavior  
- Build an incident timeline  
- Perform basic malware static analysis  
- Generate a full IR report  

---

## 🧰 Tools Used
- Windows Event Viewer  
- Sysmon  
- Splunk  
- Strings, PEview  
- PowerShell  

---

## 📝 Scenario Summary
A simulated phishing email delivered a malicious attachment that executed a PowerShell command beaconing to a mock C2 server.

---

## 📑 Files Included
- `incident-report-template.md`  
- `malware-analysis/static-analysis.md`  
- `screenshots/`  
- Relevant logs  

---

## 📚 Lessons Learned
- Email phishing remains the most common attack vector  
- Sysmon provides critical telemetry for IR  
- Correlating network and system logs gives a complete picture  
