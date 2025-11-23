# Network Traffic Analysis – Wireshark & PCAP Investigation

## 📌 Overview
This project analyzes captured network traffic to identify suspicious behavior and understand protocol-level activity.

## 🎯 Objectives
- Inspect PCAP data  
- Identify anomalies (port scans, beaconing, DNS tunneling)  
- Decode protocol data  
- Create documentation with screenshots  

---

## 🛠 Tools Used
- Wireshark  
- Tshark  
- Zeek (optional)  

---

## 🔍 Findings Summary
- Detected repeated SYN packets consistent with scanning activity  
- Observed long DNS queries similar to tunneling attempts  

---

## 📄 Included Files
- `wireshark-capture.pcap`  
- `network-map.png`  
- `suspicious-traffic-analysis.md`  
- `/screenshots/`  

---

## 📚 Lessons Learned
- PCAP analysis provides valuable network-level visibility  
- DNS anomalies often reveal covert communication  
