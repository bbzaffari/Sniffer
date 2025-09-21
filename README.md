# Network Sniffer 2023/02

![License](https://img.shields.io/badge/use-educational_or_research-blue)
![Legal](https://img.shields.io/badge/legal-use_only-grey)

> This project was developed as part of the Computer Networks Laboratory course during the undergraduate program at PUC-RS (Pontifícia Universidade Católica do Rio Grande do Sul). It is intended for educational purposes and may not be production-grade.

For a detailed explanation of attack detection logic, experimental setup, and results, please refer to the 🔗[**full technical report**](./report.pdf)

## 🛠️ Network Sniffer for SYN Flood & HTTP DoS Detection

This project is a Python-based **raw socket sniffer** developed for educational purposes in the Computer Networks Lab at PUCRS. It listens to Ethernet traffic on the host interface and inspects ARP, IPv4/IPv6, TCP, and UDP protocols. The tool detects **SYN Flood** and **HTTP DoS** patterns based on per-IP packet counts in a time window (\~10 seconds). Alerts are triggered when traffic exceeds a configurable threshold (default: 500 packets/IP).

Test scenarios included simulated attacks using tools like `hping3` (for SYN flooding) and `LOIC` (for HTTP-based DoS) against a local Apache2 server. The environment was controlled, with all tests performed legally and for academic learning only.

### Highlights

* **Raw Ethernet sniffing** (no external libraries like Scapy or Wireshark)
* **Attack detection logic** with customizable thresholds
* **Cross-protocol support** (ARP, IPv4, IPv6, TCP, UDP)
* Simple terminal output with IP-based counters and summary
  
---

## 📡 What is a Sniffer?

A **network sniffer** is a tool that captures and analyzes packets traveling across a network interface. It reads low-level data—such as headers and payloads—to extract meaningful patterns or detect suspicious activity.

In this project, the sniffer:

* Tracks TCP **SYN** packets to detect possible **SYN Flood attacks**
* Monitors **HTTP GET/POST** requests to detect potential **HTTP DoS**
* Logs ARP activity and prints summary statistics on termination

---
---

