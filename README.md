**ARP-Guard Lightweight Network Monitor**
  A proactive, Python-based security tool designed to detect ARP Spoofing and Man-in-the-Middle (MitM) attacks in real-time. This project was developed as a part of my transition into Information Security, focusing on defensive networking and automated threat detection.

**The Problem**
  The Address Resolution Protocol (ARP) is inherently "trusting"—it lacks a verification mechanism. Attackers can exploit this by sending fake ARP responses to map their MAC address to another device's IP (like the Gateway), allowing them to intercept or "sniff" local network traffic.

**How It Works**
  ARP-Guard monitors the local ARP cache for 1-to-Many mappings.

  Under normal conditions, 1 MAC Address = 1 IP Address.

  During an attack, 1 Attacker MAC = Multiple Claimed IPs.

  The script continuously parses the system's ARP table, filters out multicast noise (mDNS, SSDP), and triggers a security alert the moment a conflict is detected.

**Features**
  Real-time Detection: Scans the network environment every 10 seconds for anomalies.

  Intelligent Filtering: V2.0 automatically ignores Multicast/Broadcast ranges (224.x.x.x, 239.x.x.x) to prevent false positives.

  Stealthy & Passive: Operates purely on local cache data; it does not send "noisy" packets that could trigger network alarms.

  Cross-Compatibility: Optimized for Windows environments (PowerShell/CMD).

**Getting Started**
  Prerequisites
  Python 3.x

  Windows OS (Utilizes the native arp -a command)

**Installation**
  Clone the repository:
  
  Bash
  git clone https://github.com/your-username/arp-guard-v2.git
  Navigate to the directory:
  
  Bash
  cd arp-guard-v2
  Run the monitor:

  Bash
  python arp_detect.py
  ⚠️ Disclaimer
  For Educational and Defensive Use Only. This tool was created to help users understand network vulnerabilities and protect their local environments. Unauthorized use against systems you do not own is strictly prohibited and potentially illegal.

**Author**
  Long Sheng

  Focus: Information Security & Software Development

  Tech Stack: Python | Django | Flutter | Cybersecurity
