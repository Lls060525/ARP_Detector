import subprocess
import re
import time
from collections import defaultdict

def get_arp_table():
    try:
        # Running 'arp -a' and capturing output
        # Using encoding='cp950' for Windows compatibility
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, encoding='cp950')
        return result.stdout
    except Exception as e:
        return f"Error: {e}"

def parse_arp_table(data):
    # Regex to capture: IP, MAC, and Type (dynamic/static)
    pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)"
    mappings = defaultdict(list)
    
    for line in data.splitlines():
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            mac = match.group(2).lower().replace('-', ':')
            addr_type = match.group(3).lower()
            
            # Filtering Logic:
            # 1. Only monitor 'dynamic' entries (where attacks usually happen)
            # 2. Exclude Multicast ranges (224.x.x.x and 239.x.x.x)
            if addr_type == "dynamic" and not (ip.startswith("224.") or ip.startswith("239.")):
                mappings[mac].append(ip)
    return mappings

def monitor_network():
    print("======================================================================================")
    print("|      [*] Network Security Monitor V2.0 (Multicast Noise Filtered)                  |")
    print("|      [*] Status: Monitoring for Dynamic ARP Spoofing...                            |")
    print("|      [*] Press Ctrl+C to stop monitoring                                           |")
    print("======================================================================================")

    try:
        while True:
            raw_data = get_arp_table()
            arp_map = parse_arp_table(raw_data)
            
            alert_triggered = False
            for mac, ips in arp_map.items():
                if len(set(ips)) > 1: # Check for multiple distinct IPs on one MAC
                    print(f"\n[!!!  SECURITY ALERT - {time.strftime('%H:%M:%S')}]")
                    print(f"Suspected Spoofing: MAC [{mac}] is claiming multiple IPs: {', '.join(ips)}")
                    alert_triggered = True
            
            if not alert_triggered:
                # Refreshing status line
                print(f"[{time.strftime('%H:%M:%S')}] Network Status: IN SECURE", end="\r")
            
            # Check every 1 minute to keep CPU usage low
            time.sleep(60)
            
    except KeyboardInterrupt:
        print("\n\n[*] Monitoring Terminated. Stay safe.")

if __name__ == "__main__":
    monitor_network()