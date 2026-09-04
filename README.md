import time
import subprocess
import os

# Path to Snort log file
LOG_FILE = "/var/log/snort/fast.log"

def block_attacker(ip_address):
    """
    Response Mechanism: Automatically blocks the malicious IP using iptables
    """
    print(f"[!] ALERT! Intrusion detected from IP: {ip_address}")
    try:
        # Enforce firewall rule to drop traffic from the attacker IP
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"[+] SUCCESS: IP {ip_address} has been successfully isolated and blocked.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error executing iptables: {e}")

def monitor_nids():
    print("[*] CodeAlpha - Task 4: NIDS Response Mechanism is active. Monitoring network traffic...")
    
    if not os.path.exists(LOG_FILE):
        print(f"[Notice] Log file not found at {LOG_FILE}. Waiting for Snort events...")
    
    while True:
        try:
            with open(LOG_FILE, "r") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    
                    # Check for suspicious keywords in log lines
                    if "ICMP" in line or "Scan" in line or "Attack" in line:
                        parts = line.split()
                        for p in parts:
                            if "." in p and len(p.split(".")) == 4:
                                attacker_ip = p.split(":")[0]
                                block_attacker(attacker_ip)
                                break
        except FileNotFoundError:
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")
            break

if __name__ == "__main__":
    monitor_nids()