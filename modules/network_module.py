import nmap
import socket
import subprocess
import json
from tqdm import tqdm
import re
import sys

class NetworkModule:
    def __init__(self, target):
        self.target = target
        self.resolved_ip = None
        self.result = {
            "nmap_scan": {},
            "masscan_scan": {},
            "os_fingerprint": {},
            "banner_grabbing": {}
        }

    # Resolve Domain to IP for accurate scanning
    def resolve_target(self):
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
            print(f"[+] Resolved {self.target} to {self.resolved_ip}")
        except socket.gaierror:
            print(f"[!] Failed to resolve {self.target}")
            self.resolved_ip = None

    # Nmap Scanning with OS Detection and NSE Scripts
# Nmap Scanning with OS Detection and NSE Scripts
    # Nmap Scanning with OS Detection and NSE Scripts
    def run_nmap_scan(self):
        try:
            print(f"[+] Running Nmap fast scan on {self.target}")
            nm = nmap.PortScanner()
            nm.scan(
                hosts=self.target,
                arguments='-sS -sV -O --script=default -T4',
                timeout=30  # Timeout added here (300 seconds / 5 minutes)
            )
            if self.target in nm.all_hosts():
                self.result["nmap_scan"] = nm[self.target]
                self.result["os_fingerprint"] = nm[self.target].get('osmatch', {})
            else:
                print(f"[!] Nmap did not detect the target {self.target}")
        except Exception as e:
            print(f"[!] Nmap scan failed: {e}")
            self.result["nmap_scan"] = {"error": str(e)}



    # Masscan Fast Scanning for large networks
    def run_masscan(self, ports="1-65535", rate="10000"):
        if not self.resolved_ip:
            print("[!] Cannot run Masscan. Target IP not resolved.")
            return
        try:
            print(f"[+] Running Masscan on {self.resolved_ip}")
            masscan_cmd = f"masscan {self.resolved_ip} -p{ports} --rate={rate}"
            output = subprocess.check_output(masscan_cmd.split(), stderr=subprocess.STDOUT)
            scan_results = output.decode()
            parsed_ports = re.findall(r"Discovered open port (\d+)/tcp on ([\d.]+)", scan_results)
            self.result["masscan_scan"] = [{"ip": ip, "port": port} for port, ip in parsed_ports]
        except subprocess.CalledProcessError as e:
            print(f"[!] Masscan failed: {e.output.decode()}")
            self.result["masscan_scan"] = {"error": e.output.decode()}

    # Basic banner grabbing using Python socket
    def banner_grab_socket(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, int(port)))
            banner = s.recv(1024).decode(errors='ignore').strip()
            s.close()
            return banner
        except Exception:
            return None

    # Optional: Banner grabbing with netcat
    def banner_grab_netcat(self, ip, port):
        try:
            output = subprocess.check_output(f"nc -nv {ip} {port}", shell=True, timeout=5)
            return output.decode(errors='ignore').strip()
        except Exception:
            return None

    # Wrapper to grab banners from common ports
    def grab_banners(self):
        if not self.resolved_ip:
            print("[!] Cannot grab banners, target IP not resolved.")
            return

        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
        print(f"[+] Grabbing banners from common ports on {self.target} ({self.resolved_ip})")
        for port in tqdm(ports_to_scan):
            banner = self.banner_grab_socket(self.resolved_ip, port)
            if banner:
                self.result["banner_grabbing"][f"{self.resolved_ip}:{port}"] = banner

    def run_all(self):
        self.run_nmap_scan()
        self.run_masscan()
        self.grab_banners()
        return self.result


if __name__ == "__main__":
    target = input("Enter target IP, domain, or range for scanning: ").strip()
    scanner = NetworkModule(target)
    scanner.resolve_target()

    if not scanner.resolved_ip:
        print("[!] Exiting: Invalid target or resolution failed.")
        sys.exit(1)

    final_result = scanner.run_all()

    report_file = f"files/process/{target.replace('/', '_')}_network_report.json"
    with open(report_file, "w") as f:
        json.dump(final_result, f, indent=4)

    print(f"\n[✔] Network Scanning Completed. Report saved to {report_file}")
