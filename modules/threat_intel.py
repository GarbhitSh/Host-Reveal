import subprocess
import json
import os
import re
from tqdm import tqdm

class ThreatIntelToolModule:
    def __init__(self, target, misp_local_ioc_file="misp_iocs.json", local_threat_list="threat_list.txt"):
        self.target = target
        self.misp_local_ioc_file = misp_local_ioc_file
        self.local_threat_list = local_threat_list
        self.result = {
            "nmap_scan": [],
            "fingerprint_info": [],
            "ioc_matches": [],
            "misp_hits": []
        }

    # Emulate Shodan/Censys with local nmap
    def run_nmap_scan(self):
        print(f"[+] Running local Nmap scan on {self.target}")
        try:
            output = subprocess.check_output(
                ["nmap", "-sV", "-O", "-Pn", self.target], 
                stderr=subprocess.DEVNULL,
                timeout=60  # Timeout added here (60 seconds)
            ).decode()
            self.result["nmap_scan"] = output
        except subprocess.TimeoutExpired:
            self.result["nmap_scan"] = "Error: Nmap scan timed out"
        except subprocess.CalledProcessError as e:
            self.result["nmap_scan"] = f"Error: {str(e)}"

    # Local fingerprint using simple grep, banner, and whois (like Shodan basic)
    def local_fingerprint(self):
        print(f"[+] Running local fingerprint check on {self.target}")
        try:
            whois_data = subprocess.check_output(
                ["whois", self.target], 
                stderr=subprocess.DEVNULL,
                timeout=30  # Timeout added here (30 seconds)
            ).decode()
            self.result["fingerprint_info"].append({"whois": whois_data})
        except subprocess.TimeoutExpired:
            self.result["fingerprint_info"].append({"whois_error": "WHOIS query timed out"})
        except Exception as e:
            self.result["fingerprint_info"].append({"whois_error": str(e)})

        # Grep for technologies from nmap results (simulate WAF detection, known banners, etc.)
        waf_detection = re.findall(r"Server: (.+)", self.result["nmap_scan"])
        if waf_detection:
            self.result["fingerprint_info"].append({"WAF/Banner": waf_detection})

    # Emulate AlienVault OTX with offline IOC comparison (e.g., common C2 domains, IPs)
    def local_threat_ioc_check(self):
        if not os.path.exists(self.local_threat_list):
            print(f"[!] Local Threat IOC list {self.local_threat_list} not found.")
            return

        print(f"[+] Checking against local threat IOC list: {self.local_threat_list}")
        with open(self.local_threat_list, 'r') as f:
            iocs = [line.strip() for line in f if line.strip()]
        
        # Simple match: if the target itself is in the IOC list
        if self.target in iocs:
            self.result["ioc_matches"].append(f"Target {self.target} found in threat list")

        # Optional: Check if any found banners or services match known threats
        for line in iocs:
            if line.lower() in self.result["nmap_scan"].lower():
                self.result["ioc_matches"].append(f"IOC '{line}' matched in nmap scan output")

    # Load local MISP dump (JSON) and check for matches
    def local_misp_correlation(self):
        if not os.path.exists(self.misp_local_ioc_file):
            print(f"[!] MISP IOC file {self.misp_local_ioc_file} not found.")
            return

        print(f"[+] Correlating against local MISP dump: {self.misp_local_ioc_file}")
        with open(self.misp_local_ioc_file, 'r') as f:
            misp_data = json.load(f)

        for event in tqdm(misp_data.get("response", [])):
            for attr in event.get("Attribute", []):
                if attr.get("value") == self.target or attr.get("value") in self.result["nmap_scan"]:
                    self.result["misp_hits"].append({
                        "event_id": event.get("Event", {}).get("id"),
                        "ioc": attr.get("value"),
                        "category": attr.get("category"),
                        "type": attr.get("type")
                    })

    def run_all(self):
        self.run_nmap_scan()
        self.local_fingerprint()
        self.local_threat_ioc_check()
        self.local_misp_correlation()
        return self.result


if __name__ == "__main__":
    target = input("Enter target IP/domain: ").strip()
    intel = ThreatIntelToolModule(target)
    final_result = intel.run_all()

    os.makedirs("files/process", exist_ok=True)
    report_file = f"files/process/{target.replace('.', '_')}_local_threat_intel.json"
    with open(report_file, "w") as f:
        json.dump(final_result, f, indent=4)

    print(f"\n[✔] Local Threat Intel Completed. Report saved to {report_file}")
