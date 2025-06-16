import whois
import dns.resolver
import dns.reversename
import socket
import requests
import json
import subprocess
from ipwhois import IPWhois
from tqdm import tqdm

# Configurable API keys (Replace with your valid keys)
IPINFO_TOKEN = ""
VIRUSTOTAL_API_KEY = ""

class DomainModule:

    def __init__(self, domain):
        self.domain = domain
        self.result = {
            "domain": domain,
            "whois": {},
            "dns_records": {},
            "reverse_dns": [],
            "geolocation": [],
            "passive_dns": {},
            "crt_logs": {},
            "subdomains_sublist3r": [],
            "subdomains_amass": [],
            "dns_bruteforce": ""
        }

    def fetch_whois(self):
        try:
            w = whois.whois(self.domain)
            self.result["whois"] = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "emails": w.emails,
                "name_servers": w.name_servers
            }
        except Exception as e:
            self.result["whois"] = {"error": str(e)}

    def fetch_dns_records(self):
        try:
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'TXT']:
                answers = dns.resolver.resolve(self.domain, record_type, raise_on_no_answer=False)
                self.result["dns_records"][record_type] = [r.to_text() for r in answers]
        except Exception as e:
            self.result["dns_records"]['error'] = str(e)

    def reverse_dns_lookup(self, ip):
        try:
            rev_name = dns.reversename.from_address(ip)
            return str(dns.resolver.resolve(rev_name, "PTR")[0])
        except Exception:
            return None

    def ip_geolocation(self, ip):
        try:
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
            resp = requests.get(url)
            return resp.json()
        except Exception as e:
            return {"error": str(e)}

    def process_ips(self):
        ips = self.result["dns_records"].get("A", [])
        for ip in tqdm(ips, desc="Processing IPs"):
            ptr = self.reverse_dns_lookup(ip)
            self.result["reverse_dns"].append({ip: ptr})
            self.result["geolocation"].append({ip: self.ip_geolocation(ip)})

    def passive_dns_virustotal(self):
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/resolutions"
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            self.result["passive_dns"] = response.json() if response.status_code == 200 else {"error": response.text}
        except Exception as e:
            self.result["passive_dns"] = {"error": str(e)}

    def fetch_crt_logs(self):
        try:
            response = requests.get(f'https://crt.sh/?q={self.domain}&output=json')
            self.result["crt_logs"] = response.json() if response.status_code == 200 else {"error": response.text}
        except Exception as e:
            self.result["crt_logs"] = {"error": str(e)}

    def run_sublist3r(self):
        try:
            output_file = f"files/process/{self.domain}_sublist3r.txt"
            subprocess.run(["sublist3r", "-d", self.domain, "-o", output_file], check=True,timeout=30 )
             # Timeout after 5 minutes

            with open(output_file, "r") as file:
                self.result["subdomains_sublist3r"] = file.read().splitlines()
        except subprocess.TimeoutExpired:
            self.result["subdomains_sublist3r"] = {"error": "Sublist3r scan timed out"}
        except Exception as e:

            self.result["subdomains_sublist3r"] = {"error": str(e)}

    def run_amass(self):
        try:
            output_file = f"files/process/{self.domain}_amass.json"
            subprocess.run(["amass", "enum", "-d", self.domain, "-json", output_file], check=True,timeout=60)
            
            with open(output_file, "r") as file:
                data = json.load(file)
            self.result["subdomains_amass"] = data
        except subprocess.TimeoutExpired:
            self.result["subdomains_amass"] = {"error": "Amass scan timed out"}
        except Exception as e:
            self.result["subdomains_amass"] = {"error": str(e)}

    def run_dns_bruteforce(self):
        try:
            output = subprocess.check_output(["dnsrecon", "-d", self.domain, "-t", "brt"])
            self.result["dns_bruteforce"] = output.decode()
        except Exception as e:
            self.result["dns_bruteforce"] = {"error": str(e)}

    def run_all(self):
        print(f"Starting reconnaissance on {self.domain}")
        self.fetch_whois()
        self.fetch_dns_records()
        self.process_ips()
        self.passive_dns_virustotal()
        self.fetch_crt_logs()
        self.run_sublist3r()
        self.run_amass()
        self.run_dns_bruteforce()
        return self.result

if __name__ == "__main__":
    domain = input("Enter domain to scan: ")
    scanner = DomainModule(domain)
    final_result = scanner.run_all()

    report_file = f"files/process/{domain}_full_report.json"


    

    with open(report_file, "w") as f:
        json.dump(final_result, f, indent=4)

    print(f"\n[✔] Reconnaissance Completed. Report saved to {report_file}")
