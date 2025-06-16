domain_module.py
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
IPINFO_TOKEN = "019df4c4b07109"
VIRUSTOTAL_API_KEY = "aa75ac3bd1d0e2c6921afcb8fa69b21e8b981b731be1d9ef6f98ab1821df1085"

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

network_module.py
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

packet_analysis.py

import os
import json
import glob
import re
import subprocess
import socket
from tqdm import tqdm
import requests

IPINFO_TOKEN = "019df4c4b07109"
class PacketAnalysisModule:
    def __init__(self, domain, output_dir="analysis_output"):
        self.domain = domain
        self.output_dir = output_dir
        self.pcap_file = os.path.join(output_dir, f"{domain}.pcap")
        self.tcpflow_dir = os.path.join(output_dir, "tcpflow")
        self.zeek_dir = os.path.join(output_dir, "zeek")
        self.suricata_file = os.path.join(output_dir, "eve.json")
        os.makedirs(self.output_dir, exist_ok=True)
        self.result = {
            "zeek_dns": [],
            "zeek_http": [],
            "zeek_ssl": [],
            "domain_pivoting": set(),
            "suricata_alerts": [],
            "tcpflow_sessions": [],
            "asn_info": []
        }

    def resolve_domain(self):
        try:
            ip = socket.gethostbyname(self.domain)
            print(f"[+] Resolved {self.domain} to {ip}")
            return ip
        except socket.gaierror:
            print(f"[!] Failed to resolve {self.domain}")
            return None

    def capture_traffic(self, target_ip):
        print(f"[+] Capturing traffic to {target_ip}")
        cmd = f"tcpdump -c 100 -nn host {target_ip} -w {self.pcap_file}"
        try:
            subprocess.run(cmd, shell=True, check=True, timeout=60)
        except subprocess.TimeoutExpired:
            print("[!] tcpdump capture timed out.")
        except subprocess.CalledProcessError:
            print("[!] tcpdump failed to execute.")

    def run_zeek(self):
        print("[+] Running Zeek on pcap")
        os.makedirs(self.zeek_dir, exist_ok=True)
        try:
            subprocess.run(f"zeek -r {self.pcap_file} --output_dir {self.zeek_dir}",
                           shell=True, check=True, timeout=60)
        except subprocess.TimeoutExpired:
            print("[!] Zeek analysis timed out.")
        except subprocess.CalledProcessError:
            print("[!] Zeek failed to execute.")

    def run_suricata(self):
        print("[+] Running Suricata")
        try:
            subprocess.run(f"suricata -r {self.pcap_file} -l {self.output_dir}",
                           shell=True, check=True, timeout=60)
        except subprocess.TimeoutExpired:
            print("[!] Suricata analysis timed out.")
        except subprocess.CalledProcessError:
            print("[!] Suricata failed to execute.")

    def run_tcpflow(self):
        print("[+] Running TCPFlow")
        os.makedirs(self.tcpflow_dir, exist_ok=True)
        try:
            subprocess.run(f"tcpflow -r {self.pcap_file} -o {self.tcpflow_dir}",
                           shell=True, check=True, timeout=60)
        except subprocess.TimeoutExpired:
            print("[!] TCPFlow execution timed out.")
        except subprocess.CalledProcessError:
            print("[!] TCPFlow failed to execute.")

    def parse_zeek_logs(self):
        dns_log = os.path.join(self.zeek_dir, 'dns.log')
        http_log = os.path.join(self.zeek_dir, 'http.log')
        ssl_log = os.path.join(self.zeek_dir, 'ssl.log')

        for log_file, key, col_index in [(dns_log, "zeek_dns", 9), (http_log, "zeek_http", 5), (ssl_log, "zeek_ssl", 8)]:
            if os.path.exists(log_file):
                with open(log_file) as f:
                    for line in f:
                        if not line.startswith("#"):
                            cols = line.strip().split('\t')
                            if len(cols) > col_index:
                                entry = cols[col_index]
                                self.result[key].append(entry)
                                self.result["domain_pivoting"].add(entry)

    def parse_suricata_alerts(self):
        if os.path.exists(self.suricata_file):
            with open(self.suricata_file) as f:
                for line in f:
                    try:
                        alert = json.loads(line)
                        if alert.get('event_type') == 'alert':
                            self.result["suricata_alerts"].append({
                                "timestamp": alert.get("timestamp"),
                                "src_ip": alert.get("src_ip"),
                                "dest_ip": alert.get("dest_ip"),
                                "alert": alert.get("alert", {}).get("signature", "")
                            })
                    except:
                        continue

    def parse_tcpflow_sessions(self):
        files = glob.glob(os.path.join(self.tcpflow_dir, '*'))
        for file in tqdm(files):
            try:
                with open(file, 'r', errors='ignore') as f:
                    data = f.read()
                    hosts = re.findall(r'Host: ([^\r\n]+)', data)
                    gets = re.findall(r'GET (.+?) HTTP', data)
                    if hosts or gets:
                        self.result["tcpflow_sessions"].append({
                            "file": os.path.basename(file),
                            "hosts": hosts,
                            "gets": gets
                        })
            except:
                continue

    def lookup_asn_reputation(self, ip):
        try:
            url = f"https://ipinfo.io/{ip}/json"
            if IPINFO_TOKEN:
                url += f"?token={IPINFO_TOKEN}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                self.result["asn_info"].append(resp.json())
            else:
                print(f"[!] ASN lookup failed for {ip}")
        except requests.exceptions.Timeout:
            print(f"[!] ASN lookup for {ip} timed out.")
        except requests.RequestException as e:
            print(f"[!] ASN lookup error: {e}")

    def run_all(self):
        ip = self.resolve_domain()
        if not ip:
            return {"error": "Domain resolution failed"}

        self.capture_traffic(ip)
        self.run_zeek()
        self.run_suricata()
        self.run_tcpflow()
        self.parse_zeek_logs()
        self.parse_suricata_alerts()
        self.parse_tcpflow_sessions()
        self.lookup_asn_reputation(ip)

        self.result["domain_pivoting"] = list(self.result["domain_pivoting"])
        return self.result


if __name__ == "__main__":
    domain = input("Enter target domain: ").strip()
    analyzer = PacketAnalysisModule(domain)
    final_result = analyzer.run_all()

    report_file = f"files/process/{domain.replace('.', '_')}_packet_analysis.json"
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    with open(report_file, "w") as f:
        json.dump(final_result, f, indent=4)

    print(f"\n[✔] Complete Packet Analysis Done. Report saved to {report_file}")

ssl_network.py
import scapy.all as scapy
import pyshark
import subprocess
import socket
import ssl
import requests
from OpenSSL import crypto
import json
import re


class SSLNetworkModule:
    def __init__(self, target):
        self.target = target
        self.resolved_ip = None
        self.result = {
            "traceroute": [],
            "packet_capture": [],
            "ssl_certificate": {},
            "server_headers": {}
        }

    def resolve_target(self):
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
            print(f"[+] Resolved {self.target} to {self.resolved_ip}")
        except socket.gaierror:
            print(f"[!] Failed to resolve {self.target}")
            self.resolved_ip = None

    # 4.1 Traceroute using Scapy
    def run_traceroute(self):
        print(f"[+] Running traceroute to {self.target}")
        try:
            hops = scapy.traceroute(self.target, maxttl=20, verbose=0)[0]
            for snd, rcv in hops:
                self.result["traceroute"].append({
                    "hop": rcv.ttl,
                    "ip": rcv.src
                })
        except Exception as e:
            self.result["traceroute"] = {"error": str(e)}

    # 4.2 Packet Capture & Analysis using tshark and PyShark
    def run_packet_capture(self, capture_duration=10):
        pcap_file = f"{self.target}_capture.pcap"
        print(f"[+] Capturing packets to {self.target} for {capture_duration} seconds")
        try:
            subprocess.run(["tshark", "-a", f"duration:{capture_duration}", "-w", pcap_file], check=True)
            capture = pyshark.FileCapture(pcap_file, only_summaries=True)
            packets = []
            for packet in capture:
                packets.append(packet.summary_line)
            self.result["packet_capture"] = packets
        except Exception as e:
            self.result["packet_capture"] = {"error": str(e)}

    # 4.3 SSL Certificate Inspection using SSL and pyOpenSSL
    def ssl_certificate_analysis(self):
        print(f"[+] Performing SSL Certificate Analysis on {self.target}")
        port = 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    self.result["ssl_certificate"]["subject"] = cert.get('subject', [])
                    self.result["ssl_certificate"]["issuer"] = cert.get('issuer', [])
                    self.result["ssl_certificate"]["SAN"] = cert.get('subjectAltName', [])
                    self.result["ssl_certificate"]["valid_from"] = cert.get('notBefore')
                    self.result["ssl_certificate"]["valid_to"] = cert.get('notAfter')
        except Exception as e:
            self.result["ssl_certificate"] = {"error": str(e)}

    # Server Header Inspection using Requests
    def server_header_inspection(self):
        print(f"[+] Fetching server headers for {self.target}")
        try:
            url = f"https://{self.target}" if not self.target.startswith('http') else self.target
            resp = requests.get(url, timeout=5, verify=False)
            headers = dict(resp.headers)
            self.result["server_headers"] = headers
        except Exception as e:
            self.result["server_headers"] = {"error": str(e)}

    def run_all(self):
        self.resolve_target()
        if not self.resolved_ip:
            print("[!] Exiting: Invalid target or resolution failed.")
            return self.result

        self.run_traceroute()
        self.run_packet_capture()
        self.ssl_certificate_analysis()
        self.server_header_inspection()
        return self.result


if __name__ == "__main__":
    target = input("Enter target domain or IP: ")
    ssl_module = SSLNetworkModule(target)
    final_result = ssl_module.run_all()

    report_file = f"files/process/{target.replace('/', '_')}_ssl_network_report.json"
    with open(report_file, "w") as f:
        json.dump(final_result, f, indent=4)

    print(f"\n[✔] SSL & Network Path Inspection Completed. Report saved to {report_file}")

fingerprint_module.py
import subprocess
import json
import os
import socket
import requests
from tqdm import tqdm
import wappalyzer  
from pyppeteer import launch

class FingerprintModule:
    def __init__(self, domain, output_dir="fingerprint_output"):
        self.domain = domain
        self.url = f"https://{domain}" if not domain.startswith('http') else domain
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.result = {
            "tech_stack": [],
            "headers": {},
            "visual_screenshots": [],
            "leak_detected": []
        }

    # 6.1 Technology Stack Discovery using Wappalyzer
    async def detect_technology_stack(self):
        print(f"[+] Detecting technology stack for {self.url}")
        try:
            webpage = await WebPage.new_from_url(self.url)
            wappalyzer = Wappalyzer.latest()
            technologies = wappalyzer.analyze(webpage)
            self.result["tech_stack"] = list(technologies)
        except Exception as e:
            print(f"[!] Wappalyzer failed: {e}")
            self.result["tech_stack"] = {"error": str(e)}

    # Optional: Get server headers
    def fetch_headers(self):
        try:
            resp = requests.get(self.url, timeout=5, verify=False)
            self.result["headers"] = dict(resp.headers)
        except Exception as e:
            self.result["headers"] = {"error": str(e)}

    # 6.2 Visual Reconnaissance - Using Aquatone if installed
    def run_aquatone(self):
        print("[+] Running Aquatone for visual recon (if installed)")
        try:
            aquatone_dir = os.path.join(self.output_dir, "aquatone")
            os.makedirs(aquatone_dir, exist_ok=True)
            with open(f"{self.output_dir}/domains.txt", "w") as f:
                f.write(self.domain)
            subprocess.run(f"cat {self.output_dir}/domains.txt | aquatone -out {aquatone_dir}", shell=True, check=True)
            self.result["visual_screenshots"].append(f"{aquatone_dir}/aquatone_report.html")
        except Exception as e:
            print(f"[!] Aquatone failed: {e}")
            self.result["visual_screenshots"].append(f"Error: {e}")

    # OPTIONAL: Manual screenshot using pyppeteer headless browser (if Aquatone not available)
    async def headless_screenshot(self):
        try:
            browser = await launch(headless=True)
            page = await browser.newPage()
            await page.goto(self.url, timeout=10000)
            screenshot_path = os.path.join(self.output_dir, f"{self.domain.replace('.', '_')}_screenshot.png")
            await page.screenshot({'path': screenshot_path, 'fullPage': True})
            await browser.close()
            self.result["visual_screenshots"].append(screenshot_path)
        except Exception as e:
            print(f"[!] Screenshot failed: {e}")

    # Optional: Check if hidden leaks in headers or page source
    def detect_hidden_leaks(self):
        leaks = []
        server = self.result["headers"].get('Server', '')
        x_powered = self.result["headers"].get('X-Powered-By', '')

        if server:
            leaks.append(f"Server header leak: {server}")
        if x_powered:
            leaks.append(f"X-Powered-By leak: {x_powered}")

        try:
            resp = requests.get(self.url, timeout=5, verify=False)
            if 'internal' in resp.text.lower() or 'localhost' in resp.text.lower():
                leaks.append("Potential internal reference leak detected")
        except:
            pass

        self.result["leak_detected"] = leaks

    async def run_all(self):
        await self.detect_technology_stack()
        self.fetch_headers()
        self.detect_hidden_leaks()
        try:
            self.run_aquatone()  # Comment out if Aquatone is unavailable
        except:
            print("[!] Falling back to headless browser screenshot")
            await self.headless_screenshot()
        return self.result


if __name__ == "__main__":
    import asyncio

    domain = input("Enter target domain: ").strip()
    fingerprint = FingerprintModule(domain)
    final_result = asyncio.run(fingerprint.run_all())

    report_file = f"files/process/{domain.replace('.', '_')}_fingerprint_report.json"
    with open(report_file, "w") as f:
        json.dump(final_result, f, indent=4)

    print(f"\n[✔] Web Fingerprinting Completed. Report saved to {report_file}")

threat_intel.py
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
