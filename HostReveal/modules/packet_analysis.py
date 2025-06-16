import os
import json
import glob
import re
import subprocess
import socket
from tqdm import tqdm
import requests

IPINFO_TOKEN = ""
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
