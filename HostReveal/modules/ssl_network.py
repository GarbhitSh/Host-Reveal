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
