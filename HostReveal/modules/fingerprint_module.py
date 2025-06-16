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
