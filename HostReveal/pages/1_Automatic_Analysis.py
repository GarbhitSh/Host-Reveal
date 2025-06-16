import streamlit as st
import json
import os
from modules.domain_module import DomainModule
from modules.network_module import NetworkModule
from modules.packet_analysis import PacketAnalysisModule
from modules.ssl_network import SSLNetworkModule
from modules.threat_intel import ThreatIntelToolModule

st.set_page_config(page_title="HostReveal - Cyber Threat Analysis", layout="wide")
st.title("🕵️‍♂️ HostReveal - Unmask Hidden Hosting Providers & Threat Detection")

# Create folders
os.makedirs("files/final_reports", exist_ok=True)
os.makedirs("files/process", exist_ok=True)

# User Input
domain = st.text_input("Enter Target Domain / IP", "")
if st.button("Run Complete HostReveal Analysis") and domain:
    progress = st.progress(0)
    final_report = {}

    # 1. Domain Intelligence
    progress.progress(10)
    st.write("🔎 Running Domain Intelligence Module...")
    domain_module = DomainModule(domain)
    domain_result = domain_module.run_all()
    final_report["Domain Intelligence"] = domain_result

    # 2. Network Scanning
    progress.progress(30)
    st.write("🌐 Running Network Scanning Module...")
    network_module = NetworkModule(domain)
    network_module.resolve_target()
    network_result = network_module.run_all()
    final_report["Network Scanning"] = network_result

    # 3. Packet Analysis
    progress.progress(50)
    st.write("📦 Running Advanced Packet Analysis Module...")
    packet_module = PacketAnalysisModule(domain)
    packet_result = packet_module.run_all()
    final_report["Packet Analysis"] = packet_result

    # 4. SSL Inspection & Network Path
    progress.progress(65)
    st.write("🔐 Running SSL & Network Path Inspection...")
    ssl_module = SSLNetworkModule(domain)
    ssl_result = ssl_module.run_all()
    final_report["SSL Inspection & Network Path"] = ssl_result

    # 5. Threat Intelligence
    progress.progress(80)
    st.write("⚠️ Running Threat Intelligence Correlation...")
    threat_module = ThreatIntelToolModule(domain)
    threat_result = threat_module.run_all()
    final_report["Threat Intelligence Correlation"] = threat_result

    # 6. Final Report Generation
    progress.progress(95)
    report_path = f"files/final_reports/{domain.replace('.', '_')}_HostReveal_Final_Report.json"
    with open(report_path, "w") as report_file:
        json.dump(final_report, report_file, indent=4)

    progress.progress(100)
    st.success("✅ Complete HostReveal Analysis Done!")
    st.download_button(
        label="📥 Download Full JSON Report",
        data=json.dumps(final_report, indent=4),
        file_name=f"{domain}_HostReveal_Report.json",
        mime="application/json"
    )

    # Summary Output
    st.header("🚀 Key Findings Summary")
    try:
        # Server Location Example (from geolocation)
        geo_info = domain_result.get("geolocation", [])
        if geo_info:
            st.write("🌍 **Server Location (IP Geolocation):**")
            for item in geo_info:
                for ip, loc in item.items():
                    location = loc.get("city", "Unknown") + ", " + loc.get("region", "Unknown") + ", " + loc.get("country", "Unknown")
                    st.write(f"IP: `{ip}` --> **{location}**")

        # SSL Subject or Issuer
        ssl_cert = ssl_result.get("ssl_certificate", {})
        if ssl_cert:
            st.write("🔐 **SSL Issuer/Subject:**")
            st.json(ssl_cert)

        # Threat Detection / Malicious Checks
        if threat_result.get("ioc_matches") or threat_result.get("misp_hits"):
            st.error("⚠️ **Possible Threats or Malicious IOC Matches Detected!**")
            st.write("Matched Threats:")
            st.json(threat_result.get("ioc_matches"))
            st.json(threat_result.get("misp_hits"))
        else:
            st.success("✅ No Threats or Malicious Indicators Found.")

        # Useful Information
        st.write("📌 **Additional Useful Information:**")
        st.write("DNS Records:", domain_result.get("dns_records"))
        st.write("Subdomains (Amass & Sublist3r):", domain_result.get("subdomains_sublist3r"), domain_result.get("subdomains_amass"))
        st.write("Network Banner Grabs:", network_result.get("banner_grabbing"))
        st.write("ASN Info / ISP:", packet_result.get("asn_info"))

    except Exception as e:
        st.error(f"Error parsing final summary: {e}")

else:
    st.info("🔔 Enter a domain and click **Run Complete HostReveal Analysis** to start.")
