# main.py
import streamlit as st
from modules.domain_module import DomainModule
import json

# Set page configuration
st.set_page_config(page_title="Domain Lookup & Data Collection Module", page_icon="🌐", layout="wide")

# Title and description
st.title("🔍 Domain Lookup & Data Collection Module")
st.write("Perform WHOIS lookup, DNS records analysis, subdomain enumeration, geolocation, and more.")

# Input for domain
domain = st.text_input("🌐 Enter the domain to analyze:")

# Button to trigger processing
if st.button("🚀 Start Processing"):
    if not domain:
        st.warning("⚠️ Please enter a valid domain to continue.")
    else:
        with st.spinner("🔎 Processing... This may take a few moments..."):
            # Initialize the DomainModule
            scanner = DomainModule(domain)
            final_result = scanner.run_all()

        # Save the report locally
        report_file = f"files/process/{domain}_full_report.json"
        with open(report_file, "w") as f:
            json.dump(final_result, f, indent=4)

        st.success(f"🎉 Reconnaissance Completed! Report saved to `{report_file}`")

        # Display Results in Streamlit
        st.subheader("📄 Report Summary")

        # WHOIS Data
        st.write("## 📝 WHOIS Information")
        if "error" in final_result["whois"]:
            st.error(f"Error fetching WHOIS data: {final_result['whois']['error']}")
        else:
            st.json(final_result["whois"])

        # DNS Records
        st.write("## 📡 DNS Records")
        if "error" in final_result["dns_records"]:
            st.error(f"Error fetching DNS records: {final_result['dns_records']['error']}")
        else:
            st.json(final_result["dns_records"])

        # Reverse DNS and Geolocation
        st.write("## 🌐 IP Geolocation and Reverse DNS")
        for item in final_result["reverse_dns"]:
            st.write(f"**IP:** {list(item.keys())[0]} ➡️ **PTR:** {list(item.values())[0]}")
        for item in final_result["geolocation"]:
            ip = list(item.keys())[0]
            st.write(f"**Geolocation for {ip}:**")
            st.json(item[ip])

        # Passive DNS (VirusTotal)
        st.write("## 🦠 Passive DNS Data (VirusTotal)")
        if "error" in final_result["passive_dns"]:
            st.error(f"Error fetching passive DNS: {final_result['passive_dns']['error']}")
        else:
            st.json(final_result["passive_dns"])

        # Certificate Logs
        st.write("## 🔐 Certificate Transparency Logs")
        if "error" in final_result["crt_logs"]:
            st.error(f"Error fetching certificate logs: {final_result['crt_logs']['error']}")
        else:
            st.json(final_result["crt_logs"])

        # Subdomains (Sublist3r)
        st.write("## 🌐 Subdomains Found (Sublist3r)")
        if isinstance(final_result["subdomains_sublist3r"], dict) and "error" in final_result["subdomains_sublist3r"]:
            st.error(f"Error running Sublist3r: {final_result['subdomains_sublist3r']['error']}")
        else:
            st.write(final_result["subdomains_sublist3r"])

        # Subdomains (Amass)
        st.write("## 🌐 Subdomains Found (Amass)")
        if isinstance(final_result["subdomains_amass"], dict) and "error" in final_result["subdomains_amass"]:
            st.error(f"Error running Amass: {final_result['subdomains_amass']['error']}")
        else:
            st.json(final_result["subdomains_amass"])

        # DNS Brute Force
        st.write("## 💥 DNS Bruteforce Results")
        if isinstance(final_result["dns_bruteforce"], dict) and "error" in final_result["dns_bruteforce"]:
            st.error(f"Error running DNS Bruteforce: {final_result['dns_bruteforce']['error']}")
        else:
            st.text(final_result["dns_bruteforce"])

        # Download Report Button
        with open(report_file, "rb") as file:
            st.download_button(
                label="📥 Download Full Report",
                data=file,
                file_name=f"{domain}_full_report.json",
                mime="application/json"
            )
