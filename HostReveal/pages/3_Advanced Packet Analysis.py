# main.py
import streamlit as st
from modules.packet_analysis import PacketAnalysisModule
import json
import os

# Set page configuration
st.set_page_config(page_title="Packet Traffic Analysis Module", page_icon="📡", layout="wide")

# Title and description
st.title("📡 Packet Traffic Analysis Module")
st.write(
    "Analyze traffic using Zeek, Suricata, and TCPFlow. "
    "Perform DNS, HTTP, SSL parsing, detect threats, and gather ASN info."
)

# Input for target domain
domain = st.text_input("🌐 Enter the target domain for analysis:")

# Button to trigger processing
if st.button("🚀 Start Analysis"):
    if not domain:
        st.warning("⚠️ Please enter a valid domain to continue.")
    else:
        with st.spinner("🔎 Processing... This may take a few minutes..."):
            # Initialize PacketAnalysisModule
            analyzer = PacketAnalysisModule(domain)
            final_result = analyzer.run_all()

        if "error" in final_result:
            st.error(f"❌ Error: {final_result['error']}")
        else:
            # Save the report locally
            report_file = f"files/process/{domain.replace('.', '_')}_packet_analysis.json"
            os.makedirs("files/process", exist_ok=True)
            with open(report_file, "w") as f:
                json.dump(final_result, f, indent=4)

            st.success(f"🎉 Packet Analysis Completed! Report saved to `{report_file}`")

            # Display Results in Streamlit
            st.subheader("📄 Analysis Report Summary")

            # Zeek DNS Results
            st.write("## 📡 Zeek DNS Results")
            if final_result["zeek_dns"]:
                st.json(final_result["zeek_dns"])
            else:
                st.warning("⚠️ No DNS data found from Zeek.")

            # Zeek HTTP Results
            st.write("## 🌐 Zeek HTTP Requests")
            if final_result["zeek_http"]:
                st.json(final_result["zeek_http"])
            else:
                st.warning("⚠️ No HTTP requests found.")

            # Zeek SSL/TLS Information
            st.write("## 🔐 Zeek SSL/TLS Data")
            if final_result["zeek_ssl"]:
                st.json(final_result["zeek_ssl"])
            else:
                st.warning("⚠️ No SSL/TLS data found.")

            # Suricata Alerts
            st.write("## 🚨 Suricata Alerts")
            if final_result["suricata_alerts"]:
                st.json(final_result["suricata_alerts"])
            else:
                st.warning("⚠️ No Suricata alerts generated.")

            # TCPFlow Sessions
            st.write("## 🔎 TCPFlow Session Analysis")
            if final_result["tcpflow_sessions"]:
                st.json(final_result["tcpflow_sessions"])
            else:
                st.warning("⚠️ No TCPFlow sessions detected.")

            # Domain Pivoting Results
            st.write("## 🔁 Domain Pivoting Results")
            if final_result["domain_pivoting"]:
                st.write(final_result["domain_pivoting"])
            else:
                st.warning("⚠️ No pivoting domains discovered.")

            # ASN and IP Reputation Info
            st.write("## 🌍 ASN/Geolocation & IP Reputation Info")
            if final_result["asn_info"]:
                st.json(final_result["asn_info"])
            else:
                st.warning("⚠️ No ASN information retrieved.")

            # Download Report Button
            with open(report_file, "rb") as file:
                st.download_button(
                    label="📥 Download Full Report",
                    data=file,
                    file_name=f"{domain.replace('.', '_')}_packet_analysis.json",
                    mime="application/json"
                )
