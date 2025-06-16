# main.py
import streamlit as st
from modules.ssl_network import SSLNetworkModule
import json
import os

# Set page configuration
st.set_page_config(page_title="SSL & Network Path Inspection Module", page_icon="🔐", layout="wide")

# Title and description
st.title("🔐 SSL & Network Path Inspection Module")
st.write(
    "Perform traceroute, packet capture, SSL certificate analysis, and server header inspection."
)

# Input for target domain or IP
target = st.text_input("🌐 Enter the target domain or IP:")

# Button to trigger processing
if st.button("🚀 Start SSL & Network Analysis"):
    if not target:
        st.warning("⚠️ Please enter a valid target domain or IP to continue.")
    else:
        with st.spinner("🔎 Processing... This may take a few minutes..."):
            # Initialize SSLNetworkModule
            ssl_module = SSLNetworkModule(target)
            final_result = ssl_module.run_all()

        if "error" in final_result:
            st.error(f"❌ Error: {final_result['error']}")
        else:
            # Save the report locally
            report_file = f"files/process/{target.replace('.', '_')}_ssl_network_report.json"
            os.makedirs("files/process", exist_ok=True)
            with open(report_file, "w") as f:
                json.dump(final_result, f, indent=4)

            st.success(f"🎉 SSL & Network Inspection Completed! Report saved to `{report_file}`")

            # Display Results in Streamlit
            st.subheader("📄 Analysis Report Summary")

            # Traceroute Results
            st.write("## 🌍 Traceroute Results")
            if final_result["traceroute"]:
                st.json(final_result["traceroute"])
            else:
                st.warning("⚠️ No traceroute data found.")

            # Packet Capture Results
            st.write("## 📡 Packet Capture Summary")
            if final_result["packet_capture"]:
                st.json(final_result["packet_capture"])
            else:
                st.warning("⚠️ No packet capture data available.")

            # SSL Certificate Analysis
            st.write("## 🔐 SSL Certificate Analysis")
            if final_result["ssl_certificate"]:
                st.json(final_result["ssl_certificate"])
            else:
                st.warning("⚠️ SSL certificate analysis failed.")

            # Server Header Inspection
            st.write("## 📄 Server Header Inspection")
            if final_result["server_headers"]:
                st.json(final_result["server_headers"])
            else:
                st.warning("⚠️ Server headers not found or inspection failed.")

            # Download Report Button
            with open(report_file, "rb") as file:
                st.download_button(
                    label="📥 Download Full Report",
                    data=file,
                    file_name=f"{target.replace('.', '_')}_ssl_network_report.json",
                    mime="application/json"
                )
