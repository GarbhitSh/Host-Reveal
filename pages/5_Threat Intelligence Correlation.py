# main.py
import streamlit as st
from modules.threat_intel import ThreatIntelToolModule
import json
import os

# Set page configuration
st.set_page_config(page_title="Threat Intelligence Module", page_icon="🕵️", layout="wide")

# Title and description
st.title("🕵️ Local Threat Intelligence Tool")
st.write(
    "Perform Nmap scans, fingerprint analysis, IOC checks, and MISP correlation to detect possible threats."
)

# Input for target domain or IP
target = st.text_input("🔎 Enter the target IP or domain:")

# File upload for MISP and IOC (Optional)
misp_file = st.file_uploader("📂 Upload MISP IOC JSON File (Optional)", type=["json"])
ioc_file = st.file_uploader("📂 Upload Local Threat IOC List (Optional)", type=["txt"])

# Set file paths for local usage
misp_local_ioc_file = "misp_iocs.json"
local_threat_list = "threat_list.txt"

# Save uploaded files if provided
if misp_file is not None:
    with open(misp_local_ioc_file, "wb") as f:
        f.write(misp_file.read())
    st.success(f"✅ MISP IOC file uploaded: `{misp_local_ioc_file}`")

if ioc_file is not None:
    with open(local_threat_list, "wb") as f:
        f.write(ioc_file.read())
    st.success(f"✅ Threat IOC list uploaded: `{local_threat_list}`")

# Button to start threat intelligence analysis
if st.button("🚀 Run Threat Intelligence"):
    if not target:
        st.warning("⚠️ Please enter a valid target IP or domain.")
    else:
        with st.spinner("🕵️ Performing Threat Intelligence Analysis..."):
            # Initialize ThreatIntelToolModule
            intel = ThreatIntelToolModule(target, misp_local_ioc_file, local_threat_list)
            final_result = intel.run_all()

        # Check for errors
        if "error" in final_result:
            st.error(f"❌ Error: {final_result['error']}")
        else:
            # Save the report locally
            report_file = f"files/process/{target.replace('.', '_')}_local_threat_intel.json"
            os.makedirs("files/process", exist_ok=True)
            with open(report_file, "w") as f:
                json.dump(final_result, f, indent=4)

            st.success(f"🎉 Threat Intelligence Completed! Report saved to `{report_file}`")

            # Display Results in Streamlit
            st.subheader("📄 Analysis Report Summary")

            # Nmap Scan Results
            st.write("## 📡 Nmap Scan Results")
            if final_result["nmap_scan"]:
                st.text(final_result["nmap_scan"])
            else:
                st.warning("⚠️ No Nmap scan results found or scan failed.")

            # Fingerprint Info
            st.write("## 🔎 Fingerprint Information")
            if final_result["fingerprint_info"]:
                st.json(final_result["fingerprint_info"])
            else:
                st.warning("⚠️ No fingerprint data found.")

            # IOC Matches
            st.write("## 🧩 IOC Matches")
            if final_result["ioc_matches"]:
                st.json(final_result["ioc_matches"])
            else:
                st.success("✅ No IOC matches found.")

            # MISP Hits
            st.write("## 📊 MISP Correlation Hits")
            if final_result["misp_hits"]:
                st.json(final_result["misp_hits"])
            else:
                st.success("✅ No MISP correlation hits found.")

            # Download Report Button
            with open(report_file, "rb") as file:
                st.download_button(
                    label="📥 Download Full Report",
                    data=file,
                    file_name=f"{target.replace('.', '_')}_local_threat_intel.json",
                    mime="application/json"
                )
