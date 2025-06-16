# main.py
import streamlit as st
from modules.network_module import NetworkModule
import json

# Set page configuration
st.set_page_config(page_title="Network Scanning & Mapping Module", page_icon="🌐", layout="wide")

# Title and description
st.title("🔍 Network Scanning & Mapping Module")
st.write("Perform Nmap, Masscan for large ranges, and Banner grabbing using Socket and Netcat.")

# Input for domain or IP
target = st.text_input("🌐 Enter the target IP/Domain/Range to analyze:")

# Button to trigger processing
if st.button("🚀 Start Processing"):
    if not target:
        st.warning("⚠️ Please enter a valid target to continue.")
    else:
        with st.spinner("🔎 Processing... This may take a few moments..."):
            # Initialize the NetworkModule
            scanner = NetworkModule(target)
            scanner.resolve_target()

            # Check if the target was resolved
            if not scanner.resolved_ip:
                st.error("❌ Target resolution failed. Please check the domain/IP and try again.")
            else:
                final_result = scanner.run_all()

                # Save the report locally
                report_file = f"files/process/{target.replace('/', '_')}_network_report.json"
                with open(report_file, "w") as f:
                    json.dump(final_result, f, indent=4)

                st.success(f"🎉 Network Scanning Completed! Report saved to `{report_file}`")

                # Display Results in Streamlit
                st.subheader("📄 Network Scan Summary")

                # Nmap Scan Results
                st.write("## 🕵️ Nmap Scan Results")
                if "error" in final_result["nmap_scan"]:
                    st.error(f"Error running Nmap: {final_result['nmap_scan']['error']}")
                else:
                    st.json(final_result["nmap_scan"])

                # Masscan Scan Results
                st.write("## 🚀 Masscan Scan Results")
                if isinstance(final_result["masscan_scan"], dict) and "error" in final_result["masscan_scan"]:
                    st.error(f"Error running Masscan: {final_result['masscan_scan']['error']}")
                elif not final_result["masscan_scan"]:
                    st.warning("⚠️ No open ports found by Masscan.")
                else:
                    st.json(final_result["masscan_scan"])

                # OS Fingerprint
                st.write("## 🧠 OS Fingerprint")
                if final_result["os_fingerprint"]:
                    st.json(final_result["os_fingerprint"])
                else:
                    st.warning("⚠️ No OS fingerprint data found.")

                # Banner Grabbing Results
                st.write("## 🎯 Banner Grabbing Results")
                if not final_result["banner_grabbing"]:
                    st.warning("⚠️ No banners grabbed from common ports.")
                else:
                    st.json(final_result["banner_grabbing"])

                # Download Report Button
                with open(report_file, "rb") as file:
                    st.download_button(
                        label="📥 Download Full Report",
                        data=file,
                        file_name=f"{target.replace('/', '_')}_network_report.json",
                        mime="application/json"
                    )
