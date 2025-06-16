# main.py
import streamlit as st
from modules.fingerprint_module import FingerprintModule
import json
import asyncio
import os

# Set page configuration
st.set_page_config(page_title="Web Fingerprinting Module", page_icon="🌐", layout="wide")

# Title and description
st.title("🌐 Web Fingerprinting Module")
st.write(
    "Perform technology stack analysis, header inspection, visual reconnaissance, and hidden leak detection."
)

# Input for target domain
domain = st.text_input("🔎 Enter the target domain for fingerprinting:")

# Button to start fingerprinting
if st.button("🚀 Start Fingerprinting"):
    if not domain:
        st.warning("⚠️ Please enter a valid target domain.")
    else:
        with st.spinner("🔎 Performing Web Fingerprinting... This may take a few minutes..."):
            # Initialize FingerprintModule
            fingerprint = FingerprintModule(domain)
            final_result = asyncio.run(fingerprint.run_all())

        # Check for errors
        if "error" in final_result:
            st.error(f"❌ Error: {final_result['error']}")
        else:
            # Save the report locally
            report_file = f"files/process/{domain.replace('.', '_')}_fingerprint_report.json"
            os.makedirs("files/process", exist_ok=True)
            with open(report_file, "w") as f:
                json.dump(final_result, f, indent=4)

            st.success(f"🎉 Web Fingerprinting Completed! Report saved to `{report_file}`")

            # Display Results in Streamlit
            st.subheader("📄 Analysis Report Summary")

            # Technology Stack Results
            st.write("## 🛠️ Technology Stack Detected")
            if final_result["tech_stack"]:
                st.json(final_result["tech_stack"])
            else:
                st.warning("⚠️ No technology stack detected or Wappalyzer failed.")

            # Header Inspection Results
            st.write("## 📄 Header Inspection")
            if final_result["headers"]:
                st.json(final_result["headers"])
            else:
                st.warning("⚠️ No headers detected or inspection failed.")

            # Visual Screenshots Results
            st.write("## 📸 Visual Reconnaissance Screenshots")
            if final_result["visual_screenshots"]:
                for screenshot in final_result["visual_screenshots"]:
                    if "Error" not in screenshot:
                        st.image(screenshot, caption="Captured Screenshot", use_column_width=True)
                    else:
                        st.warning(f"⚠️ {screenshot}")
            else:
                st.warning("⚠️ No screenshots generated.")

            # Hidden Leaks Detection
            st.write("## 🕵️ Hidden Leaks Detected")
            if final_result["leak_detected"]:
                st.json(final_result["leak_detected"])
            else:
                st.success("✅ No hidden leaks detected.")

            # Download Report Button
            with open(report_file, "rb") as file:
                st.download_button(
                    label="📥 Download Full Report",
                    data=file,
                    file_name=f"{domain.replace('.', '_')}_fingerprint_report.json",
                    mime="application/json"
                )
