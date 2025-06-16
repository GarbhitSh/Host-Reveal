# ml_app.py

import streamlit as st
import pandas as pd
from modules import ml_module

st.set_page_config(page_title="ML Intelligence | HostReveal", layout="wide")

st.title("🧠 ML Intelligence Processing for HostReveal Report")

uploaded_file = st.file_uploader("Upload HostReveal JSON Report", type=["json"])

if uploaded_file:
    with open("temp_uploaded_report.json", "wb") as f:
        f.write(uploaded_file.read())
    
    st.success("✅ JSON report uploaded successfully.")
    
    if st.button("🚀 Run ML Pipeline"):
        with st.spinner("Processing... This might take a few seconds..."):
            df, message = ml_module.execute_pipeline("temp_uploaded_report.json")
            
            if df is not None:
                st.success(message)
                
                st.subheader("🔍 Processed Data Sample")
                st.dataframe(df.head(50), use_container_width=True)

                # Insights
                st.subheader("📊 Key Insights")
                cluster_count = df['dbscan_cluster'].nunique()
                anomaly_mean = df['dl_anomaly_score'].mean()
                malicious_count = df['malicious_pred'].sum() if 'malicious_pred' in df.columns else 'N/A'

                st.markdown(f"- **Total DBSCAN Clusters:** {cluster_count}")
                st.markdown(f"- **Average DL Anomaly Score:** {anomaly_mean:.4f}")
                st.markdown(f"- **Total Predicted Malicious Entries:** {malicious_count}")

                # Optional: Download Processed CSV
                st.download_button(
                    "📥 Download Processed CSV",
                    data=df.to_csv(index=False),
                    file_name="processed_ml_results.csv",
                    mime="text/csv"
                )
            else:
                st.error(message)
else:
    st.info("📥 Please upload the JSON report to begin.")
