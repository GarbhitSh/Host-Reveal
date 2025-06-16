import streamlit as st

# ✅ Page Config
st.set_page_config(page_title="HostReveal - Cyber Threat Intelligence", layout="wide")

# ✅ Title & Description
st.title("🕵️‍♂️ HostReveal - Unmask Hidden Hosting & Cyber Threat Analysis")
st.markdown("""
HostReveal is a cybersecurity investigation tool designed to **unmask hidden hosting providers** behind services like Cloudflare, detect **malicious infrastructure**, and offer **machine learning-driven insights**.

Leverage HostReveal to:
- 🔍 Perform deep domain, SSL, network, and packet analysis
- 🌐 Map real hosting locations bypassing CDNs
- ⚠️ Detect malicious IPs, compromised servers, and risky certificates
- 🤖 Run ML-driven anomaly and threat detection
""")

# ✅ Style for card-like containers with clickable effect
card_style = """
    <style>
        .card {
            padding: 25px;
            margin: 10px;
            background-color: #f5f5f5;
            border-radius: 15px;
            box-shadow: 2px 2px 8px rgba(0,0,0,0.2);
            text-align: center;
            transition: 0.3s;
        }
        .card:hover {
            background-color: #e8e8e8;
            box-shadow: 4px 4px 12px rgba(0,0,0,0.3);
            transform: translateY(-5px);
        }
        .stButton>button {
            width: 100%;
            background-color: #4CAF50;
            color: white;
            padding: 10px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 16px;
        }
        .stButton>button:hover {
            background-color: #45a049;
        }
    </style>
"""
st.markdown(card_style, unsafe_allow_html=True)

# ✅ Create 3 Columns for the Cards
col1, col2, col3 = st.columns(3)

# ✅ Automatic Analysis Card
with col1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("🚀 Automatic Analysis")
    st.markdown("Run a complete automated scan including DNS, SSL, Packet, and Threat Intelligence modules.")
    if st.button("🔎 Start Auto Analysis"):
        st.switch_page("./pages/1_Automatic_Analysis.py")  # ✅ Page name only (no .py or folder)
    st.markdown('</div>', unsafe_allow_html=True)

# ✅ Report Analysis Card
with col2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("📑 Report Analysis")
    st.markdown("Upload and review detailed JSON reports with geolocation, DNS, risk detection, and insights.")
    if st.button("📂 View Report"):
        st.switch_page("./pages/Report_Analysis.py")
    st.markdown('</div>', unsafe_allow_html=True)

# ✅ Machine Learning Card
with col3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("🧠 Machine Learning")
    st.markdown("Run ML models for clustering, anomaly detection, and risk prediction on processed data.")
    if st.button("🤖 Run ML Analysis"):
        st.switch_page("./pages/ML_Analysis.py")
    st.markdown('</div>', unsafe_allow_html=True)

# ✅ Footer / Note
st.markdown("""
---
🔐 **HostReveal** helps digital investigators, cybersecurity researchers, and SOC teams gain visibility into obfuscated infrastructures.

💻 Built with Python, Streamlit, Nmap, Masscan, TensorFlow, and more.
""")
