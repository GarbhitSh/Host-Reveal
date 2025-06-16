import streamlit as st
import json
import pandas as pd
import plotly.express as px

# 🌙 Dark Mode Toggle
dark_mode = st.toggle("🌙 Enable Dark Mode")

if dark_mode:
    st.markdown(
        """
        <style>
            .main { background-color: #121212; color: #FFFFFF; }
            .stTextInput > div > div > input { background-color: #333; color: #FFF; }
            .stDataFrame { background-color: #333; color: #FFF; }
            .stTable { background-color: #333; color: #FFF; }
        </style>
        """, unsafe_allow_html=True
    )

# 📤 Upload JSON
uploaded_file = st.file_uploader("📤 Upload HostReveal Report JSON", type=["json"])

if uploaded_file:
    report = json.load(uploaded_file)
    st.title(f"🌐 HostReveal Dashboard - {report['Domain Intelligence']['domain']}")


    # WHOIS Section
    with st.container():
        st.markdown("## 📄 WHOIS Information")
        whois = report['Domain Intelligence'].get('whois', {})
        st.json(whois)

    # Geolocation Section
    with st.container():
        st.markdown("## 🌍 Server Geolocation Map & Hosting Insight")
        st.info("This section visualizes server locations, hosting ASNs, and countries identified during the scan.")
        geo_data = report['Domain Intelligence'].get('geolocation', [])

        if geo_data:
            geo_df = pd.DataFrame([
                {
                    "IP": list(entry.keys())[0],
                    "City": list(entry.values())[0].get('city', 'Unknown'),
                    "Region": list(entry.values())[0].get('region', 'Unknown'),
                    "Country": list(entry.values())[0].get('country', 'Unknown'),
                    "Latitude": float(list(entry.values())[0]['loc'].split(",")[0]),
                    "Longitude": float(list(entry.values())[0]['loc'].split(",")[1]),
                    "ASN/Org": list(entry.values())[0].get('org', 'N/A'),
                }
                for entry in geo_data
            ])

            with st.expander("📊 View Hosting Summary Table"):
                st.dataframe(geo_df, use_container_width=True)

            # Top Hosting Providers
            top_hosts = geo_df['ASN/Org'].value_counts().reset_index()
            top_hosts.columns = ['Hosting Provider (ASN/Org)', 'Count']
            st.markdown("#### 🏢 **Top Hosting Providers:**")
            st.table(top_hosts)

            # Plot Map
            center_lat = geo_df["Latitude"].mean()
            center_lon = geo_df["Longitude"].mean()

            fig = px.scatter_mapbox(
                geo_df,
                lat="Latitude",
                lon="Longitude",
                hover_name="IP",
                hover_data=["City", "Region", "Country", "ASN/Org"],
                color_discrete_sequence=["blue"],
                zoom=3,
                height=500
            )
            fig.update_layout(mapbox_style="open-street-map", mapbox_center={"lat": center_lat, "lon": center_lon})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("🚫 No geolocation data available to plot the map.")

    # Passive DNS / Risk Section
    with st.container():
        st.markdown("## ⚠️ Risk / Malicious Detection Summary")
        passive_dns = report['Domain Intelligence'].get('passive_dns', {}).get('data', [])
        risk_data = []
        for entry in passive_dns:
            ip = entry['attributes'].get('ip_address')
            mal_score = entry['attributes']['ip_address_last_analysis_stats'].get('malicious', 0)
            suspicious = entry['attributes']['ip_address_last_analysis_stats'].get('suspicious', 0)
            risk_data.append({"IP": ip, "Malicious": mal_score, "Suspicious": suspicious})

        risk_df = pd.DataFrame(risk_data)
        if not risk_df.empty:
            st.dataframe(risk_df, use_container_width=True)

            # 📊 Bar Graph for Risk
            fig = px.bar(risk_df, x='IP', y=['Malicious', 'Suspicious'], title="Risk Levels per IP")
            st.plotly_chart(fig)

            # ✅ Additional Pie Chart
            total_malicious = risk_df['Malicious'].sum()
            total_suspicious = risk_df['Suspicious'].sum()
            total_safe = len(risk_df) - ((risk_df['Malicious'] > 0) | (risk_df['Suspicious'] > 0)).sum()

            pie_data = pd.DataFrame({
                'Risk Type': ['Malicious', 'Suspicious', 'Safe'],
                'Count': [total_malicious, total_suspicious, total_safe]
            })
            pie_fig = px.pie(pie_data, names='Risk Type', values='Count', title='Overall Risk Distribution')
            st.plotly_chart(pie_fig)

            # 🚨 High Risk Detection
            high_risk = risk_df[(risk_df['Malicious'] > 0) | (risk_df['Suspicious'] > 0)]
            if not high_risk.empty:
                st.error("🚨 High Risk IPs Detected:")
                st.table(high_risk)
            else:
                st.success("✅ No high-risk IPs detected.")
        else:
            st.warning("No Passive DNS or Risk Data found.")

    # DNS Records Section
    with st.container():
        st.markdown("## 🗂️ DNS Records")
        dns_records = report['Domain Intelligence'].get('dns_records', {})
        st.json(dns_records)

    # Reverse DNS Section
    with st.container():
        st.markdown("## 🔄 Reverse DNS Lookups")
        reverse_dns = report['Domain Intelligence'].get('reverse_dns', [])
        st.json(reverse_dns)

    # SSL Certificate Transparency Logs
    with st.container():
        st.markdown("## 🔐 SSL Certificates (CRT Logs)")
        crt_logs = report['Domain Intelligence'].get('crt_logs', [])
        if crt_logs:
            crt_df = pd.DataFrame(crt_logs)
            st.dataframe(crt_df[['common_name', 'name_value', 'not_before', 'not_after']])
        else:
            st.warning("No SSL Certificate logs available.")

    # Insights / Final Thoughts
    with st.container():
        st.markdown("## 🧠 Insights & Final Report Summary")

        # Dynamic Server Locations Insight
        asns = geo_df['ASN/Org'].value_counts() if not geo_df.empty else pd.Series()
        top_asn = asns.idxmax() if not asns.empty else "Unknown"
        top_asn_count = asns.max() if not asns.empty else 0
        server_location_summary = f"Mostly hosted by `{top_asn}` ({top_asn_count} instances)" if top_asn != "Unknown" else "Server location data is insufficient."

        # Passive DNS Risk Summary
        if not risk_df.empty:
            max_mal = risk_df['Malicious'].max()
            max_susp = risk_df['Suspicious'].max()
            passive_dns_summary = "⚠️ Malicious or suspicious activity detected in Passive DNS." if (max_mal > 0 or max_susp > 0) else "✅ No active malicious detection in Passive DNS."
        else:
            passive_dns_summary = "No Passive DNS data available."

        # SSL Certificate Summary
        if crt_logs:
            ssl_issuers = [entry.get('issuer_ca_id', 'Unknown') for entry in crt_logs]
            unique_ssl_issuers = set(ssl_issuers)
            ssl_summary = f"Certificates issued by: {', '.join(map(str, unique_ssl_issuers))}"
        else:
            ssl_summary = "No SSL Certificate logs available."

        # Reverse DNS Insight
        if reverse_dns:
            reverse_domains = set()
            for entry in reverse_dns:
                for ip, rev in entry.items():
                    if rev:
                        reverse_domains.add(rev)
            reverse_summary = f"Reverse DNS points to possible CDNs or intermediaries: {', '.join(reverse_domains)}" if reverse_domains else "No significant reverse DNS records found."
        else:
            reverse_summary = "No Reverse DNS data available."

        # Risk Analysis
        risk_analysis = "🚨 Risk Level: Malicious IPs Detected" if not risk_df.empty and ((risk_df['Malicious'] > 0).any() or (risk_df['Suspicious'] > 0).any()) else "✅ Risk Level: Safe — No malicious IPs flagged"

        # Render Insights Dynamically
        st.markdown(f"""
        - **Server Locations:** {server_location_summary}
        - **Passive DNS:** {passive_dns_summary}
        - **Certificates:** {ssl_summary}
        - **Reverse DNS:** {reverse_summary}
        - **Risk Analysis:** {risk_analysis}
        """)
