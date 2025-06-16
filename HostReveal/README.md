# HostReveal - Cyber Threat Investigation & Hosting Unmasking Tool

## Project Overview

HostReveal is a cybersecurity investigation and threat intelligence tool designed to unmask hidden hosting providers, identify malicious infrastructure, and provide machine learning-powered insights. In an age where services like Cloudflare mask the real origin servers, HostReveal helps security researchers, penetration testers, and SOC teams:

* Go beyond traditional DNS lookups
* Perform deep SSL inspection, packet analysis, and network mapping
* Integrate machine learning to detect anomalies and threats


![Alt text](https://github.com/GarbhitSh/HostReveal/blob/main/f.png)

## Key Features

### Domain & DNS Intelligence

* WHOIS queries, DNS records, passive DNS, reverse DNS
* IP Geolocation and hosting insights

### Network Scanning & SSL Analysis

* Nmap, Masscan scanning
* SSL Certificate Transparency logs inspection
* Network path tracing

### Packet Capture & Advanced Analysis

* Auto packet parsing with Zeek, Suricata, TCPFlow
* Traffic fingerprinting and risk analysis

### Threat Intelligence Correlation

* Integrate with OTX, MISP, Shodan, Censys
* Malicious IP detection & risk scoring

### Machine Learning Pipeline (ML Module)

* DBSCAN clustering of infrastructure
* RandomForest classification of risky hosts
* Deep learning-based anomaly detection
* Time-series forecasting using Prophet

### Interactive Streamlit Dashboard

* Visualize geolocation maps, risk graphs, and ML results
* Dark mode support, report analysis, and ML insights

### Automated Report Generation

* JSON & CSV output
* PDF/HTML report capability (optional)

## Technologies & Libraries Used

| Module | Tools & Libraries |
| --- | --- |
| DNS/WHOIS | dnspython, python-whois, socket, requests |
| Network Scanning | python-nmap, masscan, zmap, scapy |
| SSL Inspection | pyOpenSSL, ssl, http.client, crt.sh |
| Packet Analysis | PyShark, Zeek, Suricata, tcpflow |
| Threat Intel | OTX SDK, Shodan, MISP |
| Machine Learning | scikit-learn, TensorFlow, Prophet, NetworkX, matplotlib, pandas, numpy |
| Visualization | Streamlit, Plotly, Folium |

## Why HostReveal?

* Bypass CDN shielding (Cloudflare, Akamai)
* Perform multi-layered digital forensics
* Enhance investigations with AI/ML insights
* Aggregate DNS, SSL, packet, and risk data in one tool
* Visual dashboards for quick decision making

## Project Impact

* Helps SOC analysts detect hidden malicious servers
* Aids OSINT researchers and pentesters to correlate domains, IPs, and SSL traces
* Supports proactive threat hunting with ML-enhanced risk detection
* Speeds up digital forensic investigations with auto-reports and visualization

## Installation

```bash
git clone https://github.com/garbhitsh/HostReveal.git
cd HostReveal
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run Host_Reveal.py
```

Optional:

* Install nmap, tshark, zeek, suricata system-wide if needed.

## Project Structure

```bash
├── Host_Reveal.py                 # Main Streamlit UI
├── ml_module.py                   # Machine Learning module
├── modules/                       # Domain, network, SSL, packet, threat modules
├── pages/                         # Streamlit multi-page app structure
├── files/final_reports/           # Generated final JSON reports
├── files/process/                 # Processed CSV/PCAP/Graph outputs
├── README.md
└── requirements.txt
```

## Example Outputs

* Geolocation World Map of Real Server IPs
* Bar & Pie charts of Risky IPs
* ML Insights: DBSCAN clusters, Anomaly scores, Risk predictions
* Interactive Network Graph (GEXF export for Gephi)

## Future Improvements

* Auto PDF/HTML report generation
* Real-time monitoring mode
* More threat intelligence source integrations
* Webhooks/Slack alerts for critical findings





## Related Projects

* Zeek
* Suricata
* Shodan
* MISP Threat Intel

## Ready to Unmask the Hidden Web?

Start your investigation with:

```bash
streamlit run Host_Reveal.py
```
