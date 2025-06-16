import pandas as pd
import numpy as np
import json
import os
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import tensorflow as tf
import networkx as nx
from prophet import Prophet
import matplotlib.pyplot as plt

INSIGHT_REPORT = {}

def load_report(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    print(f"[+] Loaded report from {json_file}")
    return data

def preprocess_data(content):
    flat_data = pd.json_normalize(content)
    flat_data.fillna(0, inplace=True)
    return flat_data

def run_dbscan(df, feature_cols):
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(df[feature_cols])
    dbscan = DBSCAN(eps=0.5, min_samples=3)
    df['dbscan_cluster'] = dbscan.fit_predict(scaled_features)
    cluster_count = len(set(df['dbscan_cluster'])) - (1 if -1 in df['dbscan_cluster'] else 0)
    INSIGHT_REPORT['dbscan_clusters'] = cluster_count
    print(f"[+] DBSCAN created {cluster_count} clusters (excluding noise)")
    return df

def train_classifier(df, feature_cols, label_col='malicious'):
    if label_col not in df.columns:
        print(f"[!] Label column '{label_col}' not found. Skipping classification.")
        return df
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(df[feature_cols], df[label_col])
    df['malicious_pred'] = clf.predict(df[feature_cols])
    risk_count = df['malicious_pred'].sum()
    INSIGHT_REPORT['predicted_malicious'] = int(risk_count)
    print(f"[+] Classification done. Predicted malicious entries: {risk_count}")
    return df

def deep_learning_anomaly_detection(df, feature_cols):
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(len(feature_cols),)),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(len(feature_cols))
    ])
    model.compile(optimizer='adam', loss='mse')
    model.fit(df[feature_cols], df[feature_cols], epochs=8, verbose=0)
    reconstructions = model.predict(df[feature_cols])
    mse = np.mean(np.square(df[feature_cols] - reconstructions), axis=1)
    df['dl_anomaly_score'] = mse
    INSIGHT_REPORT['avg_anomaly_score'] = round(mse.mean(), 4)
    print(f"[+] Deep Learning anomaly scores calculated. Average Score: {mse.mean():.4f}")
    return df

def build_network_graph(df, source_col='source_ip', target_col='dest_ip'):
    G = nx.Graph()
    for _, row in df.iterrows():
        if pd.notnull(row.get(source_col)) and pd.notnull(row.get(target_col)):
            G.add_edge(row[source_col], row[target_col])
    nodes, edges = G.number_of_nodes(), G.number_of_edges()
    INSIGHT_REPORT['graph_nodes'] = nodes
    INSIGHT_REPORT['graph_edges'] = edges
    print(f"[+] Graph created: {nodes} nodes, {edges} edges.")
    nx.write_gexf(G, 'files/process/network_graph.gexf')
    return G

def time_series_forecast(df, time_col, value_col):
    if time_col not in df.columns or value_col not in df.columns:
        print(f"[!] Missing {time_col} or {value_col} for time series forecast")
        return None
    ts_df = df[[time_col, value_col]].rename(columns={time_col: 'ds', value_col: 'y'})
    model = Prophet()
    model.fit(ts_df)
    future = model.make_future_dataframe(periods=30)
    forecast = model.predict(future)
    print("[+] Time series forecasting completed.")
    # Optional plot
    model.plot(forecast)
    plt.savefig('files/process/prophet_forecast.png')
    return forecast

def execute_pipeline(json_file):
    os.makedirs('files/process', exist_ok=True)
    content = load_report(json_file)

    # Flatten nested sections like DNS, SSL, ASN, etc.
    records = []
    for section in ['dns_records', 'passive_dns', 'ssl_certificate_logs', 'reverse_dns', 'asn_info']:
        if section in content:
            records.extend(content[section])
    df = preprocess_data(records if records else content)

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_cols:
        print("[!] No numeric data for ML processing.")
        return None, "No numeric data available."

    # DBSCAN Clustering
    df = run_dbscan(df, numeric_cols)

    # Classification
    df = train_classifier(df, numeric_cols, 'malicious')

    # Deep Learning Anomaly Detection
    df = deep_learning_anomaly_detection(df, numeric_cols)

    # Graph Analysis if IP data exists
    if 'source_ip' in df.columns and 'dest_ip' in df.columns:
        build_network_graph(df, 'source_ip', 'dest_ip')

    # Optional: Time Series Forecasting
    time_cols = [col for col in df.columns if 'time' in col or 'timestamp' in col]
    if time_cols:
        time_series_forecast(df, time_cols[0], numeric_cols[0])

    # Save processed ML results
    df.to_csv('files/process/processed_ml_results.csv', index=False)

    # Insight Summary
    INSIGHT_REPORT['total_rows_processed'] = len(df)
    INSIGHT_REPORT['numeric_features_used'] = numeric_cols
    print("[✔] ML Pipeline executed successfully. Report ready.")
    return df, INSIGHT_REPORT

if __name__ == "__main__":
    # Example test
    df, insights = execute_pipeline("thalesgroup.com_HostReveal_Report.json")
    print(json.dumps(insights, indent=4))
