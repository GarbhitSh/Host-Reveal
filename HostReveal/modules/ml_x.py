# ml_module.py

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


# Load the JSON report
def load_report():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    print(f"Loaded report from {DATA_FILE}")
    return data

# Normalize and aggregate data
def preprocess_data(content):
    flat_data = pd.json_normalize(content)
    flat_data.fillna(0, inplace=True)
    return flat_data

# DBSCAN Clustering for hidden infrastructure
def run_dbscan(df, feature_cols):
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(df[feature_cols])
    dbscan = DBSCAN(eps=0.5, min_samples=3)
    df['dbscan_cluster'] = dbscan.fit_predict(scaled_features)
    print(f"DBSCAN clusters created. Number of clusters: {len(set(df['dbscan_cluster']))}")
    return df

# Classification Model to predict risky hosts
def train_classifier(df, feature_cols, label_col='malicious'):
    if label_col not in df.columns:
        print(f"Label column '{label_col}' not found. Skipping classification.")
        return df
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(df[feature_cols], df[label_col])
    df['malicious_pred'] = clf.predict(df[feature_cols])
    print("Classification completed. Risky hosts predicted.")
    return df

# Deep Learning Anomaly Detection (TensorFlow)
def deep_learning_anomaly_detection(df, feature_cols):
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(len(feature_cols),)),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(len(feature_cols))
    ])
    model.compile(optimizer='adam', loss='mse')
    model.fit(df[feature_cols], df[feature_cols], epochs=10, verbose=1)
    reconstructions = model.predict(df[feature_cols])
    mse = np.mean(np.square(df[feature_cols] - reconstructions), axis=1)
    df['dl_anomaly_score'] = mse
    print("Deep Learning anomaly scores calculated.")
    return df

# Graph Analysis (NetworkX)
def build_network_graph(df, source_col='source_ip', target_col='dest_ip'):
    G = nx.Graph()
    for _, row in df.iterrows():
        if source_col in row and target_col in row:
            G.add_edge(row[source_col], row[target_col])
    print(f"Graph created with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")
    nx.write_gexf(G, 'network_graph.gexf')
    return G

# Time Series Analysis (Prophet)
def time_series_forecast(df, time_col, value_col):
    if time_col not in df.columns or value_col not in df.columns:
        print(f"Missing {time_col} or {value_col} for time series forecast")
        return None
    ts_df = df[[time_col, value_col]].rename(columns={time_col: 'ds', value_col: 'y'})
    model = Prophet()
    model.fit(ts_df)
    future = model.make_future_dataframe(periods=30)
    forecast = model.predict(future)
    model.plot(forecast)
    plt.show()
    print("Time series forecasting completed.")
    return forecast

# Full Pipeline Execution
def execute_pipeline():
    content = load_report()

    # Flatten nested sections like DNS, SSL, ASN, etc., if needed
    # Example: If 'dns_records' is a list inside JSON
    records = []
    for section in ['dns_records', 'passive_dns', 'ssl_certificate_logs', 'reverse_dns', 'asn_info']:
        if section in content:
            for item in content[section]:
                records.append(item)
    if not records:
        print("No detailed records found in sections. Using full JSON as flat data.")
        df = preprocess_data(content)
    else:
        df = pd.json_normalize(records)
        df.fillna(0, inplace=True)

    # Auto-detect numerical features
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_cols:
        print("No numeric columns found for ML processing.")
        return

    # DBSCAN Clustering
    df = run_dbscan(df, numeric_cols)

    # Classification (only if 'malicious' exists)
    df = train_classifier(df, numeric_cols, 'malicious')

    # Deep Learning Anomaly Detection
    df = deep_learning_anomaly_detection(df, numeric_cols)

    # Graph Analysis if possible
    if 'source_ip' in df.columns and 'dest_ip' in df.columns:
        build_network_graph(df, 'source_ip', 'dest_ip')

    # Time Series Forecasting on timestamp-related fields if found
    time_cols = [col for col in df.columns if 'time' in col or 'timestamp' in col]
    if time_cols:
        time_series_forecast(df, time_cols[0], numeric_cols[0])

    # Save output
    os.makedirs('files/process', exist_ok=True)
    df.to_csv('files/process/processed_ml_results.csv', index=False)
    print("Pipeline executed. Results saved to files/process/processed_ml_results.csv")

if __name__ == "__main__":
    execute_pipeline(DATA_FILE)
