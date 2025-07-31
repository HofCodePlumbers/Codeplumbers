# file: backend/app.py
from qiskit_aer import AerSimulator
from flask import Flask, request, jsonify
from encrypt_url import decrypt_url
from features import extract_features
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import json
from datetime import datetime
from hashlib import sha256
import os
import firebase_admin
from firebase_admin import credentials, firestore
from qiskit.circuit.library import ZZFeatureMap
from qiskit_machine_learning.kernels import FidelityQuantumKernel
import numpy as np
from sklearn.cluster import KMeans
import traceback
# Load Firebase
cred = credentials.Certificate("QC/firebase-cred.json")
firebase_admin.initialize_app(cred)
db = firestore.client()
# Quantum Setup
simulator = AerSimulator()
feature_map = ZZFeatureMap(feature_dimension=3)
fidelity_kernel = FidelityQuantumKernel(feature_map=feature_map)
app = Flask(__name__)
LOG_PATH = "backend/logs/prediction_log.json"
CLUSTERING_LOG = os.path.join("backend", "logs", "clustering_log.json")
def decrypt_url(encrypted_url: str, key_hex: str) -> str:
    key = bytes.fromhex(key_hex)
    iv = b'QUANTUMBLOCKMODE'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(base64.urlsafe_b64decode(encrypted_url))
    return unpad(decrypted, AES.block_size).decode()


def fake_predict(url: str):
    return {
    "label": "phishing" if ".tk" in url or "free" in url else "safe",
    "confidence": 0.91
    }

def log_prediction(ip: str, url: str, result: dict):
    log_entry = {
    "timestamp": datetime.utcnow().isoformat(),
    "ip": ip,
    "url": url,
    "result": result
    }

    db.collection("threat_logs").add(log_entry)
    print(f"[:white_check_mark:] Logged to Firebase: {url} → {result['label']}")
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            data = json.load(f)
    else:
        data = []
        data.append(log_entry)
        with open(LOG_PATH, "w") as f:
            json.dump(data, f, indent=2)
# :white_check_mark: Clustering Logger
def log_clustering(ip, points, labels):
    log_entry = {
    "timestamp": datetime.utcnow().isoformat(),
    "ip": ip,
    "data_points": points,
    "labels": labels
    }
    try:
    # :white_check_mark: Log to Firebase
        db.collection("quantum_clusters").add(log_entry)
        print(f":white_check_mark: Logged clustering to Firebase for IP: {ip}")
    except Exception as e:
        print(f":x: Firebase Logging Error: {e}")
        if os.path.exists(CLUSTERING_LOG):
            with open(CLUSTERING_LOG, "r") as f:
                data = json.load(f)
        else:
            data = []
        data.append(log_entry)
        with open(CLUSTERING_LOG, "w") as f:
            json.dump(data, f, indent=2)
            print(f":white_check_mark: Logged clustering locally to {CLUSTERING_LOG}")
    except Exception as e:
        print(f":x: Local Clustering Log Error: {e}")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    encrypted_url = data.get("encrypted_url")
    key_hex = data.get("key")
    if not encrypted_url or not key_hex:
        return jsonify({"error": "Missing data"}), 400
    try:
        url = decrypt_url(encrypted_url, key_hex)
        features = extract_features(url)
        result = fake_predict(url) # Using placeholder until quantum mod$
        result["transport"] = "PQ TLS (simulated)"
        result["url"] = url
        log_prediction(request.remote_addr, url, result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/quantum_cl$", methods=["POST"])
def quantum_cluster():
    try:
        data = request.get_json()
        if not data or 'data' not in data:
            traceback.print_exc()
            return jsonify({"error": "Missing data"}), 400
        
        points = data['data']
        
        if not points or not isinstance(points, list) or not all(isinstance(p, list) for p in points):
            traceback.print_exc()            
            return jsonify({"error": "Invalid data format"}), 400
        X = np.array(points)
        simulator = AerSimulator()
        feature_map = ZZFeatureMap(feature_dimension=X.shape[1], reps=1)
        fidelity_kernel = FidelityQuantumKernel(feature_map=feature_map)
        kernel_matrix = fidelity_kernel.evaluate(x_vec=X)
        kmeans = KMeans(n_clusters=2, random_state=0, n_init=10)
        
        labels = kmeans.fit_predict(kernel_matrix)
        labels_list = labels.tolist()

        # Converts labels into a string
        labels_list = [str(label) for label in labels_list]
        # Converts points into a string
        points = [str(point) for point in points]

        log_clustering(request.remote_addr, points, labels_list)
        return jsonify({"labels": labels_list})
    except Exception as e:
        traceback.print_exc()

        return jsonify({"error": str(e)}), 500
    
# :white_check_mark: Main entry point
if __name__ == '__main__':
    # Security: Debug mode should never be enabled in production environments as it can expose
    # sensitive information through detailed error pages and stack traces
    
    # Enable debug mode only in development environment
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    # Single app.run() call with controlled debug mode
    app.run(debug=True)
    