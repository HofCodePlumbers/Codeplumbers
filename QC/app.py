# file: backend/app.py

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import json
from datetime import datetime
from hashlib import sha256
import os
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import logging

# Load service account key (replace with your actual filename)
cred = credentials.Certificate("firebase-cred.json")
firebase_admin.initialize_app(cred)

# Get Firestore DB instance
db = firestore.client()

app = Flask(__name__)
LOG_PATH = "backend/logs/prediction_log.json"

def decrypt_url(encrypted_url: str, key_hex: str, iv_b64: str = None) -> str:
    key = bytes.fromhex(key_hex)
    if iv_b64:
        # Use client-provided IV (secure)
        iv = base64.urlsafe_b64decode(iv_b64)
    else:
        # For backward compatibility - this is insecure and will be deprecated
        logging.warning("SECURITY WARNING: Using static IV for decryption. This is insecure and will be deprecated soon.")
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
    print(f"[✅] Logged to Firebase: {url} → {result['label']}")

    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            data = json.load(f)
    else:
        data = []
    data.append(log_entry)
    with open(LOG_PATH, "w") as f:
        json.dump(data, f, indent=2)

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    encrypted_url = data.get("encrypted_url")
    key_hex = data.get("key")
    iv_b64 = data.get("iv")  # Optional for backward compatibility

    if not encrypted_url or not key_hex:
        return jsonify({"error": "Missing data"}), 400

    try:
        url = decrypt_url(encrypted_url, key_hex, iv_b64)
        result = fake_predict(url)
        result["transport"] = "PQ TLS (simulated)"
        log_prediction(request.remote_addr, url, result)
        return jsonify({**result, "url": url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode)