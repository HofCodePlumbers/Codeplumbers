# file: streamlit_app.py

import firebase_admin
from features import extract_features
from model import predict_from_features
import json
import os
from firebase_admin import credentials, firestore, initialize_app
import streamlit as st
import requests
from quantum_key_sim import generate_bb84_key
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from encrypt_url import encrypt_url, decrypt_url
from quantum_key_sim import safe_generate_key
import platform

if not firebase_admin._apps:
    cred = credentials.Certificate("firebase-cred.json")
    initialize_app(cred)
db = firestore.client()

def get_device_type():
    return f"{platform.system()} {platform.machine()}"

# ✅ Log scan to Firebase
def log_to_firebase(ip, features, result, encrypted_url, aes_key):
    device = get_device_type()
    db.collection("threat_logs").add({
        "ip": ip,
        "device": device,
        "url_encrypted": encrypted_url,
        "aes_key": aes_key,
        "confidence": result.get("confidence"),
        "label": result.get("label"),
        "confidence": result.get("confidence"),
        "transport": "PQ TLS (simulated)"
    })
st.title("🛡️ SafeClick - Quantum URL Threat Scanner")

st.title("🔐 Quantum-Enhanced URL Threat Checker")

url_input = st.text_input("🔗 Enter a URL to scan:")
if st.button("🚀 Generate Key & Scan"):
    try: 
        with st.spinner("Simulating BB84 quantum key exchange..."):
            key = safe_generate_key()
            key_hex = key.hex()
            encrypted_url = encrypt_url(url_input, key)

        decrypted = decrypt_url(encrypted_url, key)
        features = extract_features(decrypted)
        result = predict_from_features(features)

        # ✅ Log with device info
        log_to_firebase("streamlit-user", features, result, encrypted_url, key_hex)
        st.code(f"AES Key (hex): {key_hex}", language="plaintext")
        st.code(f"Encrypted URL: {encrypted_url}", language="plaintext")
        st.code(f"Extracted Features: {features}", language="json")

        if result["label"] == "phishing":
            st.error(f"🚨 PHISHING DETECTED! (Confidence: {result['confidence']})")
        else:
            st.success(f"✅ SAFE URL (Confidence: {result['confidence']})")

        st.caption("🔐 Secured with BB84 Quantum Key + AES + PQ TLS")

    except Exception as e:
        st.error(f"⚠️ Error: {e}")
