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
import re
from urllib.parse import urlparse

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

# Function to validate URL format
def is_valid_url(url):
    try:
        result = urlparse(url)
        # Check if scheme and netloc are present
        return all([result.scheme, result.netloc])
    except:
        return False

# Function to sanitize URL
def sanitize_url(url):
    # Basic sanitization - remove unwanted characters, limit length
    url = url.strip()
    # Only allow characters typically found in URLs
    url = re.sub(r'[^\w\s:/.?&=%~#-]', '', url)
    return url[:2048]  # Limit URL length

st.title("🛡️ SafeClick - Quantum URL Threat Scanner")

st.title("🔐 Quantum-Enhanced URL Threat Checker")

url_input = st.text_input("🔗 Enter a URL to scan:")
if st.button("🚀 Generate Key & Scan"):
    try: 
        # Validate URL format first
        if not is_valid_url(url_input):
            st.error("⚠️ Please enter a valid URL (including http:// or https://)")
            st.stop()
        
        # Sanitize URL before processing
        sanitized_url = sanitize_url(url_input)
        
        with st.spinner("Simulating BB84 quantum key exchange..."):
            key = safe_generate_key()
            key_hex = key.hex()
            encrypted_url = encrypt_url(sanitized_url, key)

        decrypted = decrypt_url(encrypted_url, key)
        
        # Extract features with validation
        try:
            features = extract_features(decrypted)
            
            # Simple check to ensure features is a valid dictionary
            if not isinstance(features, dict):
                raise ValueError("Invalid feature format")
                
            # Perform ML prediction with validation
            result = predict_from_features(features)
            
            # Validate result format
            if not isinstance(result, dict) or "label" not in result or "confidence" not in result:
                raise ValueError("Invalid prediction result format")
                
        except Exception as feature_error:
            st.error(f"⚠️ Error processing URL: {feature_error}")
            st.stop()

        # ✅ Log with device info
        log_to_firebase("streamlit-user", features, result, encrypted_url, key_hex)
        st.info("🔒 Your URL has been securely encrypted for processing.")
        st.code(f"Extracted Features: {features}", language="json")

        if result["label"] == "phishing":
            st.error(f"🚨 PHISHING DETECTED! (Confidence: {result['confidence']})")
        else:
            st.success(f"✅ SAFE URL (Confidence: {result['confidence']})")

        st.caption("🔐 Secured with BB84 Quantum Key + AES + PQ TLS")

    except Exception as e:
        st.error(f"⚠️ Error: {e}")