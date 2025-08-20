import os
import joblib
import numpy as np
import hashlib
import pandas as pd

# Use safe absolute path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODEL_PATH = os.path.join(BASE_DIR, "ml", "phishing_model.pkl")

# Expected SHA-256 hash of the model file
# SECURITY NOTICE: You MUST set a valid hash here for model integrity verification
# You can generate it with: hashlib.sha256(open(MODEL_PATH, 'rb').read()).hexdigest()
# The application will not start until you provide a valid hash
#EXPECTED_MODEL_HASH = hashlib.sha256(open(MODEL_PATH, 'rb').read()).hexdigest()

def verify_model_integrity(file_path, expected_hash):
    """Verify the integrity of a file by comparing its hash with the expected hash."""
    # Calculate the actual hash of the model file
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        actual_hash = sha256_hash.hexdigest()
        
        # If no expected hash is provided, fail with a detailed message
        if not expected_hash:
            print("SECURITY ERROR: Model integrity verification is not configured.")
            print(f"Current model hash: {actual_hash}")
            print("To enable the application, set EXPECTED_MODEL_HASH to the value above.")
            return False  # Don't allow loading without a hash
        
        # Compare with expected hash
        if actual_hash != expected_hash:
            print(f"SECURITY ERROR: Model file integrity check failed. The file may have been tampered with.")
            print(f"Expected hash: {expected_hash}")
            print(f"Actual hash: {actual_hash}")
            return False
        return True
    except Exception as e:
        print(f"Error verifying model file: {e}")
        return False

# Verify model integrity before loading
if not verify_model_integrity(MODEL_PATH, EXPECTED_MODEL_HASH):
    raise ValueError("Model file integrity check failed. Cannot load the model without verification.")

# Load the model only if it passes integrity check
model = joblib.load(MODEL_PATH)
print()
def predict_from_features(feature_vector):
    # Convert to 2D array for prediction
    
    X = pd.DataFrame([feature_vector], columns=["having_IP_Address", "URL_Length", "Shortening_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "Web_Traffic", "Page_Rank", "Google_Index",
    "Links_pointing_to_page", "Statistical_report"])
    
    proba = model.predict_proba(X)[0]
    pred = model.predict(X)[0]
    confidence = round(max(proba) * 100, 2)

    # Interpret using thresholds
    if confidence < 70:
        label = "suspicious"
    else:
        label = "malicious" if pred == -1 else "safe"

    return {
        "prediction": label,
        "confidence": confidence
    }
