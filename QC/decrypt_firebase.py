# file: encrypt_url.py
# Works

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import firebase_admin
from firebase_admin import credentials, firestore
from quantum_key_sim import generate_bb84_key  
from encrypt_url import safe_generate_key, decrypt_url
# 1. Initialize Firebase
cred = credentials.Certificate("QC/firebase-cred.json")  # <-- change this
firebase_admin.initialize_app(cred)
db = firestore.client()

def decrypt_url_from_firestore(doc_path: str, field_name: str, key: bytes) -> str:
    """
    Decrypts an encrypted URL stored in a Firestore document.

    Args:
        doc_path (str): Path to the Firestore document (e.g. 'threat_logs/icLgfuspLTrk4pn7nHBA')
        field_name (str): Name of the field that contains the encrypted URL
        key (bytes): AES decryption key (must be same as used in encryption)

    Returns:
        str: The original decrypted URL
    """
    # 2. Read document from Firestore
    doc_ref = db.document(doc_path)
    doc = doc_ref.get()
    
    if not doc.exists:
        raise ValueError(f"Document '{doc_path}' not found.")
    print(f"Document '{doc_path}' retrieved successfully.")
    encrypted_url = doc.to_dict().get(field_name)
    print(f"Encrypted URL  '{encrypted_url}' retrieved successfully.")

    if not encrypted_url:
        raise ValueError(f"Field '{field_name}' not found in document.")
    
    # 3. Decrypt URL
    print("Decrypting URL...")
    # 4. Return decrypted URL
    
    iv = b'QUANTUMBLOCKMODE'  # Must match the IV used during encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(base64.urlsafe_b64decode(encrypted_url))
    print("")
    # 4. Unpad and return the decrypted URL

    return unpad(decrypted, AES.block_size).decode()

if __name__ == "__main__":

    doc_path = "icLgfuspLTrk4pn7nHBA" # <-- change this to the encrypt log path on Firebase

    aes_hex = db.document("threat_logs/"+doc_path).get().to_dict().get("aes_key")
    print("🔐 Generating quantum AES key...")
    key = bytes.fromhex(aes_hex)

    print("Key generated successfully.")

    
    #Decrypt a URL from Firestore
    try:
        doc_path = "threat_logs/" + doc_path  # <-- change this to your document path
        field_name = "url_encrypted"  # <-- change this to your field name
        decrypted_url = decrypt_url_from_firestore(doc_path, field_name, key)
        print("\n🔓 Decrypted URL:", decrypted_url)
    except Exception as e:
        print(f"\n[!] Decryption failed: {e}")