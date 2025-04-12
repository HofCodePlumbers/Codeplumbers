# file: test_client.py

import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from quantum_key_sim import generate_bb84_key

API_URL = "http://127.0.0.1:5000/predict"
URL_TO_TEST = "http://free-lottery123.tk/login"

def encrypt_url(url: str, key: bytes) -> str:
    iv = b'QUANTUMBLOCKMODE'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(url.encode(), AES.block_size))
    return base64.urlsafe_b64encode(ciphertext).decode()

if __name__ == "__main__":
    print("🔐 Generating quantum AES key...")
    key = generate_bb84_key()
    key_hex = key.hex()

    print("🔗 Encrypting URL...")
    encrypted_url = encrypt_url(URL_TO_TEST, key)

    print("📤 Sending to Flask backend...")
    response = requests.post(API_URL, json={
        "encrypted_url": encrypted_url,
        "key": key_hex
    })

    print("\n🎯 Server Response:")
    print(response.status_code, response.json())

