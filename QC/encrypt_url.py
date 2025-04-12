# file: encrypt_url.py

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import time
from tqdm import tqdm
from quantum_key_sim import generate_bb84_key
from quantum_key_sim import simulate_bb84

def safe_generate_key():
    for _ in range(3):
        key = simulate_bb84(bits=128)
        if key:
            return key
    raise Exception("❌ Quantum key rejected: eavesdropper detected")

def encrypt_url(url: str, key: bytes) -> str:
    iv = b'QUANTUMBLOCKMODE'  # 16 bytes static IV for demo only
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(url.encode(), AES.block_size))
    return base64.urlsafe_b64encode(ciphertext).decode()

def decrypt_url(encrypted_url: str, key: bytes) -> str:
    iv = b'QUANTUMBLOCKMODE'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(base64.urlsafe_b64decode(encrypted_url))
    return unpad(decrypted, AES.block_size).decode()

if __name__ == "__main__":
    print("🔐 Generating quantum AES key...")
    for _ in tqdm(range(50), desc="Simulating BB84"):
        time.sleep(0.02)

    try:
        key = safe_generate_key()
        key_hex = key.hex()

        test_url = "http://free-lottery123.tk/login"
        encrypted = encrypt_url(test_url, key)
        decrypted = decrypt_url(encrypted, key)

        print("\n🧠 AES Key (hex):", key_hex)
        print("\n✅ Encrypted URL:", encrypted)
        print("🔓 Decrypted URL:", decrypted)
    except Exception as e:
        print(f"\n[!] Key generation failed: {e}")
