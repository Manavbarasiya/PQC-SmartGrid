import base64
import json
import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def simulate_pqc_shared_secret():
    print("⚠️ oqs-python not installed. Using emulated PQC shared secret.")
    return sha256(b"mock_pqc_shared_secret").digest()

def encrypt_payload(payload, shared_secret):
    cipher = AES.new(shared_secret[:16], AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def decrypt_payload(encrypted_data, shared_secret):
    raw = base64.b64decode(encrypted_data)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(shared_secret[:16], AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

if __name__ == "__main__":
    print("🔐 Post-Quantum Smart Meter Payload Encryption/Decryption Demo")

    payload = {
        "meter_id": input("Enter Meter ID: "),
        "timestamp": int(input("Enter Timestamp (e.g., 1700000000): ")),
        "kWh": float(input("Enter Energy Consumption (kWh): ")),
        "voltage": float(input("Enter Voltage (V): ")),
        "current": float(input("Enter Current (A): "))
    }

    shared_secret = simulate_pqc_shared_secret()

    encrypted = encrypt_payload(json.dumps(payload), shared_secret)
    print(f"🔐 Encrypted Ciphertext (base64):\n{encrypted}")

    decrypted = decrypt_payload(encrypted, shared_secret)
    print(f"🔓 Decrypted Payload:\n{json.loads(decrypted)}")
