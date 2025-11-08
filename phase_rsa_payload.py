
import time
import pandas as pd
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

def simulate_rsa_aes_payload(iterations=10):
    results = []
    for i in range(iterations):
        # RSA key generation
        t0 = time.time()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        t1 = time.time()

        rsa_keygen_time = t1 - t0

        # AES key + IV
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"MeterReading: 132.5kWh; Voltage: 230V"

        # AES encryption
        t2 = time.time()
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        t3 = time.time()

        aes_encrypt_time = t3 - t2

        # RSA encryption of AES key
        t4 = time.time()
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        t5 = time.time()

        rsa_encrypt_time = t5 - t4

        # RSA decryption of AES key
        t6 = time.time()
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        t7 = time.time()

        rsa_decrypt_time = t7 - t6

        # AES decryption
        t8 = time.time()
        decryptor = Cipher(algorithms.AES(decrypted_key), modes.GCM(iv, tag)).decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        t9 = time.time()

        aes_decrypt_time = t9 - t8

        results.append({
            "rsa_keygen_time": rsa_keygen_time,
            "rsa_encrypt_time": rsa_encrypt_time,
            "rsa_decrypt_time": rsa_decrypt_time,
            "aes_encrypt_time": aes_encrypt_time,
            "aes_decrypt_time": aes_decrypt_time,
            "ciphertext_size": len(ciphertext),
            "encrypted_key_size": len(encrypted_key),
        })

    df = pd.DataFrame(results)
    df.to_csv("phase_rsa_payload_results.csv", index=False)
    print("✅ RSA + AES payload simulation complete. Results saved to phase_rsa_payload_results.csv")

simulate_rsa_aes_payload()
