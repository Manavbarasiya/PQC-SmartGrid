import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import oqs
    pqc_available = True
except ImportError:
    pqc_available = False
    print("⚠️ oqs-python not installed. Using emulated PQC shared secret.")

# Step 1: Generate PQC key pair and perform KEM
if pqc_available:
    with oqs.KeyEncapsulation("Kyber1024") as server:
        public_key = server.generate_keypair()
        with oqs.KeyEncapsulation("Kyber1024") as client:
            ciphertext, shared_secret_client = client.encap_secret(public_key)
        shared_secret_server = server.decap_secret(ciphertext)
else:
    # Emulate with shared secret for demo
    ciphertext = b"fakecipher"
    shared_secret_client = shared_secret_server = hashlib.sha256(b"kyber").digest()

assert shared_secret_client == shared_secret_server

# Step 2: Derive AES key from shared secret
key = hashlib.sha256(shared_secret_client).digest()

data = {
    "meter_id": 7,
    "timestamp": 1700000000,
    "kWh": 145.82,
    "voltage": 231.1,
    "current": 4.8
}
plaintext = json.dumps(data).encode()

# Step 4: Encrypt with AES-GCM
nonce = os.urandom(12)
aesgcm = AESGCM(key)
ciphertext_enc = aesgcm.encrypt(nonce, plaintext, None)

# Step 5: Decrypt
decrypted = aesgcm.decrypt(nonce, ciphertext_enc, None)
decrypted_data = json.loads(decrypted.decode())

# Output
print("🔐 Encrypted Ciphertext (base64):", base64.b64encode(ciphertext_enc).decode())
print("🔓 Decrypted Payload:", decrypted_data)