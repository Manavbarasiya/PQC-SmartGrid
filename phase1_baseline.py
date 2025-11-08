import time
import os
import sys
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
try:
    import simpy
    HAS_SIMPY = True
except Exception:
    HAS_SIMPY = False
try:
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives import serialization as ser
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

try:
    import pandas as pd
    HAS_PANDAS = True
except Exception:
    HAS_PANDAS = False

RESULT_CSV = "C:/Users/Hp/OneDrive/Documents/pq-smartgrid/phase1_baseline_results.csv"

MOCK_HANDSHAKE_TIME = 0.006
MOCK_SIGN_TIME = 0.002     
MOCK_VERIFY_TIME = 0.0015    
MOCK_PUBKEY_SIZE = 65       
MOCK_SIGNATURE_SIZE = 64    
@dataclass
class Metric:
    meter_id: int
    handshake_time_s: float
    sign_time_s: float
    verify_time_s: float
    pubkey_size_bytes: int
    signature_size_bytes: int

class UtilityServer:
    def __init__(self):
        self.has_crypto = HAS_CRYPTO
        if self.has_crypto:
            self.x25519_priv = x25519.X25519PrivateKey.generate()
            self.x25519_pub = self.x25519_priv.public_key()
        else:
            self.x25519_priv = None

    def decapsulate(self, peer_public_bytes: Optional[bytes]) -> (bytes, int):
        """
        Simulate the server side of a key exchange:
        If crypto available, expect peer_public_bytes as X25519 public key bytes, compute shared key.
        Otherwise return a mock shared secret and public key size.
        Returns (shared_secret_bytes, pubkey_size_bytes)
        """
        if self.has_crypto and peer_public_bytes is not None:
            peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
            start = time.perf_counter()
            shared = self.x25519_priv.exchange(peer_pub)
            end = time.perf_counter()
            hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'ami-handshake')
            derived = hkdf.derive(shared)
            return derived, len(peer_public_bytes)
        else:
            time.sleep(0)  
            fake_secret = b"\x00" * 16
            return fake_secret, MOCK_PUBKEY_SIZE

class SmartMeter:
    def __init__(self, meter_id: int, server: UtilityServer):
        self.meter_id = meter_id
        self.server = server
        self.has_crypto = HAS_CRYPTO
        if self.has_crypto:
            self.x25519_priv = x25519.X25519PrivateKey.generate()
            self.x25519_pub = self.x25519_priv.public_key()
            self.ed_priv = ed25519.Ed25519PrivateKey.generate()
            self.ed_pub = self.ed_priv.public_key()
        else:
            self.x25519_priv = None
            self.x25519_pub = None
            self.ed_priv = None
            self.ed_pub = None

    def handshake(self) -> (float, int):
        """Perform a client->server handshake. Returns (elapsed_time_s, pubkey_size_bytes)."""
        if self.has_crypto:
            peer_bytes = self.x25519_pub.public_bytes(encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw)
            start = time.perf_counter()
            derived, pk_size = self.server.decapsulate(peer_bytes)
            shared = self.x25519_priv.exchange(self.server.x25519_pub)
            hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'ami-handshake')
            derived_client = hkdf.derive(shared)
            end = time.perf_counter()
            return end - start, pk_size
        else:
            start = time.perf_counter()
            time.sleep(0)  
            end = time.perf_counter()
            return MOCK_HANDSHAKE_TIME, MOCK_PUBKEY_SIZE

    def sign_reading(self, data: bytes) -> (bytes, float):
        """Sign data and return signature and elapsed time"""
        if self.has_crypto:
            start = time.perf_counter()
            sig = self.ed_priv.sign(data)
            end = time.perf_counter()
            return sig, end - start
        else:
            start = time.perf_counter()
            time.sleep(0)
            end = time.perf_counter()
            return b"\x00" * MOCK_SIGNATURE_SIZE, MOCK_SIGN_TIME

    def verify_signature(self, data: bytes, signature: bytes) -> float:
        if self.has_crypto:
            start = time.perf_counter()
            try:
                self.ed_pub.verify(signature, data)
                valid = True
            except Exception:
                valid = False
            end = time.perf_counter()
            return (end - start)
        else:
            start = time.perf_counter()
            time.sleep(0)
            end = time.perf_counter()
            return MOCK_VERIFY_TIME

def run_simulation(num_meters: int = 10, use_simpy: bool = HAS_SIMPY) -> List[Metric]:
    server = UtilityServer()
    meters = [SmartMeter(i, server) for i in range(num_meters)]
    results: List[Metric] = []

    if use_simpy:
        env = simpy.Environment()

        def meter_process(env, meter: SmartMeter):
            yield env.timeout(meter.meter_id * 0.01)
            hs_time, pk_size = meter.handshake()
            yield env.timeout(0.005)
            data = f"meter:{meter.meter_id}:reading:123.45".encode()
            sig, sign_time = meter.sign_reading(data)
            verify_time = meter.verify_signature(data, sig)
            sig_size = len(sig)
            results.append(Metric(meter_id=meter.meter_id,
                                  handshake_time_s=hs_time,
                                  sign_time_s=sign_time,
                                  verify_time_s=verify_time,
                                  pubkey_size_bytes=pk_size,
                                  signature_size_bytes=sig_size))
        for m in meters:
            env.process(meter_process(env, m))
        env.run(until=10.0)
    else:
        for meter in meters:
            hs_time, pk_size = meter.handshake()
            data = f"meter:{meter.meter_id}:reading:123.45".encode()
            sig, sign_time = meter.sign_reading(data)
            verify_time = meter.verify_signature(data, sig)
            sig_size = len(sig)
            results.append(Metric(meter_id=meter.meter_id,
                                  handshake_time_s=hs_time,
                                  sign_time_s=sign_time,
                                  verify_time_s=verify_time,
                                  pubkey_size_bytes=pk_size,
                                  signature_size_bytes=sig_size))
    return results

def save_results(results: List[Metric], csv_path: str = RESULT_CSV):
    rows = [asdict(r) for r in results]
    try:
        import json
        with open(csv_path, "w") as f:
            if rows:
                headers = list(rows[0].keys())
                f.write(",".join(headers) + "\\n")
                for r in rows:
                    f.write(",".join(str(r[h]) for h in headers) + "\\n")
        print(f"Results written to {csv_path}")
    except Exception as e:
        print("Failed to write CSV:", e)

def print_summary(results: List[Metric]):
    if not results:
        print("No results to display")
        return
    avg_handshake = sum(r.handshake_time_s for r in results) / len(results)
    avg_sign = sum(r.sign_time_s for r in results) / len(results)
    avg_verify = sum(r.verify_time_s for r in results) / len(results)
    avg_pk = sum(r.pubkey_size_bytes for r in results) / len(results)
    avg_sig = sum(r.signature_size_bytes for r in results) / len(results)
    print("=== Baseline Simulation Summary ===")
    print(f"Meters simulated: {len(results)}")
    print(f"Avg handshake time (s): {avg_handshake:.6f}")
    print(f"Avg sign time (s): {avg_sign:.6f}")
    print(f"Avg verify time (s): {avg_verify:.6f}")
    print(f"Avg pubkey size (bytes): {avg_pk:.1f}")
    print(f"Avg signature size (bytes): {avg_sig:.1f}")
    print("Detailed per-meter metrics available in CSV.")
def main():
    num_meters = 10
    print(f"SimPy available: {HAS_SIMPY}. Crypto available: {HAS_CRYPTO}. Pandas available: {HAS_PANDAS}.")
    print("Running baseline simulation (ECC-like behavior). This may be using mock timings if crypto libs are unavailable.")
    results = run_simulation(num_meters=num_meters, use_simpy=HAS_SIMPY)
    save_results(results)
    print_summary(results)
    if HAS_PANDAS:
        df = pd.DataFrame([asdict(r) for r in results])
        print("\\nFirst 5 rows:")
        print(df.head().to_string(index=False))

if __name__ == '__main__':
    main()
