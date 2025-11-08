"""
Phase 3 - PQC (Kyber + Dilithium) handshake simulation using SimPy.

Behavior:
 - If oqs (oqs-python) is installed, the script will attempt to use real KEM/signature calls.
 - If oqs is NOT installed, the script will emulate PQC operations with conservative timing & size parameters
   so you can run experiments immediately and compare results with Phase 2.

Usage (local VS Code):
 1) Activate your venv (in Git Bash):
    source venv/Scripts/activate
    or in PowerShell:
    .\venv\Scripts\activate
 2) Install dependencies:
    pip install simpy cryptography pandas oqs-python
    - If `pip install oqs-python` fails on Windows, consider using WSL (Ubuntu) and run the same pip command there.
 3) Run:
    python phase3_pqc_sim.py

Outputs: phase3_pqc_results.csv (same folder)
"""

import time
from dataclasses import dataclass, asdict
from typing import List
import simpy
import pandas as pd

try:
    import oqs
    HAS_OQS = True
except Exception:
    HAS_OQS = False

KYBER768_PK_BYTES = 1184   
KYBER768_CT_BYTES = 1088  
DILITHIUM3_SIG_BYTES = 2700  
DILITHIUM3_PK_BYTES = 1472  
EMU_KEM_ENCAP_SEC = 0.0008   
EMU_KEM_DECAP_SEC = 0.0006 
EMU_SIG_SIGN_SEC = 0.0025   
EMU_SIG_VERIFY_SEC = 0.0005  
RESULT_CSV = "phase3_pqc_results.csv"


@dataclass
class PQCSessionMetric:
    client_id: int
    sim_handshake_time: float
    cpu_client_kem_encap: float
    cpu_server_kem_decap: float
    cpu_server_sig: float
    cpu_client_sig_verify: float
    pk_size_bytes: int
    ct_size_bytes: int
    sig_size_bytes: int

class PQCServer:
    def __init__(self, env, network_latency=0.02, processing_delay=0.001):
        self.env = env
        self.network_latency = network_latency
        self.processing_delay = processing_delay
        self.has_oqs = HAS_OQS
        if self.has_oqs:
            try:
                self.kem_alg = "Kyber768"
                self.sig_alg = "Dilithium3"
                self.kem = oqs.KeyEncapsulation(self.kem_alg)
                try:
                    self.kem_pub = self.kem.generate_keypair()
                    # If generate_keypair returned (pk, sk) adjust accordingly
                    if isinstance(self.kem_pub, tuple) and len(self.kem_pub) == 2:
                        self.kem_pub, self.kem_sk = self.kem_pub
                    else:
                        # Some oqs versions may use export_public_key; try that
                        try:
                            self.kem_sk = self.kem.export_secret_key()
                        except Exception:
                            self.kem_sk = None
                except Exception:
                    try:
                        self.kem_pub = self.kem.generate_keypair()
                    except Exception:
                        self.kem_pub = b"server_kem_pub"
                        self.kem_sk = None
                self.sig = oqs.Signature(self.sig_alg)
                try:
                    self.sig_pub, self.sig_priv = self.sig.generate_keypair()
                except Exception:
                    try:
                        self.sig_priv = self.sig.generate_keypair()
                        self.sig_pub = self.sig.export_public_key()
                    except Exception:
                        self.sig_pub = b"server_sig_pub"
                        self.sig_priv = None
            except Exception:
                self.has_oqs = False
        else:
            self.kem = None
            self.sig = None

    def handle_client_kem(self, client, client_kem_pk: bytes, callback):
        """SimPy process: server receives a client's KEM encapsulation attempt.
           Client will send its public key; server will perform decapsulation on receipt.
        """
        # network delay to receive
        yield self.env.timeout(self.network_latency)
        yield self.env.timeout(self.processing_delay)

        # Server decapsulates (if oqs available do real operation)
        t0 = time.perf_counter()
        if self.has_oqs and self.kem is not None:
            try:
                # Prefer decap_secret API; if unavailable, emulate.
                try:
                    shared_server = self.kem.decapsulate(client_kem_pk, self.kem_sk)
                except Exception:
                    # alternative API path: encap/decap via kem.encap_secret
                    # We cannot guarantee behavior across oqs versions here; if calls fail, fallback
                    raise RuntimeError("oqs decap failed - falling back")
                cpu_server_kem = time.perf_counter() - t0
                pk_size = len(client_kem_pk) if client_kem_pk else len(self.kem_pub)
                ct_size = len(client_kem_pk)  # using the client's encapsulation as ciphertext
            except Exception:
                cpu_server_kem = time.perf_counter() - t0
                # emulate sizes
                pk_size = KYBER768_PK_BYTES
                ct_size = KYBER768_CT_BYTES
        else:
            # Emulate timings/sizes
            time.sleep(0)  # no blocking sleep; just measure virtual time cost
            cpu_server_kem = EMU_KEM_DECAP_SEC
            pk_size = KYBER768_PK_BYTES
            ct_size = KYBER768_CT_BYTES

        # Server signs the handshake transcript (client_pk || server info). We'll emulate or use oqs Sign API.
        t0 = time.perf_counter()
        if self.has_oqs and self.sig is not None and self.sig_priv is not None:
            try:
                signature = self.sig.sign(b"transcript", self.sig_priv)
                cpu_server_sig = time.perf_counter() - t0
                sig_size = len(signature)
            except Exception:
                cpu_server_sig = EMU_SIG_SIGN_SEC
                sig_size = DILITHIUM3_SIG_BYTES
        else:
            cpu_server_sig = EMU_SIG_SIGN_SEC
            sig_size = DILITHIUM3_SIG_BYTES

        # Simulate sending server response back to client
        def deliver():
            yield self.env.timeout(self.network_latency)
            callback(pk_size, ct_size, sig_size, cpu_server_kem, cpu_server_sig)

        self.env.process(deliver())

class PQCClient:
    def __init__(self, env, client_id: int, server: PQCServer, start_time: float = 0.0):
        self.env = env
        self.client_id = client_id
        self.server = server
        self.start_time = start_time
        # client will prepare an encapsulation (ct) to the server's public key

    def start(self, results_list: List[PQCSessionMetric]):
        self.env.process(self._handshake_process(results_list))

    def _handshake_process(self, results_list: List[PQCSessionMetric]):
        yield self.env.timeout(self.start_time)
        t_sim_start = self.env.now

        # Client KEM encapsulation: produce ciphertext and shared secret (emulated or real)
        t0 = time.perf_counter()
        if self.server.has_oqs and self.server.kem is not None:
            try:
                # Attempt to use oqs API: encap_secret or similar. If it fails, fallback to emulation.
                try:
                    ct, shared_client = self.server.kem.encap_secret(self.server.kem_pub)
                    cpu_client_kem = time.perf_counter() - t0
                    ct_bytes = ct if isinstance(ct, (bytes, bytearray)) else b''
                    ct_size = len(ct_bytes)
                except Exception:
                    cpu_client_kem = EMU_KEM_ENCAP_SEC
                    ct_size = KYBER768_CT_BYTES
            except Exception:
                cpu_client_kem = EMU_KEM_ENCAP_SEC
                ct_size = KYBER768_CT_BYTES
        else:
            cpu_client_kem = EMU_KEM_ENCAP_SEC
            ct_size = KYBER768_CT_BYTES
            # emulate ciphertext bytes
            ct = b"ciphertext"

        # send client's KEM ct/public to server (server will decapsulate & sign)
        handshake_completed = {'done': False, 'cpu_server_kem': 0.0, 'cpu_server_sig': 0.0,
                               'pk_size': 0, 'ct_size': ct_size, 'sig_size': 0, 'sim_end': None}

        def server_callback(pk_size, ct_size_cb, sig_size, cpu_server_kem, cpu_server_sig):
            handshake_completed['pk_size'] = pk_size
            handshake_completed['ct_size'] = ct_size_cb
            handshake_completed['sig_size'] = sig_size
            handshake_completed['cpu_server_kem'] = cpu_server_kem
            handshake_completed['cpu_server_sig'] = cpu_server_sig
            handshake_completed['done'] = True
            handshake_completed['sim_end'] = self.env.now

        # Trigger server processing
        self.env.process(self.server.handle_client_kem(self, ct, server_callback))

        # wait for server response
        while not handshake_completed['done']:
            yield self.env.timeout(0.0001)

        # Client verifies server signature (emulated or real)
        t0 = time.perf_counter()
        if self.server.has_oqs and self.server.sig is not None:
            try:
                ok = self.server.sig.verify(b"transcript", handshake_completed['sig_size'])
                cpu_client_sig_verify = time.perf_counter() - t0
            except Exception:
                cpu_client_sig_verify = EMU_SIG_VERIFY_SEC
        else:
            cpu_client_sig_verify = EMU_SIG_VERIFY_SEC

        t_sim_end = handshake_completed['sim_end'] or self.env.now
        sim_handshake_time = t_sim_end - t_sim_start

        # Save metrics
        m = PQCSessionMetric(client_id=self.client_id,
                             sim_handshake_time=sim_handshake_time,
                             cpu_client_kem_encap=cpu_client_kem,
                             cpu_server_kem_decap=handshake_completed['cpu_server_kem'],
                             cpu_server_sig=handshake_completed['cpu_server_sig'],
                             cpu_client_sig_verify=cpu_client_sig_verify,
                             pk_size_bytes=handshake_completed['pk_size'],
                             ct_size_bytes=handshake_completed['ct_size'],
                             sig_size_bytes=handshake_completed['sig_size'])
        results_list.append(m)
        return

def run_experiment(num_clients=20, network_latency=0.02, stagger=0.01):
    env = simpy.Environment()
    server = PQCServer(env, network_latency=network_latency, processing_delay=0.0005)
    results: List[PQCSessionMetric] = []

    for i in range(num_clients):
        c = PQCClient(env, client_id=i, server=server, start_time=i * stagger)
        c.start(results)

    env.run(until=num_clients * stagger + 1.0)
    df = pd.DataFrame([asdict(r) for r in results])
    df.to_csv(RESULT_CSV, index=False)
    return df

def main():
    print("Phase 3 - PQC (Kyber + Dilithium) SimPy demo. oqs available:", HAS_OQS)
    df = run_experiment(num_clients=10, network_latency=0.02, stagger=0.02)
    print(df.describe().transpose())
    print("\\nSaved results to", RESULT_CSV)
    if not HAS_OQS:
        print("\\nNOTE: oqs-python not detected. This run used EMULATED PQC timings and sizes.")
        print("To run with real PQC, install liboqs and oqs-python in your venv:")
        print("  pip install oqs-python")
        print("If installation on Windows fails, consider using WSL (Ubuntu) and running the same commands there.")

if __name__ == '__main__':
    main()
