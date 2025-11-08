"""
Phase 2 - TLS-like handshake simulation (SimPy) with ECC primitives
- Handshake design (simplified TLS 1.3 style):
  1. Client sends ClientHello containing client_ephemeral_pub
  2. Server receives, generates server_ephemeral, computes shared secret server-side,
     signs the handshake (client_pub || server_pub) with Ed25519 static key,
     and sends ServerHello (server_ephemeral_pub + signature) back to client.
  3. Client receives ServerHello, verifies signature, computes shared secret client-side.
- Metrics recorded per session:
  - sim_handshake_time: env.now between client send and client completion
  - cpu_sign_time: server Ed25519 signing time (seconds)
  - cpu_verify_time: client Ed25519 verification time (seconds)
  - cpu_shared_client: client shared-secret compute time (seconds)
  - cpu_shared_server: server shared-secret compute time (seconds)
  - sizes: lengths of public keys and signature in bytes
- Save results to CSV and print summary.
"""

import simpy
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import pandas as pd

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

RESULT_CSV = "phase2_tls_results.csv"

@dataclass
class SessionMetric:
    client_id: int
    sim_handshake_time: float
    cpu_server_sign: float
    cpu_server_shared: float
    cpu_client_verify: float
    cpu_client_shared: float
    client_pub_size: int
    server_pub_size: int
    signature_size: int

class UtilityServer:
    def __init__(self, env: simpy.Environment, network_latency: float = 0.02, processing_delay: float = 0.001):
        self.env = env
        self.network_latency = network_latency  # seconds one-way
        self.processing_delay = processing_delay
        # static long-term signing key (Ed25519)
        self.sign_priv = ed25519.Ed25519PrivateKey.generate()
        self.sign_pub = self.sign_priv.public_key()

    def receive_client_hello(self, client, client_pub_bytes: bytes, callback):
        """SimPy process: handle incoming ClientHello, perform server-side crypto, and schedule response to client."""
        # simulate network transit time
        yield self.env.timeout(self.network_latency)
        # processing delay
        yield self.env.timeout(self.processing_delay)
        # compute shared secret on server side using ephemeral X25519
        server_ephemeral_priv = x25519.X25519PrivateKey.generate()
        server_ephemeral_pub = server_ephemeral_priv.public_key()
        server_pub_bytes = server_ephemeral_pub.public_bytes(encoding=serialization.Encoding.Raw,
                                                            format=serialization.PublicFormat.Raw)
        # compute shared secret (measure CPU time)
        t0 = time.perf_counter()
        try:
            peer_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
            shared = server_ephemeral_priv.exchange(peer_pub)
        except Exception as e:
            shared = b""
        t1 = time.perf_counter()
        cpu_server_shared = t1 - t0

        to_sign = client_pub_bytes + server_pub_bytes
        t0 = time.perf_counter()
        signature = self.sign_priv.sign(to_sign)
        t1 = time.perf_counter()
        cpu_server_sign = t1 - t0
        def deliver():
            yield self.env.timeout(self.network_latency)
            # schedule client's receive
            callback(server_pub_bytes, signature, cpu_server_sign, cpu_server_shared)

        self.env.process(deliver())

class SmartMeterClient:
    def __init__(self, env: simpy.Environment, client_id: int, server: UtilityServer, start_time: float = 0.0):
        self.env = env
        self.client_id = client_id
        self.server = server
        self.start_time = start_time
        self.ephemeral_priv = None
        self.ephemeral_pub_bytes = None

    def start(self, results_list: List[SessionMetric]):
        # start the SimPy process
        self.env.process(self._handshake_process(results_list))

    def _handshake_process(self, results_list: List[SessionMetric]):
        yield self.env.timeout(self.start_time)
        t_sim_start = self.env.now
        self.ephemeral_priv = x25519.X25519PrivateKey.generate()
        self.ephemeral_pub = self.ephemeral_priv.public_key()
        client_pub_bytes = self.ephemeral_pub.public_bytes(encoding=serialization.Encoding.Raw,
                                                          format=serialization.PublicFormat.Raw)
        self.ephemeral_pub_bytes = client_pub_bytes
        client_pub_size = len(client_pub_bytes)
        handshake_completed = {'done': False, 'sim_end': None, 'cpu_server_sign': 0.0, 'cpu_server_shared': 0.0,
                               'server_pub_bytes': b'', 'signature': b''}

        def server_response_callback(server_pub_bytes, signature, cpu_server_sign, cpu_server_shared):

            handshake_completed['server_pub_bytes'] = server_pub_bytes
            handshake_completed['signature'] = signature
            handshake_completed['cpu_server_sign'] = cpu_server_sign
            handshake_completed['cpu_server_shared'] = cpu_server_shared
            handshake_completed['done'] = True
            # record sim time when reply received
            handshake_completed['sim_end'] = self.env.now

        # send ClientHello to server (server handles network latency inside its process)
        self.env.process(self.server.receive_client_hello(self, client_pub_bytes, server_response_callback))
        # Now wait until the callback sets 'done' to True (i.e., response delivered)
        while not handshake_completed['done']:
            # yield a small timeout to yield control to env
            yield self.env.timeout(0.0001)

        # At this point, server_pub_bytes and signature are available
        server_pub_bytes = handshake_completed['server_pub_bytes']
        signature = handshake_completed['signature']
        cpu_server_sign = handshake_completed['cpu_server_sign']
        cpu_server_shared = handshake_completed['cpu_server_shared']

        server_pub_size = len(server_pub_bytes)
        signature_size = len(signature)

        # Client verifies signature (measure CPU time)
        t0 = time.perf_counter()
        try:
            server_pubkey = self.server.sign_pub
            server_pubkey.verify(signature, client_pub_bytes + server_pub_bytes)
            verify_ok = True
        except Exception as e:
            verify_ok = False
        t1 = time.perf_counter()
        cpu_client_verify = t1 - t0

        # Client computes shared secret (measure CPU time)
        t0 = time.perf_counter()
        try:
            peer_pub = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
            shared_client = self.ephemeral_priv.exchange(peer_pub)
        except Exception:
            shared_client = b''
        t1 = time.perf_counter()
        cpu_client_shared = t1 - t0

        t_sim_end = handshake_completed['sim_end'] or self.env.now
        sim_handshake_time = t_sim_end - t_sim_start

        # Derive a symmetric key via HKDF (not timed)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'tls-like')
        try:
            symmetric = hkdf.derive(shared_client)
        except Exception:
            symmetric = b''

        # Save metrics
        m = SessionMetric(client_id=self.client_id,
                          sim_handshake_time=sim_handshake_time,
                          cpu_server_sign=cpu_server_sign,
                          cpu_server_shared=cpu_server_shared,
                          cpu_client_verify=cpu_client_verify,
                          cpu_client_shared=cpu_client_shared,
                          client_pub_size=client_pub_size,
                          server_pub_size=server_pub_size,
                          signature_size=signature_size)
        results_list.append(m)
        # end of process
        return

def run_experiment(num_clients=20, network_latency=0.02, stagger=0.01):
    env = simpy.Environment()
    server = UtilityServer(env, network_latency=network_latency, processing_delay=0.0005)
    results: List[SessionMetric] = []

    # create clients and schedule them
    for i in range(num_clients):
        c = SmartMeterClient(env, client_id=i, server=server, start_time=i * stagger)
        c.start(results)

    # run the simulation for sufficient time
    env.run(until=num_clients * stagger + 1.0)
    # Convert results to DataFrame and save
    df = pd.DataFrame([asdict(r) for r in results])
    df.to_csv(RESULT_CSV, index=False)
    return df

def main():
    print("Phase 2 - TLS-like SimPy ECC handshake demo")
    df = run_experiment(num_clients=10, network_latency=0.02, stagger=0.02)
    print(df.describe().transpose())
    print("\\nSaved results to", RESULT_CSV)

if __name__ == '__main__':
    main()
