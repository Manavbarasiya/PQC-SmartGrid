
import pandas as pd
import matplotlib.pyplot as plt

# Load ECC and PQC simulation results
ecc_df = pd.read_csv("phase2_tls_results.csv")
pqc_df = pd.read_csv("phase3_pqc_results.csv")

# Aggregate means for comparison
ecc_summary = {
    'Handshake Time (ms)': ecc_df['sim_handshake_time'].mean() * 1000,
    'Key Exchange (Client)': ecc_df['cpu_client_shared'].mean() * 1000,
    'Key Exchange (Server)': ecc_df['cpu_server_shared'].mean() * 1000,
    'Signature Generation': ecc_df['cpu_server_sign'].mean() * 1000,
    'Signature Verification': ecc_df['cpu_client_verify'].mean() * 1000,
    'Public Key Size (bytes)': ecc_df['client_pub_size'].mean(),
    'Signature Size (bytes)': ecc_df['signature_size'].mean()
}

pqc_summary = {
    'Handshake Time (ms)': pqc_df['sim_handshake_time'].mean() * 1000,
    'Key Exchange (Client)': pqc_df['cpu_client_kem_encap'].mean() * 1000,
    'Key Exchange (Server)': pqc_df['cpu_server_kem_decap'].mean() * 1000,
    'Signature Generation': pqc_df['cpu_server_sig'].mean() * 1000,
    'Signature Verification': pqc_df['cpu_client_sig_verify'].mean() * 1000,
    'Public Key Size (bytes)': pqc_df['pk_size_bytes'].mean(),
    'Signature Size (bytes)': pqc_df['sig_size_bytes'].mean()
}

# Prepare comparison DataFrame
compare_df = pd.DataFrame([ecc_summary, pqc_summary], index=['ECC (Phase 2)', 'PQC (Phase 3)'])

# Plot bar chart: handshake and CPU times
cpu_metrics = ['Handshake Time (ms)', 'Key Exchange (Client)', 'Key Exchange (Server)', 
               'Signature Generation', 'Signature Verification']
compare_df[cpu_metrics].plot(kind='bar', figsize=(10, 6))
plt.title("ECC vs PQC: Handshake and CPU Times")
plt.ylabel("Milliseconds (ms)")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("ecc_vs_pqc_cpu_times.png")
plt.close()

# Plot line chart: key and signature sizes
size_metrics = ['Public Key Size (bytes)', 'Signature Size (bytes)']
compare_df[size_metrics].T.plot(kind='line', marker='o', figsize=(8, 5))
plt.title("ECC vs PQC: Key and Signature Sizes")
plt.ylabel("Bytes")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("ecc_vs_pqc_sizes.png")
plt.close()

print("✅ Charts generated:\n- ecc_vs_pqc_cpu_times.png\n- ecc_vs_pqc_sizes.png")
