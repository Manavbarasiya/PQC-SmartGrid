import pandas as pd

# Load simulation results
ecc_df = pd.read_csv("phase2_tls_results.csv")
pqc_df = pd.read_csv("phase3_pqc_results.csv")

# Extract mean values for comparison
comparison_data = {
    "Metric": [
        "Simulated Handshake Time (ms)",
        "Client Key Exchange CPU Time (ms)",
        "Server Key Exchange CPU Time (ms)",
        "Server Signature Generation Time (ms)",
        "Client Signature Verification Time (ms)",
        "Public Key Size (bytes)",
        "Ciphertext / Shared Secret Size (bytes)",
        "Signature Size (bytes)"
    ],
    "ECC (Phase 2)": [
        ecc_df['sim_handshake_time'].mean() * 1000,
        ecc_df['cpu_client_shared'].mean() * 1000,
        ecc_df['cpu_server_shared'].mean() * 1000,
        ecc_df['cpu_server_sign'].mean() * 1000,
        ecc_df['cpu_client_verify'].mean() * 1000,
        ecc_df['client_pub_size'].mean(),
        ecc_df['server_pub_size'].mean(),
        ecc_df['signature_size'].mean()
    ],
    "PQC (Phase 3)": [
        pqc_df['sim_handshake_time'].mean() * 1000,
        pqc_df['cpu_client_kem_encap'].mean() * 1000,
        pqc_df['cpu_server_kem_decap'].mean() * 1000,
        pqc_df['cpu_server_sig'].mean() * 1000,
        pqc_df['cpu_client_sig_verify'].mean() * 1000,
        pqc_df['pk_size_bytes'].mean(),
        pqc_df['ct_size_bytes'].mean(),
        pqc_df['sig_size_bytes'].mean()
    ]
}

# Create DataFrame and export to CSV
compare_df = pd.DataFrame(comparison_data)
compare_df.to_csv("ecc_vs_pqc_comparison.csv", index=False)
print("✅ Comparison saved to ecc_vs_pqc_comparison.csv")
