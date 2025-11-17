# Creating publication-ready plots from the provided CSV content.
# This code reads the two CSVs (metrics summary and crypto ops), creates several
# separate matplotlib figures (one per plot as requested), saves PNG and PDF outputs,
# displays the dataframes in the notebook UI, and writes a zip containing all figures.
# Files are saved under /mnt/data and a downloadable zip is created at the end.
# NOTE: matplotlib default color cycle is used (no explicit colors set).

from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import io, zipfile

# make output dir
out_dir = Path('/mnt/data/uav_plots')
out_dir.mkdir(parents=True, exist_ok=True)

# --- raw CSV strings provided by user ---
metrics_csv = """Node,PktsSent,PktsRecv,BytesSent,BytesRecv,AvgDelay_s,Crypto_ms,InitE_J,FinalE_J
9,4,2,388,336,0.503720,0.437000,500.000000,499.074153
8,0,0,0,0,0.000000,0.000000,500.000000,499.074091
7,0,0,0,0,0.000000,0.000000,500.000000,499.073921
6,0,0,0,0,0.000000,0.000000,500.000000,499.074446
5,0,0,0,0,0.000000,0.000000,500.000000,499.075006
4,0,0,0,0,0.000000,0.000000,500.000000,499.074596
3,0,0,0,0,0.000000,0.000000,500.000000,499.074131
2,0,0,0,0,0.000000,0.000000,500.000000,499.075102
1,1,502,168,27586,0.000077,1.413000,500.000000,499.079408
0,501,2,27560,194,0.002727,3.752000,500.000000,499.079327
ALL,506,506,28116,28116,0.002079,5.602000,5000.000000,4990.754180
"""

crypto_csv = """Node,OpName,Count,Total_us,Total_ms
9,"AEAD_ENCRYPT_GROUP_A",1,4,0.004
9,"AEAD_ENCRYPT_GROUP_B",1,8,0.008
9,"AUTH_VERIFY",2,425,0.425
1,"AEAD_DECRYPT_DATA",500,1038,1.038
1,"AEAD_DECRYPT_GROUP",1,1,0.001
1,"AUTH_ACK_VERIFY",1,184,0.184
1,"AUTH_GEN",1,190,0.19
0,"AEAD_DECRYPT_GROUP",1,2,0.002
0,"AEAD_ENCRYPT_DATA",500,3374,3.374
0,"AUTH_ACK_VERIFY",1,194,0.194
0,"AUTH_GEN",1,182,0.182
"""

# read into DataFrames
metrics = pd.read_csv(io.StringIO(metrics_csv))
crypto = pd.read_csv(io.StringIO(crypto_csv))

# Normalize Node column: remove 'ALL' from node-level analyses
metrics_nodes = metrics[metrics['Node'] != 'ALL'].copy()
metrics_nodes['Node'] = metrics_nodes['Node'].astype(int)
metrics_nodes = metrics_nodes.sort_values('Node').reset_index(drop=True)

# calculate derived columns
metrics_nodes['EnergyConsumed_J'] = metrics_nodes['InitE_J'] - metrics_nodes['FinalE_J']
metrics_nodes['PktDiff'] = metrics_nodes['PktsSent'] - metrics_nodes['PktsRecv']

# crypto aggregation per-node (sum Total_ms)
crypto_per_node = crypto.groupby('Node', as_index=False).agg({
    'Count': 'sum',
    'Total_ms': 'sum'
}).rename(columns={'Total_ms': 'TotalCrypto_ms'})
crypto_per_node['Node'] = crypto_per_node['Node'].astype(int)
crypto_per_node = crypto_per_node.sort_values('Node').reset_index(drop=True)

# merge with metrics for joint plots
merged = pd.merge(metrics_nodes, crypto_per_node, on='Node', how='left').fillna(0)

# Display dataframes to user
import ace_tools as tools; tools.display_dataframe_to_user("Metrics per node", metrics_nodes)
tools.display_dataframe_to_user("Crypto ops per node", crypto_per_node)
tools.display_dataframe_to_user("Merged metrics + crypto", merged)

# --- PLOT 1: Energy per node (Init vs Final) ---
fig1, ax1 = plt.subplots(figsize=(6.5,4))
nodes = merged['Node'].astype(str)
x = np.arange(len(nodes))
width = 0.35
ax1.bar(x - width/2, merged['InitE_J'], width, label='InitE (J)')
ax1.bar(x + width/2, merged['FinalE_J'], width, label='FinalE (J)')
ax1.set_xticks(x); ax1.set_xticklabels(nodes)
ax1.set_xlabel('Node'); ax1.set_ylabel('Energy (J)')
ax1.set_title('Initial vs Final Energy per Node')
ax1.grid(axis='y', linestyle='--', linewidth=0.5)
ax1.legend()
fig1.tight_layout()
f1_png = out_dir / 'energy_per_node.png'
f1_pdf = out_dir / 'energy_per_node.pdf'
fig1.savefig(f1_png, dpi=300); fig1.savefig(f1_pdf)
plt.close(fig1)

# --- PLOT 2: Packets sent / received per node ---
fig2, ax2 = plt.subplots(figsize=(6.5,4))
ax2.bar(x - width/2, merged['PktsSent'], width, label='PktsSent')
ax2.bar(x + width/2, merged['PktsRecv'], width, label='PktsRecv')
ax2.set_xticks(x); ax2.set_xticklabels(nodes)
ax2.set_xlabel('Node'); ax2.set_ylabel('Packets')
ax2.set_title('Packets Sent vs Received per Node')
ax2.grid(axis='y', linestyle='--', linewidth=0.5)
ax2.legend()
fig2.tight_layout()
f2_png = out_dir / 'pkts_sent_recv_per_node.png'
f2_pdf = out_dir / 'pkts_sent_recv_per_node.pdf'
fig2.savefig(f2_png, dpi=300); fig2.savefig(f2_pdf)
plt.close(fig2)

# --- PLOT 3: Average delay per node (log-scale y for clarity) ---
fig3, ax3 = plt.subplots(figsize=(6.5,4))
ax3.plot(nodes, merged['AvgDelay_s'], marker='o', linewidth=1.2)
ax3.set_yscale('log')
ax3.set_xlabel('Node'); ax3.set_ylabel('Avg delay (s) [log scale]')
ax3.set_title('Average end-to-end delay per Node (log scale)')
ax3.grid(True, which='both', linestyle='--', linewidth=0.5)
fig3.tight_layout()
f3_png = out_dir / 'avg_delay_per_node_log.png'
f3_pdf = out_dir / 'avg_delay_per_node_log.pdf'
fig3.savefig(f3_png, dpi=300); fig3.savefig(f3_pdf)
plt.close(fig3)

# --- PLOT 4: Energy consumed and Crypto time (dual axis) ---
fig4, ax4 = plt.subplots(figsize=(6.5,4))
ax4.bar(x, merged['EnergyConsumed_J'], label='EnergyConsumed (J)')
ax4.set_xlabel('Node'); ax4.set_xticks(x); ax4.set_xticklabels(nodes)
ax4.set_ylabel('Energy consumed (J)')
ax4.grid(axis='y', linestyle='--', linewidth=0.5)
ax4_twin = ax4.twinx()
ax4_twin.plot(x, merged['TotalCrypto_ms'], marker='o', linewidth=1.2, linestyle='--', label='Crypto time (ms)')
ax4_twin.set_ylabel('Total crypto time (ms)')
ax4.set_title('Energy consumed vs Crypto CPU time per Node')
# legends
lines, labels = ax4.get_legend_handles_labels()
lines2, labels2 = ax4_twin.get_legend_handles_labels()
ax4.legend(lines+lines2, labels+labels2, loc='upper right')
fig4.tight_layout()
f4_png = out_dir / 'energy_vs_crypto_time.png'
f4_pdf = out_dir / 'energy_vs_crypto_time.pdf'
fig4.savefig(f4_png, dpi=300); fig4.savefig(f4_pdf)
plt.close(fig4)

# --- PLOT 5: Crypto breakdown (counts) stacked by node for top ops ---
# We'll take top 6 op names by total count for a readable stacked bar
ops_ct = crypto.groupby('OpName', as_index=False)['Count'].sum().sort_values('Count', ascending=False)
top_ops = ops_ct.head(6)['OpName'].tolist()
crypto_pivot = crypto[crypto['OpName'].isin(top_ops)].pivot_table(index='Node', columns='OpName', values='Count', aggfunc='sum', fill_value=0)
crypto_pivot = crypto_pivot.reindex(sorted(crypto_pivot.index), fill_value=0)
fig5, ax5 = plt.subplots(figsize=(7,4))
bottom = np.zeros(len(crypto_pivot))
node_labels = [str(int(n)) for n in crypto_pivot.index]
for col in crypto_pivot.columns:
    vals = crypto_pivot[col].values
    ax5.bar(node_labels, vals, bottom=bottom, label=col)
    bottom = bottom + vals
ax5.set_xlabel('Node'); ax5.set_ylabel('Operation Count')
ax5.set_title('Crypto operation counts (top ops) per Node')
ax5.legend(ncol=2, fontsize='small')
ax5.grid(axis='y', linestyle='--', linewidth=0.5)
fig5.tight_layout()
f5_png = out_dir / 'crypto_ops_counts_per_node.png'
f5_pdf = out_dir / 'crypto_ops_counts_per_node.pdf'
fig5.savefig(f5_png, dpi=300); fig5.savefig(f5_pdf)
plt.close(fig5)

# Create a zip of all outputs for easy download
zip_path = Path('/mnt/data/uav_plots_figures.zip')
with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
    for p in sorted(out_dir.iterdir()):
        zf.write(p, arcname=p.name)

print("Created figures in:", out_dir)
print("Created zip:", zip_path)
