"""
Script to generate the comprehensive, publication-ready PNG table:
per_model_three_stream_mapping_table.png

Presents all 10 Leave-One-Attack-Out (LOAO) models tested across all 3 traffic streams:
1. Unseen Zero-Day Flows: Tested, -> Unknown (S > tau), -> Known (S <= tau), -> Normal (S <= tau), Catch Rate %
2. Known Attack Flows: Tested, -> Known (S <= tau), -> Unknown (S > tau), -> Normal (S <= tau)
3. Benign Normal Flows: Tested, -> Normal (S <= tau), -> Unknown (S > tau), -> Known (S <= tau)

Excludes the totals summary row and the last two aggregated columns per user request.
"""

import os
import matplotlib.pyplot as plt
import numpy as np

OUTPUT_DIR = r'd:\p01\Live_Demonstration\outputs\step3_tier2_zeroday'
RESULTS_DIR = r'd:\p01\Final_Proposed_Solution\03_Tier2_ZeroDay_Detection\results'
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# Wide figure to guarantee ample breathing room for all 14 columns
fig, ax = plt.subplots(figsize=(24, 10.5), dpi=300)
ax.axis('off')

# Title & Subtitles
fig.text(0.5, 0.965, "10-Model Leave-One-Attack-Out (LOAO) Comprehensive Traffic Transition Matrix", 
         ha='center', va='top', fontsize=18, fontweight='bold', color='#0f172a')
fig.text(0.5, 0.935, "100% Genuine UNSW Bot-IoT Test Flows | 135,556 Evaluations Across 10 Independent Models", 
         ha='center', va='top', fontsize=11, color='#475569')

headers = [
    "Held-Out Model\n(m)",
    "Unseen ZD\nTotal",
    "ZD → Unk\n(S > τ) [TP]",
    "ZD → Known\n(S ≤ τ) [Perim]",
    "ZD → Norm\n(S ≤ τ) [FN]",
    "Zero-Day\nCatch %",
    "Known Att\nTotal",
    "Known → Att\n(S ≤ τ) [TP_att]",
    "Known → Unk\n(S > τ) [FP_rej]",
    "Known → Norm\n(S ≤ τ) [FN_att]",
    "Normal\nTotal",
    "Norm → Norm\n(S ≤ τ) [TN]",
    "Norm → Unk\n(S > τ) [FP]",
    "Norm → Att\n(S ≤ τ) [FP_att]"
]

rows = [
    ["1. DoS - HTTP", "5,960", "5,954", "0", "6", "99.90%", "6,845", "6,411", "430", "4", "1,432", "1,414", "18", "0"],
    ["2. DoS - TCP", "3,846", "3,846", "0", "0", "100.00%", "7,162", "6,681", "475", "6", "1,432", "1,421", "10", "0"],
    ["3. DoS - UDP", "5,239", "5,239", "0", "0", "100.00%", "6,953", "6,560", "390", "3", "1,432", "1,415", "17", "0"],
    ["4. DDoS - HTTP", "4,040", "4,035", "0", "5", "99.88%", "7,133", "6,712", "417", "4", "1,432", "1,410", "22", "0"],
    ["5. DDoS - TCP", "6,154", "6,154", "0", "0", "100.00%", "6,815", "6,433", "375", "7", "1,432", "1,412", "19", "0"],
    ["6. DDoS - UDP", "4,761", "4,760", "0", "1", "99.98%", "7,024", "6,616", "402", "6", "1,432", "1,415", "17", "0"],
    ["7. Recon - OS_Fingerprint", "10,000", "9,936", "0", "64", "99.36%", "6,239", "5,904", "330", "5", "1,432", "1,414", "18", "0"],
    ["8. Recon - Service_Scan", "10,000", "9,588", "0", "412", "95.88%", "6,239", "5,863", "370", "6", "1,432", "1,422", "10", "0"],
    ["9. Theft - Keylogging", "1,469", "1,452", "0", "17", "98.84%", "7,518", "7,069", "447", "2", "1,432", "1,416", "16", "0"],
    ["10. Theft - Data_Exfil", "118", "110", "0", "8", "93.22%", "7,721", "7,241", "477", "3", "1,432", "1,414", "18", "0"]
]

# 14 columns, total width = 1.00
col_widths = [
    0.130,  # Model Name
    0.060,  # ZD Total
    0.072,  # ZD -> Unk [TP]
    0.068,  # ZD -> Known [Perim]
    0.068,  # ZD -> Norm [FN]
    0.062,  # ZD Catch %
    0.060,  # Known Total
    0.080,  # Known -> Att [TP_att]
    0.072,  # Known -> Unk [FP_rej]
    0.068,  # Known -> Norm [FN_att]
    0.060,  # Norm Total
    0.072,  # Norm -> Norm [TN]
    0.060,  # Norm -> Unk [FP]
    0.068   # Norm -> Att [FP_att]
]

table = ax.table(
    cellText=rows,
    colLabels=headers,
    colWidths=col_widths,
    cellLoc='center',
    loc='center',
    bbox=[0.01, 0.09, 0.98, 0.80]
)

table.auto_set_font_size(False)
table.set_fontsize(9.2)

# Style headers
for j in range(14):
    cell = table[(0, j)]
    cell.set_facecolor('#0f172a')
    cell.set_text_props(color='white', fontweight='bold', fontsize=9.0)
    cell.set_height(0.088)

# Style data rows
for i in range(1, len(rows) + 1):
    bg_color = '#f8fafc' if i % 2 == 1 else '#ffffff'
    
    for j in range(14):
        cell = table[(i, j)]
        cell.set_facecolor(bg_color)
        cell.set_edgecolor('#cbd5e1')
        cell.set_height(0.068)
        
        if j == 0:
            cell.get_text().set_ha('left')
            cell.set_text_props(fontweight='bold', color='#1e293b')
        elif j in [2, 5]: # ZD caught & rate
            cell.set_text_props(fontweight='bold', color='#047857')
        elif j == 3: # ZD -> Known
            cell.set_text_props(color='#64748b')
        elif j == 4: # ZD -> Normal (FN missed)
            val = rows[i-1][4]
            color = '#64748b' if val == '0' else '#b91c1c'
            cell.set_text_props(fontweight='bold' if val != '0' else 'normal', color=color)
        elif j == 7: # Known -> Known
            cell.set_text_props(fontweight='bold', color='#047857')
        elif j == 8: # Known -> Unknown (Alert)
            cell.set_text_props(color='#b45309')
        elif j == 9: # Known -> Normal (FN_att missed)
            val = rows[i-1][9]
            cell.set_text_props(color='#b91c1c' if int(val) > 0 else '#64748b')
        elif j == 11: # Normal cleared
            cell.set_text_props(fontweight='bold', color='#047857')
        elif j == 12: # Normal -> Unknown (False alarm)
            cell.set_text_props(color='#b91c1c')
        elif j == 13: # Normal -> Known (FP_att)
            cell.set_text_props(color='#64748b')
        else:
            cell.set_text_props(color='#334155')

# Caption explaining notation at bottom
caption_text = (
    "Terminology & Security Roles:  "
    "TP = Unseen Zero-Day Isolated (S > τ)  |  "
    "FN = Zero-Day Missed into Normal (S ≤ τ)  |  "
    "TP_att = Known Attack Correctly Routed to Tier-1 (S ≤ τ)  |  "
    "FP_rej = Known Attack Alerted as Novelty (S > τ)  |\n"
    "FN_att = Known Attack Slipped into Normal (S ≤ τ)  |  "
    "TN = Normal Correctly Cleared (S ≤ τ)  |  "
    "FP = False Alarm on Normal (S > τ)  |  "
    "FP_att = Normal Falsely Tagged as Known Attack (0 flows leaked)"
)
fig.text(0.5, 0.038, caption_text, ha='center', va='center', fontsize=9.2, color='#475569',
         bbox=dict(boxstyle='round,pad=0.5', facecolor='#f1f5f9', edgecolor='#cbd5e1'))

p_live = os.path.join(OUTPUT_DIR, "per_model_three_stream_mapping_table.png")
p_res = os.path.join(RESULTS_DIR, "per_model_three_stream_mapping_table.png")
plt.savefig(p_live, bbox_inches='tight', dpi=300)
plt.savefig(p_res, bbox_inches='tight', dpi=300)
plt.close()
print("Saved complete per-model 3-stream table (14 cols, 10 models) to:", p_live)
