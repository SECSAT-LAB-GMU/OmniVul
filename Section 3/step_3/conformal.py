import json
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt 


def conformal_fit_ordinal(cal_yhat, cal_y, alpha=0.10):
    """
    Fit conformal predictor for ordinal labels {1,2,3,4,5}.

    cal_yhat: 1D array of LLM scores on calibration set (floats)
    cal_y:    1D array of human labels on calibration set (ints)
    alpha:    miscoverage level (0.10 -> 90% coverage)

    Returns:
        q: conformal radius (float)
    """
    cal_yhat = np.asarray(cal_yhat, dtype=float)
    cal_y = np.asarray(cal_y, dtype=int)
    assert cal_yhat.shape == cal_y.shape
    n = cal_y.size
    if n == 0:
        raise ValueError("Empty calibration set.")

    # nonconformity scores
    s = np.abs(cal_yhat - cal_y)

    # finite-sample quantile
    k = int(np.ceil((n + 1) * (1 - alpha)))
    k = min(max(k, 1), n)
    q = np.partition(s, k - 1)[k - 1]

    return float(q)


def conformal_predict_set_ordinal(yhat, q, label_min=1, label_max=5):
    """
    Predict conformal set for a new float score yhat.

    yhat:      LLM score (float)
    q:         radius from conformal_fit_ordinal
    label_min, label_max: ordinal label space

    Returns:
        labels: sorted np.array of integers
    """
    candidates = np.arange(label_min, label_max + 1)
    mask = np.abs(candidates - yhat) <= q
    return candidates[mask]

metric = 'faithfulness'  # 'faithfulness', 'correctness', 'completeness'
llm_df = pd.read_csv(f'conformal/cves_{metric}.csv')
human_df = pd.read_csv(f'conformal/human_{metric}.csv')
llm_df = llm_df.sort_values(by='CVE').reset_index(drop=True)
human_df = human_df.sort_values(by='CVE').reset_index(drop=True)
id_col = "CVE"

common = [c for c in llm_df.columns if c in human_df.columns and c != id_col]
print(f"Common columns: {len(common)}")
numeric_cols = common.copy()

llm_num = llm_df[numeric_cols].reset_index(drop=True)
human_num = human_df[numeric_cols].reset_index(drop=True)

# Compute two-sided absolute non-conformity
nonconf_scores = (llm_num - human_num).abs()

# Keep CVE column as-is and concat with scores
nonconf_df = pd.concat([llm_df[[id_col]], nonconf_scores], axis=1)
nonconf_df.to_csv(f'conformal/nonconformity_{metric}.csv', index=False)
alpha = 0.10  # 90% coverage
results = []

for col in nonconf_df.columns:
    if col == "CVE":   # skip the ID column
        continue
    
    s = nonconf_df[col].dropna().to_numpy(float)
    n = s.size
    if n == 0:
        results.append({"column": col, "n": 0, "q": np.nan})
        continue

    # finite-sample quantile
    k = int(np.ceil((n + 1) * (1 - alpha)))
    k = min(max(k, 1), n)
    q = float(np.partition(s, k - 1)[k - 1])

    results.append({"column": col, "n": n, "k": k, "q": round(q, 4)})

conformal_q_df = pd.DataFrame(results).sort_values("column").reset_index(drop=True)
conformal_q_df.to_csv(f'conformal/threshold_{metric}.csv', index=False)

mean_score = llm_df.drop(columns=['CVE']).mean().round(2)

# mean_score = pd.read_csv(f'rag_mean_{metric}.csv')
mean_score = mean_score.rename(columns={mean_score.columns[0]: 'Attribute', f'Mean {metric.capitalize()}': 'Score'})

conformal_thresholds = pd.read_csv(f'conformal/threshold_{metric}.csv')[['column', 'q']]
conformal_thresholds = conformal_thresholds.rename(columns={'column': 'Attribute', 'q': f'Conformal Threshold'})

merged_df = pd.merge(mean_score, conformal_thresholds, on='Attribute', how='inner')
merged_df[['Category', 'Attribute']] = merged_df['Attribute'].str.split('_', n=1, expand=True)

attr_name_map = {
    'Function_name': 'Func. Name',
    'File_name': 'File Name',
    'Vulnerable_OS_component': 'Vuln. OS Comp.',
    'Weakness_Type': 'Weakness',
    'root_cause': 'Root Cause',
    'secure_coding_violation': 'Sec. Violation',
    'mitigation': 'Mitigation',
    'cia_impact': 'CIA Impact',
    'exploit_expl': 'Exploit Expl.',
    'Exploit_Code': 'Exploit Code',
    'exploited_versions': 'Exploit Vers.',
    'abusable_interfaces': 'Abusable Intfs.',
    'exploit_steps': 'Exploit Steps',
    'privs_req': 'Privs. Req.',
    'exploit_privs': 'Exploit Privs.',
    'remote_exploitability': 'Remote Exploit.',
    'crash_dump': 'Crash Dump',
    'patch_expl': 'Patch Expl.',
    'patch_date': 'Patch Date',
    'patched_versions': 'Patch Vers.',
    'Code_diff': 'Code Diff',
    'Patch_code': 'Patch Code',
    'score_explain': 'Score Expl.'
}

category_map = {'SCORES': 'Impact', 
                'CWE': 'Primary', 
                'Localization': 'Primary',
                'Reasoning': 'Primary'}

merged_df['Attribute'] = merged_df['Attribute'].map(attr_name_map).fillna(merged_df['Attribute'])
merged_df['Category'] = merged_df['Category'].map(category_map).fillna(merged_df['Category'])
merged_df.loc[merged_df['Attribute'] == 'Exploit Expl.', 'Category'] = 'Exploit'
# category_order = ['Localization', 'CWE', 'Reasoning', 'Exploit', 'Patch', 'Impact Scores']
category_order = ['Primary', 'Exploit', 'Patch', 'Impact']
merged_df['Category'] = pd.Categorical(merged_df['Category'], categories=category_order, ordered=True)
merged_df = merged_df.sort_values(by='Category', ascending=False)

# Define color palette
category_colors = {
    'Primary': '#1f77b4',
    'Exploit': '#ff7f0e',
    'Patch': '#2ca02c',
    'Impact': '#9467bd',
}

merged_df['marker'] = np.where(merged_df['Conformal Threshold'] == 0.0, 's', '^')  # 's' = square, '^' = triangle
attribute_order = ['Func. Name', 'File Name', 'Vuln. OS Comp.', 'Weakness', 'Root Cause', 
                  'Sec. Violation', 'Mitigation', 'CIA Impact', 
                  'Exploit Expl.', 'Exploit Code', 'Exploit Vers.', 'Abusable Intfs.', 
                  'Exploit Steps', 'Privs. Req.', 'Exploit Privs.', 'Remote Exploit.', 
                  'Crash Dump', 
                  'Patch Expl.', 'Patch Date', 'Patch Vers.', 'Code Diff', 'Patch Code',
                  'Score Expl.']
merged_df['Attribute'] = pd.Categorical(merged_df['Attribute'], categories=attribute_order, ordered=True)
merged_df = merged_df.sort_values(by='Attribute', ascending=True)
merged_df = merged_df.reset_index(drop=True)
merged_df['y_pos'] = range(len(merged_df))

# Plotting
fig, ax = plt.subplots(figsize=(4.5,6))
for idx, row in merged_df.iterrows():
    y = row['y_pos']
    score = row['Score']
    threshold = row['Conformal Threshold']
    category = row['Category']
    color = category_colors[category]
    ax.hlines(y=y, xmin=max(score - threshold, 0), xmax=min(score + threshold, 5),
              color=color, linewidth=10, alpha=0.3)
    ax.plot(score, y, marker=row['marker'], color=category_colors[category],
            markersize=8 if row['marker'] == 's' else 10)

ax.set_yticks(merged_df['y_pos'])
ax.set_yticklabels(merged_df['Attribute'], fontsize=14)
ax.tick_params(axis='x', labelsize=12)
ax.set_xticks(np.arange(1, 6, 1))
ax.set_xlim(1, 5.2)
ax.set_xlabel(f"{metric.capitalize()} Score", fontsize=14, fontweight='bold')
ax.set_ylabel(f"Attributes", fontsize=14, fontweight='bold')
ax.invert_yaxis()
ax.grid(axis='x', linestyle='--', alpha=0.7)
ax.grid(axis='y', linestyle=':', alpha=0.7)

# Custom legend
handles = []
for cat in category_order:
    handles.append(plt.Line2D([0], [0], marker='s', color='w',
                              markerfacecolor=category_colors[cat], label=cat,
                              markersize=10))
ax.legend(handles=handles, title='Category', loc='upper left', fontsize=12, title_fontsize=14)

plt.tight_layout()
plt.savefig(f'conformal/{metric}_conformal.pdf', dpi=300)