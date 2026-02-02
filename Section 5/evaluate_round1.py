import json
import os
import numpy as np
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

model_name = "gpt"
result_dir = f"{model_name}_results_round1"
predicted_results = []
ground_truths = []

for cve_file in os.listdir(result_dir):
    data = json.load(open(os.path.join(result_dir, cve_file), 'r'))
    if len(data) == 0:
        print(f"{cve_file} has no data")

    total_files = len(data)
    pos_files = sum(1 for v in data.values() if v == 1)
    neg_files = sum(1 for v in data.values() if v == 0)
    unk_files = sum(1 for v in data.values() if v == -1)

    if pos_files > 0:
        predicted_results.append(1)
    else:
        predicted_results.append(0)

    if cve_file.startswith('P'):
        ground_truths.append(0)
    else:
        ground_truths.append(1)

print(len(predicted_results), len(ground_truths))


def macro_statistics(y_pred, y_true):
    cm = confusion_matrix(y_true, y_pred)
    FP = cm.sum(axis=0) - np.diag(cm)
    FN = cm.sum(axis=1) - np.diag(cm)
    TP = np.diag(cm)
    TN = cm.sum() - (FP + FN + TP)

    TPR = TP / (TP + FN)
    TNR = TN / (TN + FP)

    # statistics for each class
    precision = TP / (TP + FP + 1e-10)
    recall = TP / (TP + FN + 1e-10)
    f1 = 2 * (precision * recall) / (precision + recall + 1e-10)

    macro_precision = np.mean(precision)
    macro_recall = np.mean(recall)
    macro_f1 = np.mean(f1)

    return cm, macro_precision, macro_recall, macro_f1

def binary_statistics(y_pred, y_true):
    cm = confusion_matrix(y_true, y_pred)
    FP = cm.sum(axis=0) - np.diag(cm)
    FN = cm.sum(axis=1) - np.diag(cm)
    TP = np.diag(cm)

    precision = TP / (TP + FP + 1e-10)
    recall = TP / (TP + FN + 1e-10)
    f1 = 2 * (precision * recall) / (precision + recall + 1e-10)

    return cm, precision, recall, f1

def weighted_statistics(y_pred, y_true):
    cm = confusion_matrix(y_true, y_pred)
    FP = cm.sum(axis=0) - np.diag(cm)
    FN = cm.sum(axis=1) - np.diag(cm)
    TP = np.diag(cm)

    # Per-class metrics
    precision = TP / (TP + FP + 1e-10)
    recall = TP / (TP + FN + 1e-10)
    f1 = 2 * (precision * recall) / (precision + recall + 1e-10)

    # Support (true instances per class)
    support = cm.sum(axis=1)

    # Weighted averages
    weighted_precision = np.sum(precision * support) / np.sum(support)
    weighted_recall = np.sum(recall * support) / np.sum(support)
    weighted_f1 = np.sum(f1 * support) / np.sum(support)

    return cm, weighted_precision, weighted_recall, weighted_f1

cm, precision, recall, f1 = weighted_statistics(np.array(predicted_results), np.array(ground_truths))
print(f"Precision: {precision}, Recall: {recall}, F1: {f1}")

# plt.figure(figsize=(6, 5))
# sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Pred Neg', 'Pred Pos'], yticklabels=['True Neg', 'True Pos'])
# plt.xlabel('Predicted Label')
# plt.ylabel('True Label')
# plt.title(f'Confusion Matrix for {model_name.upper()} Model') 

# with open('vulnerable_cves.txt', 'w') as f:
#     for cve in vulnerable_cves:
#         f.write(f"{cve}\n")


