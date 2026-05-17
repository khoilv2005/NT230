"""Standard classification metrics used throughout the paper.

Reports Accuracy, Precision, Recall, F1 and Balanced Accuracy together with
the confusion-matrix counts so consumers can render the figures shown in
§5.1–§5.3 of the paper.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix as sk_confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
)


@dataclass
class ClassificationReport:
    accuracy: float
    balanced_accuracy: float
    precision: float
    recall: float
    f1: float
    # Per-class metrics for the imbalanced D2 setting.
    benign: dict
    malicious: dict
    confusion: dict
    n_samples: int

    def to_dict(self) -> dict:
        return {
            "accuracy": self.accuracy,
            "balanced_accuracy": self.balanced_accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "benign": self.benign,
            "malicious": self.malicious,
            "confusion": self.confusion,
            "n_samples": self.n_samples,
        }


def confusion_matrix(y_true: Sequence[int], y_pred: Sequence[int]) -> dict:
    """Return TN/FP/FN/TP counts for binary predictions."""
    cm = sk_confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
    }


def classification_report(
    y_true: Sequence[int], y_pred: Sequence[int]
) -> ClassificationReport:
    """Compute the metric set reported in the paper."""
    y_true_arr = np.asarray(y_true)
    y_pred_arr = np.asarray(y_pred)
    if len(y_true_arr) == 0:
        raise ValueError("Empty prediction list")

    acc = accuracy_score(y_true_arr, y_pred_arr)
    bal_acc = balanced_accuracy_score(y_true_arr, y_pred_arr)
    p, r, f1, _ = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, average="binary", zero_division=0
    )

    per_class = precision_recall_fscore_support(
        y_true_arr, y_pred_arr, labels=[0, 1], zero_division=0
    )
    benign_p, benign_r, benign_f1, benign_support = (
        float(per_class[0][0]),
        float(per_class[1][0]),
        float(per_class[2][0]),
        int(per_class[3][0]),
    )
    mal_p, mal_r, mal_f1, mal_support = (
        float(per_class[0][1]),
        float(per_class[1][1]),
        float(per_class[2][1]),
        int(per_class[3][1]),
    )

    return ClassificationReport(
        accuracy=float(acc),
        balanced_accuracy=float(bal_acc),
        precision=float(p),
        recall=float(r),
        f1=float(f1),
        benign={
            "precision": benign_p,
            "recall": benign_r,
            "f1": benign_f1,
            "support": benign_support,
        },
        malicious={
            "precision": mal_p,
            "recall": mal_r,
            "f1": mal_f1,
            "support": mal_support,
        },
        confusion=confusion_matrix(y_true_arr, y_pred_arr),
        n_samples=int(len(y_true_arr)),
    )


def format_report(report: ClassificationReport) -> str:
    """Render a report in a paper-style human-readable format."""
    lines = [
        f"Samples           : {report.n_samples}",
        f"Accuracy          : {report.accuracy:.4f}",
        f"Balanced Accuracy : {report.balanced_accuracy:.4f}",
        f"Precision         : {report.precision:.4f}",
        f"Recall            : {report.recall:.4f}",
        f"F1                : {report.f1:.4f}",
        "",
        "                  Precision   Recall      F1          Support",
        "Benign            "
        f"{report.benign['precision']:<11.4f} "
        f"{report.benign['recall']:<11.4f} "
        f"{report.benign['f1']:<11.4f} "
        f"{report.benign['support']}",
        "Malicious         "
        f"{report.malicious['precision']:<11.4f} "
        f"{report.malicious['recall']:<11.4f} "
        f"{report.malicious['f1']:<11.4f} "
        f"{report.malicious['support']}",
        "",
        "Confusion matrix  :",
        f"  TN={report.confusion['TN']}  FP={report.confusion['FP']}",
        f"  FN={report.confusion['FN']}  TP={report.confusion['TP']}",
    ]
    return "\n".join(lines)
