"""Compute precision, recall, F1 and confusion matrix"""
from collections import defaultdict

def confusion_counts(y_true, y_pred, positive_label="malicious"):
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        t_pos = (t == positive_label)
        p_pos = (p == positive_label)
        if t_pos and p_pos:
            tp += 1
        elif not t_pos and p_pos:
            fp += 1
        elif not t_pos and not p_pos:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn

def compute_metrics(y_true, y_pred):
    tp, fp, tn, fn = confusion_counts(y_true, y_pred)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "total": len(y_true)
    }

def per_attack_breakdown(results):
    """list of dicts with true_attack, predicted_label."""
    by_type = defaultdict(lambda: {"total": 0, "detected": 0})

    for r in results:
        attack = r["true_attack"]
        if not attack:
            continue
        by_type[attack]["total"] += 1
        if r["predicted_label"] == "malicious":
            by_type[attack]["detected"] += 1

    breakdown = {}
    for attack, stats in by_type.items():
        rate = stats["detected"] / stats["total"] if stats["total"] else 0.0
        breakdown[attack] = {
            "total": stats["total"],
            "detected": stats["detected"],
            "detection_rate": round(rate, 4)
        }
    return breakdown

def per_source_breakdown(results):
    """Group by input source."""
    by_source = defaultdict(lambda: {"total": 0, "correct": 0})

    for r in results:
        source = r.get("source", "unknown")
        by_source[source]["total"] += 1
        if r["true_label"] == r["predicted_label"]:
            by_source[source]["correct"] += 1

    breakdown = {}
    for source, stats in by_source.items():
        acc = stats["correct"] / stats["total"] if stats["total"] else 0.0
        breakdown[source] = {
            "total": stats["total"],
            "correct": stats["correct"],
            "accuracy": round(acc, 4)
        }
    return breakdown

def false_positives(results):
    return [r for r in results if r["true_label"] == "benign" and r["predicted_label"] == "malicious"]

def false_negatives(results):
    return [r for r in results if r["true_label"] == "malicious" and r["predicted_label"] == "benign"]
