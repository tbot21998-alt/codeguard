def classification_metrics(expected, predicted):
    pairs = list(zip(expected, predicted))
    tp = sum(wanted and actual for wanted, actual in pairs)
    fp = sum(not wanted and actual for wanted, actual in pairs)
    fn = sum(wanted and not actual for wanted, actual in pairs)
    tn = sum(not wanted and not actual for wanted, actual in pairs)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (tp + tn) / len(pairs) if pairs else 0.0
    return {"labeled_count": len(pairs), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "accuracy": accuracy, "precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0, "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0, "meets_accuracy_target": accuracy > 0.9}
