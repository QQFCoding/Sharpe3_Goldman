import math
import statistics


def latency(values, duration):
    ordered = sorted(values)
    def p(q):
        return ordered[max(0, math.ceil(q * len(ordered)) - 1)] if ordered else 0
    return {"requests": len(values), "duration_seconds": duration,
        "throughput_rps": len(values) / duration if duration else 0,
        "p50_ms": statistics.median(ordered) if ordered else 0, "p95_ms": p(.95), "p99_ms": p(.99)}


def classification(rows, threshold):
    tp = sum(r["malicious"] and r["score"] >= threshold for r in rows)
    fp = sum(not r["malicious"] and r["score"] >= threshold for r in rows)
    fn = sum(r["malicious"] and r["score"] < threshold for r in rows)
    tn = len(rows) - tp - fp - fn
    def ratio(a, b):
        return a / b if b else 0
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    positives = [r["score"] for r in rows if r["malicious"]]
    negatives = [r["score"] for r in rows if not r["malicious"]]
    auc = ratio(sum((p > n) + .5 * (p == n) for p in positives for n in negatives), len(positives) * len(negatives))
    ap, previous_recall = 0, 0
    for score in sorted({r["score"] for r in rows}, reverse=True):
        predicted = [r for r in rows if r["score"] >= score]
        true = sum(r["malicious"] for r in predicted)
        current_recall = ratio(true, len(positives))
        ap += (current_recall - previous_recall) * ratio(true, len(predicted))
        previous_recall = current_recall
    return {"samples": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": ratio(tp + tn, len(rows)), "precision": precision, "recall": recall,
        "f1": ratio(2 * precision * recall, precision + recall), "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, tp + fn), "auroc": auc if positives and negatives else None,
        "auprc_average_precision": ap if positives else None}


def calibrate(rows, minimum_threshold=.01):
    candidates = sorted(t for t in {minimum_threshold, .3, .5, .85, .99, 1.0, *[r["score"] for r in rows]}
        if t >= minimum_threshold)
    measured = [(t, classification(rows, t)) for t in candidates]
    feasible = [x for x in measured if x[1]["false_positive_rate"] <= .1]
    threshold, _ = max(feasible or measured, key=lambda x: (x[1]["f1"], x[1]["recall"], -x[1]["false_positive_rate"], x[0]))
    return threshold
