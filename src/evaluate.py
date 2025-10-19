import json, argparse
from pathlib import Path
from collections import Counter

def load_jsonl(p):
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)  # results/runs/run_*.jsonl
    args = ap.parse_args()

    y_true, y_pred = [], []
    cwe_true, cwe_pred = [], []
    errors = 0

    for rec in load_jsonl(args.run):
        gold = rec["gold_label"] == "vulnerable"
        y_true.append(gold)

        det = rec["detect_output"]
        if not isinstance(det, dict) or "vulnerable" not in det:
            errors += 1
            y_pred.append(False)
        else:
            y_pred.append(bool(det["vulnerable"]))

        # CWE scoring only on vulnerable gold items
        if gold:
            gold_cwe = (rec.get("gold_cwe") or "").strip() or None
            if isinstance(det, dict) and det.get("predicted_cwe"):
                pred_cwe = det["predicted_cwe"]
            else:
                co = rec.get("classify_output") or {}
                pred_cwe = co.get("predicted_cwe") if isinstance(co, dict) else None
            cwe_true.append(gold_cwe)
            cwe_pred.append(pred_cwe)

    # Binary metrics
    tp = sum(1 for t,p in zip(y_true, y_pred) if t and p)
    tn = sum(1 for t,p in zip(y_true, y_pred) if not t and not p)
    fp = sum(1 for t,p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t,p in zip(y_true, y_pred) if t and not p)

    def safe_div(a,b): return a / b if b else 0.0
    precision = safe_div(tp, tp+fp)
    recall    = safe_div(tp, tp+fn)
    f1        = safe_div(2*precision*recall, precision+recall)
    accuracy  = safe_div(tp+tn, len(y_true))

    print("=== Vulnerability detection ===")
    print(f"Accuracy : {accuracy:.3f}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall   : {recall:.3f}")
    print(f"F1       : {f1:.3f}")
    print(f"Parsing errors: {errors}")

    # CWE top-1 accuracy on gold-vulnerable subset (ignore None gold)
    cwe_pairs = [(g,p) for g,p in zip(cwe_true, cwe_pred) if g]
    if cwe_pairs:
        cwe_acc = sum(1 for g,p in cwe_pairs if p == g) / len(cwe_pairs)
        misses  = Counter([g for g,p in cwe_pairs if p != g])
        print("\n=== CWE Classification (gold vulnerable only) ===")
        print(f"Top-1 Accuracy: {cwe_acc:.3f} (on {len(cwe_pairs)} items)")
        print("Most missed CWEs:", misses.most_common(5))
    else:
        print("\n(No gold CWEs to score.)")

if __name__ == "__main__":
    main()
