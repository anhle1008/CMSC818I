import json, argparse
from pathlib import Path
from collections import Counter

def load_jsonl(p):
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)

def norm_cwe(x):
    if not x:
        return None
    x = str(x).strip().upper()
    if x.startswith("CWE-"):
        return "CWE-" + x.split("CWE-")[-1].strip()
    # allow bare numbers like "78"
    if x.isdigit():
        return f"CWE-{x}"
    return x  # fall back

def safe_bool(v):
    # robustly coerce to bool if model returns "true"/"false"/1/0
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "yes", "y", "1"):  return True
        if s in ("false", "no", "n", "0"):  return False
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)  # results/runs/run_*.jsonl
    args = ap.parse_args()

    y_true, y_pred = [], []
    cwe_true, cwe_pred = [], []
    errors = 0
    n = 0

    for rec in load_jsonl(args.run):
        n += 1
        gold = (rec.get("gold_label") == "vulnerable")
        y_true.append(gold)

        # 1) merge judge -> detect (so flips affect scoring)
        det = rec.get("detect_output") or {}
        judge = rec.get("judge_output")
        if isinstance(judge, dict) and judge.get("judge_verdict") in ("confirm", "flip"):
            det = {
                **det,
                **{k: judge.get(k, det.get(k)) for k in ("vulnerable", "predicted_cwe")}
            }

        # 2) detection label (count parse errors if no boolean present)
        if not isinstance(det, dict) or "vulnerable" not in det:
            errors += 1
            v_pred = False
        else:
            v_pred = safe_bool(det.get("vulnerable"))

        y_pred.append(v_pred)

        # 3) CWE scoring only on gold-vulnerable items
        if gold:
            gold_cwe = norm_cwe(rec.get("gold_cwe"))
            # prefer merged det.cwe, else fallback to classify_output (if present)
            det_cwe = norm_cwe(det.get("predicted_cwe")) if isinstance(det, dict) else None
            if not det_cwe:
                co = rec.get("classify_output") or {}
                det_cwe = norm_cwe(co.get("predicted_cwe")) if isinstance(co, dict) else None
            cwe_true.append(gold_cwe)
            cwe_pred.append(det_cwe)

    # Binary metrics
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)

    def safe_div(a, b): return a / b if b else 0.0
    precision = safe_div(tp, tp + fp)
    recall    = safe_div(tp, tp + fn)
    f1        = safe_div(2 * precision * recall, precision + recall)
    accuracy  = safe_div(tp + tn, len(y_true))

    print("=== Vulnerability detection ===")
    print(f"Examples  : {n}")
    print(f"Accuracy  : {accuracy:.3f}")
    print(f"Precision : {precision:.3f}")
    print(f"Recall    : {recall:.3f}")
    print(f"F1        : {f1:.3f}")
    print(f"Parse errs: {errors}")

    # CWE top-1 accuracy on gold-vulnerable subset (ignore None gold CWEs)
    cwe_pairs = [(g, p) for g, p in zip(cwe_true, cwe_pred) if g]
    if cwe_pairs:
        cwe_acc = sum(1 for g, p in cwe_pairs if p == g) / len(cwe_pairs)
        misses  = Counter([g for g, p in cwe_pairs if p != g])
        print("\n=== CWE Classification (gold vulnerable only) ===")
        print(f"Top-1 Accuracy: {cwe_acc:.3f} (on {len(cwe_pairs)} items)")
        print("Most missed CWEs:", misses.most_common(5))
    else:
        print("\n(No gold CWEs to score.)")

if __name__ == "__main__":
    main()
