import csv, json, os, time, argparse
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

from openai import OpenAI  # pip install openai

def load_template(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def call_model(client, model: str, prompt: str, max_output_tokens: int = 400) -> str:
    # Responses API works well for JSON-style prompting
    resp = client.responses.create(
        model=model,
        input=prompt,
        temperature=0.2,
        max_output_tokens=max_output_tokens
    )
    return resp.output_text  # text the model returned

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/tiny.csv")
    ap.add_argument("--detect_tmpl", default="prompts/detect_vuln.txt")
    ap.add_argument("--classify_tmpl", default="prompts/classify_cwe.txt")
    ap.add_argument("--model", default="gpt-4.1-mini")  # cheap+strong; swap if needed
    ap.add_argument("--outdir", default="results/runs")
    args = ap.parse_args()

    client = OpenAI()  # expects OPENAI_API_KEY env var
    Path(args.outdir).mkdir(parents=True, exist_ok=True)

    detect_tmpl = load_template(args.detect_tmpl)
    classify_tmpl = load_template(args.classify_tmpl)

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = Path(args.outdir) / f"run_{run_id}.jsonl"
    print(f"Writing outputs to {out_path}")

    with open(args.data, newline="", encoding="utf-8") as f_in, open(out_path, "w", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in)
        for row in reader:
            code = row["code"]
            detect_prompt = detect_tmpl.replace("{{CODE}}", code)

            try:
                det_raw = call_model(client, args.model, detect_prompt)
                det = json.loads(det_raw)
            except Exception as e:
                det = {"error": str(e), "raw": det_raw if "det_raw" in locals() else ""}

            cwe_second_pass = None
            if isinstance(det, dict) and det.get("vulnerable") and not det.get("predicted_cwe"):
                classify_prompt = classify_tmpl.replace("{{CODE}}", code)
                try:
                    cls_raw = call_model(client, args.model, classify_prompt)
                    cwe_second_pass = json.loads(cls_raw)
                except Exception as e:
                    cwe_second_pass = {"error": str(e)}

            record: Dict[str, Any] = {
                "id": row["id"],
                "lang": row.get("lang", ""),
                "gold_label": row["label"],
                "gold_cwe": row.get("cwe_id", "") or None,
                "detect_output": det,
                "classify_output": cwe_second_pass
            }
            f_out.write(json.dumps(record) + "\n")
            time.sleep(0.2)  # be nice to the rate limits

if __name__ == "__main__":
    main()
