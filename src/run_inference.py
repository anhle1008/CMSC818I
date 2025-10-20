import csv
import json
import time
import argparse
import re
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from openai import OpenAI  # make sure openai is installed

# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------

def load_template(path: str) -> str:
    """Load text from a prompt template file."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# Regex to capture first JSON object
JSON_BLOCK = re.compile(r'\{.*\}', re.DOTALL)

def coerce_json(text: str) -> dict:
    """
    Try to parse model output as JSON.
    If it fails, attempt to extract first {...} block.
    """
    if not text:
        return {"error": "empty_model_output", "raw": text}

    try:
        return json.loads(text)
    except Exception:
        pass

    m = JSON_BLOCK.search(text)
    if m:
        candidate = m.group(0)
        try:
            return json.loads(candidate)
        except Exception as e:
            return {"error": f"json_parse_error: {type(e).__name__}: {e}", "raw": text}

    return {"error": "no_json_found_in_output", "raw": text}


def call_model(client, model: str, prompt: str, max_output_tokens: int = 400) -> dict:
    """
    Call the model and return parsed JSON (or an error dict).
    """
    try:
        resp = client.responses.create(
            model=model,
            input=prompt,
            temperature=0.0,
            max_output_tokens=max_output_tokens
        )
        text = resp.output_text or ""
        return coerce_json(text)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

# ---------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/tiny.csv")
    ap.add_argument("--detect_tmpl", default="prompts/detect_vuln.txt")
    ap.add_argument("--classify_tmpl", default="prompts/classify_cwe.txt")
    ap.add_argument("--model", default="gpt-4.1-mini")
    ap.add_argument("--outdir", default="results/runs")
    args = ap.parse_args()

    client = OpenAI()  # expects OPENAI_API_KEY to be set
    Path(args.outdir).mkdir(parents=True, exist_ok=True)

    detect_tmpl = load_template(args.detect_tmpl)
    classify_tmpl = load_template(args.classify_tmpl)

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = Path(args.outdir) / f"run_{run_id}.jsonl"
    print(f"Writing outputs to {out_path}")

    with open(args.data, newline="", encoding="utf-8") as f_in, open(out_path, "w", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in, delimiter=",")
        row_count = 0

        for row in reader:
            row_count += 1
            if row_count <= 2:
                print(f"[debug] row#{row_count} keys={list(row.keys())}")

            code = row["code"]
            detect_prompt = detect_tmpl.replace("{{CODE}}", code)

            det = call_model(client, args.model, detect_prompt)

            # If vulnerable and no CWE predicted, run classification
            if isinstance(det, dict) and det.get("vulnerable") and not det.get("predicted_cwe"):
                classify_prompt = classify_tmpl.replace("{{CODE}}", code)
                cwe_second_pass = call_model(client, args.model, classify_prompt)
            else:
                cwe_second_pass = None

            record: Dict[str, Any] = {
                "id": row.get("id"),
                "lang": row.get("lang", ""),
                "gold_label": row.get("label"),
                "gold_cwe": (row.get("cwe_id") or None),
                "detect_output": det,
                "classify_output": cwe_second_pass
            }

            f_out.write(json.dumps(record) + "\n")
            f_out.flush()
            time.sleep(0.2)  # small pause for rate limits

        print(f"[debug] processed rows: {row_count}")

# ---------------------------------------------------------------------

if __name__ == "__main__":
    main()
