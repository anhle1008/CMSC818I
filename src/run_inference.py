#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_inference.py

Pipeline to run an LLM over a CSV of code snippets to detect vulnerabilities and
(optionally) predict CWE categories. Designed to be simple, reproducible, and OS-agnostic.

-------------------------------------------------------------------------------
USAGE (examples)
-------------------------------------------------------------------------------
# Baseline few-shot (single pass)
python3 src/run_inference.py --data data/tiny.csv --mode baseline --model gpt-4.1-mini

# Checklist (structured JSON, recommended)
python3 src/run_inference.py --data data/tiny.csv --mode checklist --model gpt-4.1-mini

# Generator → Judge (two-pass)
python3 src/run_inference.py --data data/tiny.csv --mode gen_judge --model gpt-4.1-mini

# Self-consistency (k=5 majority vote) on checklist
python3 src/run_inference.py --data data/tiny.csv --mode checklist --k 5

# With lightweight retrieval (add short CWE/API blurbs when available)
python3 src/run_inference.py --data data/tiny.csv --mode checklist --retrieval on --blurbs prompts/cwe_blurbs.json

-------------------------------------------------------------------------------
INPUT CSV FORMAT (UTF-8)
-------------------------------------------------------------------------------
Required columns:
- id        : unique string ID per row
- lang      : programming language tag (e.g., c, cpp, java, python, php)
- code      : code snippet (keep ≤ ~120 lines)
- label     : 'vulnerable' or 'clean'         (gold, used by evaluator later)
- cwe_id    : 'CWE-XXX' or empty if clean     (gold, used by evaluator later)

Optional columns are ignored.

-------------------------------------------------------------------------------
OUTPUT
-------------------------------------------------------------------------------
Writes a JSONL file into results/runs/, e.g., results/runs/run_YYYYMMDD-HHMMSS.jsonl
Per line:
{
  "id": "...",
  "lang": "...",
  "gold_label": "vulnerable" | "clean",
  "gold_cwe": "CWE-XXX" | null,
  "prompt_version": {...},             # filenames & mode for reproducibility
  "detect_output": {...},              # final detector JSON (after k-vote)
  "detect_samples": [...],             # (if k>1) raw per-sample JSONs
  "judge_output": {...} | null,        # (gen_judge only) verifier's JSON
  "raw_text": "...",                   # last detector raw text (debug)
  "raw_judge_text": "..." | null,      # judge raw text (debug)
  "errors": {"detector_parse": 0|1, "judge_parse": 0|1}
}

-------------------------------------------------------------------------------
REQUIREMENTS
-------------------------------------------------------------------------------
- openai >= 1.40
- python-dotenv >= 1.0   (optional; for loading .env)
- An environment variable OPENAI_API_KEY set (or a .env file with it)

-------------------------------------------------------------------------------
PROMPT FILES (expected locations by default)
-------------------------------------------------------------------------------
- prompts/detect_vuln.txt       : baseline/generator prompt (few-shot, STRICT JSON)
- prompts/detect_checklist.txt  : checklist prompt (STRICT JSON)
- prompts/judge_verify.txt      : judge/verification prompt (STRICT JSON)
- prompts/cwe_blurbs.json       : (optional) tiny CWE/API blurbs for retrieval
"""

from __future__ import annotations

import os
import csv
import json
import time
import argparse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Load .env silently if present (so OPENAI_API_KEY can live in .env without being committed)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# OpenAI Python SDK (Responses API)
from openai import OpenAI  # type: ignore


# --------------------------- Utility: Files & Templates ---------------------------

def load_text(path: str) -> str:
    """Read a UTF-8 text file and return its contents."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_json(path: str) -> Any:
    """Read a UTF-8 JSON file and return its parsed object. Returns {} on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# ----------------------------- Utility: JSON Parsing ------------------------------

def extract_first_json_block(text: str) -> Optional[str]:
    """
    Best-effort extraction: find the first top-level JSON object in a text blob.
    Returns the JSON string if found, else None.

    This is a light safeguard against models returning extra text around JSON,
    e.g., leading/trailing prose or code fences. We still instruct STRICT JSON, but
    this improves robustness without attempting to "repair" content.
    """
    if not text:
        return None

    start = text.find("{")
    if start == -1:
        return None

    # Track bracket depth to find matching closing brace
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i+1]
    return None


def parse_json_strict_or_best_effort(text: str) -> Tuple[Optional[dict], int]:
    """
    Try to parse JSON. First parse full text; if that fails, extract first JSON block.
    Returns (obj_or_None, parse_error_flag).
    """
    try:
        return json.loads(text), 0
    except Exception:
        pass

    block = extract_first_json_block(text)
    if block is None:
        return None, 1
    try:
        return json.loads(block), 0
    except Exception:
        return None, 1


# ------------------------------ Utility: OpenAI Calls ----------------------------

def call_model(client: OpenAI,
               model: str,
               prompt: str,
               temperature: float = 0.2,
               max_output_tokens: int = 400,
               max_retries: int = 3,
               retry_sleep: float = 1.0) -> str:
    """
    Call the OpenAI Responses API and return raw text output.
    Includes simple retry with backoff on transient errors.
    """
    last_err: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            resp = client.responses.create(
                model=model,
                input=prompt,
                temperature=temperature,
                max_output_tokens=max_output_tokens,
            )
            return resp.output_text
        except Exception as e:
            last_err = e
            time.sleep(retry_sleep * (2 ** attempt))
    # Surface the last error message in-band to help debugging
    return f'{{"error":"model_call_failed","detail":"{str(last_err)}"}}'


# ------------------------------- Prompt Construction -----------------------------

def attach_retrieval_blurb(code: str,
                           predicted_cwe: Optional[str],
                           blurb_map: Dict[str, str],
                           retrieval: str) -> str:
    """
    Optionally append a tiny CWE/API blurb to the code context.
    We keep this short to control token cost. Only attach if `retrieval == "on"`
    and a matching blurb is available for predicted_cwe.
    """
    if retrieval != "on":
        return ""
    if not predicted_cwe:
        return ""
    tip = blurb_map.get(predicted_cwe)
    if not tip:
        return ""
    return f"\n[Brief CWE context]\n{predicted_cwe}: {tip}\n"


# ----------------------------- Majority Vote (Self-Consistency) ------------------

def majority_vote(preds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Given a list of detector JSONs, return a single consensus dict:
    - vulnerable: majority vote (ties resolve to False)
    - predicted_cwe: most frequent non-null
    """
    from collections import Counter

    vulns = []
    cwes = []
    for p in preds:
        v = p.get("vulnerable", False)
        if isinstance(v, str):
            v = v.strip().lower() in ("true", "1", "yes", "y")
        elif isinstance(v, (int, float)):
            v = bool(v)
        elif not isinstance(v, bool):
            v = False
        vulns.append(v)

        c = p.get("predicted_cwe")
        if c:
            cwes.append(str(c).strip())

    vote_vuln = False
    if vulns:
        tally = Counter(vulns)
        if tally[True] > tally[False]:
            vote_vuln = True

    vote_cwe = None
    if cwes:
        vote_cwe = Counter(cwes).most_common(1)[0][0]

    return {"vulnerable": vote_vuln, "predicted_cwe": vote_cwe}


# -------------------------------------- Main -------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Run an LLM to detect vulns in code snippets.")
    parser.add_argument("--data", required=True, help="Path to CSV with columns: id,lang,code,label,cwe_id")
    parser.add_argument("--outdir", default="results/runs", help="Where to write JSONL outputs")
    parser.add_argument("--model", default="gpt-4.1-mini", help="OpenAI model name")
    parser.add_argument("--judge-model", default=None, help="Optional different model for judge pass")

    # Modes
    parser.add_argument("--mode",
                        default="checklist",
                        choices=["baseline", "checklist", "gen", "gen_judge"],
                        help="Detection strategy")
    parser.add_argument("--k", type=int, default=1, help="Self-consistency votes per item (k>=1)")

    # Prompts
    parser.add_argument("--detect-tmpl", default="prompts/detect_vuln.txt", help="Baseline/generator prompt file")
    parser.add_argument("--checklist-tmpl", default="prompts/detect_checklist.txt", help="Checklist prompt file")
    parser.add_argument("--judge-tmpl", default="prompts/judge_verify.txt", help="Judge prompt file")

    # Retrieval
    parser.add_argument("--retrieval", default="off", choices=["on", "off"], help="Attach tiny CWE/API blurbs")
    parser.add_argument("--blurbs", default="prompts/cwe_blurbs.json", help="JSON file with CWE blurbs")

    # Misc
    parser.add_argument("--sleep", type=float, default=0.2, help="Sleep between API calls (rate-limit friendliness)")
    parser.add_argument("--max-output-tokens", type=int, default=400, help="Max tokens in model outputs")

    args = parser.parse_args()

    # Initialize client
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set. Put it in your environment or a .env file.")

    client = OpenAI()

    # Ensure output dir exists
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Load prompts & blurbs
    detect_tmpl = load_text(args.detect_tmpl)
    checklist_tmpl = load_text(args.checklist_tmpl)
    judge_tmpl = load_text(args.judge_tmpl)
    blurb_map: Dict[str, str] = load_json(args.blurbs) if args.retrieval == "on" else {}

    # Prepare output file
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = outdir / f"run_{run_id}.jsonl"
    print(f"[run_inference] Writing to: {out_path}")

    # Helper to call detector once for a single mode
    def detect_once(code: str,
                    mode: str,
                    predicted_cwe_hint: Optional[str] = None) -> tuple[Dict[str, Any], str, int]:
        """
        Run one detector call, return (parsed_json, raw_text, parse_error_flag).
        - mode 'baseline' and 'gen' use the baseline template
        - mode 'checklist' uses the checklist template
        - predicted_cwe_hint is used to attach a tiny retrieval blurb (if enabled)
        """
        ctx = ""
        if args.retrieval == "on":
            ctx = attach_retrieval_blurb(code, predicted_cwe_hint, blurb_map, args.retrieval)

        if mode in ("baseline", "gen"):
            prompt = detect_tmpl.replace("{{CODE}}", code + ctx)
        elif mode == "checklist":
            prompt = checklist_tmpl.replace("{{CODE}}", code + ctx)
        else:
            raise ValueError("detect_once: invalid mode for single pass")

        raw = call_model(
            client,
            model=args.model,
            prompt=prompt,
            temperature=0.2,
            max_output_tokens=args.max_output_tokens,
        )
        parsed, p_err = parse_json_strict_or_best_effort(raw)
        parsed = parsed or {}
        return parsed, raw, p_err

    # CSV iteration
    total = 0
    with open(args.data, newline="", encoding="utf-8") as fin, open(out_path, "w", encoding="utf-8") as fout:
        reader = csv.DictReader(fin)
        for row in reader:
            total += 1
            row_id = row.get("id", f"row{total}")
            lang = row.get("lang", "") or ""
            code = row.get("code", "") or ""
            gold_label = row.get("label", "") or ""
            gold_cwe = row.get("cwe_id", "") or None
            if not code.strip():
                # Skip empty code rows, but still record a stub line
                record = {
                    "id": row_id,
                    "lang": lang,
                    "gold_label": gold_label,
                    "gold_cwe": gold_cwe,
                    "prompt_version": {
                        "mode": args.mode,
                        "model": args.model,
                        "judge_model": args.judge_model or args.model,
                        "detect_tmpl": args.detect_tmpl,
                        "checklist_tmpl": args.checklist_tmpl,
                        "judge_tmpl": args.judge_tmpl,
                        "retrieval": args.retrieval,
                        "blurbs": args.blurbs if args.retrieval == "on" else None,
                        "k": args.k,
                    },
                    "detect_output": {"vulnerable": False, "predicted_cwe": None},
                    "detect_samples": [],
                    "judge_output": None,
                    "raw_text": "",
                    "raw_judge_text": None,
                    "errors": {"detector_parse": 1, "judge_parse": 0},
                }
                fout.write(json.dumps(record) + "\n")
                continue

            # --- One-pass modes (baseline | checklist | gen) with optional self-consistency ---
            detect_samples: List[Dict[str, Any]] = []
            last_raw_text = ""
            det_parse_errors = 0

            if args.mode in ("baseline", "checklist", "gen"):
                for _ in range(max(1, args.k)):
                    det_parsed, raw_text, p_err = detect_once(code, args.mode, predicted_cwe_hint=None)
                    detect_samples.append(det_parsed)
                    last_raw_text = raw_text
                    det_parse_errors += p_err
                    time.sleep(args.sleep)
                det_final = majority_vote(detect_samples) if args.k > 1 else detect_samples[0]

                record = {
                    "id": row_id,
                    "lang": lang,
                    "gold_label": gold_label,
                    "gold_cwe": gold_cwe,
                    "prompt_version": {
                        "mode": args.mode,
                        "model": args.model,
                        "judge_model": args.judge_model or args.model,
                        "detect_tmpl": args.detect_tmpl,
                        "checklist_tmpl": args.checklist_tmpl,
                        "judge_tmpl": args.judge_tmpl,
                        "retrieval": args.retrieval,
                        "blurbs": args.blurbs if args.retrieval == "on" else None,
                        "k": args.k,
                    },
                    "detect_output": det_final,
                    "detect_samples": detect_samples if args.k > 1 else [],
                    "judge_output": None,
                    "raw_text": last_raw_text,
                    "raw_judge_text": None,
                    "errors": {"detector_parse": int(det_parse_errors > 0), "judge_parse": 0},
                }
                fout.write(json.dumps(record) + "\n")
                continue

            # --- Two-pass mode: gen_judge ---
            elif args.mode == "gen_judge":
                # 1) Generator pass (with self-consistency)
                gen_samples: List[Dict[str, Any]] = []
                gen_last_raw = ""
                gen_parse_errors = 0
                for _ in range(max(1, args.k)):
                    gen_parsed, gen_raw, gen_err = detect_once(code, "gen", predicted_cwe_hint=None)
                    gen_samples.append(gen_parsed)
                    gen_last_raw = gen_raw
                    gen_parse_errors += gen_err
                    time.sleep(args.sleep)

                gen_consensus = majority_vote(gen_samples) if args.k > 1 else gen_samples[0]

                # 2) Judge pass (may attach retrieval blurb if gen predicted a CWE)
                predicted_cwe_hint = gen_consensus.get("predicted_cwe")
                judge_ctx = ""
                if args.retrieval == "on":
                    judge_ctx = attach_retrieval_blurb(code, predicted_cwe_hint, blurb_map, args.retrieval)

                judge_prompt = (
                    judge_tmpl
                    .replace("{{CODE}}", code + judge_ctx)
                    .replace("{{GEN_JSON}}", json.dumps(gen_consensus, ensure_ascii=False))
                )

                judge_model = args.judge_model or args.model
                judge_raw = call_model(
                    client,
                    model=judge_model,
                    prompt=judge_prompt,
                    temperature=0.2,
                    max_output_tokens=min(args.max_output_tokens, 300),
                )
                judge_parsed, judge_err = parse_json_strict_or_best_effort(judge_raw)
                judge_parsed = judge_parsed or {}

                # Adopt judge override if "flip"
                det_final = dict(gen_consensus)
                if isinstance(judge_parsed, dict) and judge_parsed.get("judge_verdict") == "flip":
                    if "vulnerable" in judge_parsed:
                        det_final["vulnerable"] = judge_parsed["vulnerable"]
                    if "predicted_cwe" in judge_parsed:
                        det_final["predicted_cwe"] = judge_parsed["predicted_cwe"]

                record = {
                    "id": row_id,
                    "lang": lang,
                    "gold_label": gold_label,
                    "gold_cwe": gold_cwe,
                    "prompt_version": {
                        "mode": args.mode,
                        "model": args.model,
                        "judge_model": judge_model,
                        "detect_tmpl": args.detect_tmpl,
                        "checklist_tmpl": args.checklist_tmpl,
                        "judge_tmpl": args.judge_tmpl,
                        "retrieval": args.retrieval,
                        "blurbs": args.blurbs if args.retrieval == "on" else None,
                        "k": args.k,
                    },
                    "detect_output": det_final,           # final detector label (after judge)
                    "detect_samples": gen_samples if args.k > 1 else [],  # raw generator samples
                    "judge_output": judge_parsed,         # judge JSON (confirm/flip)
                    "raw_text": gen_last_raw,             # last generator raw text
                    "raw_judge_text": judge_raw,          # judge raw text
                    "errors": {
                        "detector_parse": int(gen_parse_errors > 0),
                        "judge_parse": int(judge_err > 0),
                    },
                }
                fout.write(json.dumps(record) + "\n")
                time.sleep(args.sleep)

            else:
                raise ValueError(f"Unsupported mode: {args.mode}")

    print(f"[run_inference] Done. Processed {total} rows.")
    print(f"[run_inference] Output: {out_path}")


if __name__ == "__main__":
    main()
