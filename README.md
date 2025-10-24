# Prompting LLMs to Find Software Vulnerabilities

A simple, cross-platform pipeline to check if LLMs can detect code vulnerabilities and (optionally) predict CWE IDs.

- No GPUs or compilers needed
- Works on macOS, Linux, and Windows
- Uses only Python + OpenAI API

## 1. Prerequisites
- **Python** 3.9–3.12
- **OpenAI API key** (access to a GPT-4–class model, e.g. `gpt-4.1-mini`)

## 2. Install
### 2.1 Clone
```bash
git clone <your-repo-url> vuln-repo
cd vuln-repo
```
### 2.2 Create a virtual environment
#### macOS/Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```
#### Windows (PowerShell)
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```
### 2.3 Install dependencies
#### macOS/Linux
```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```
#### Windows
```powershell
py -3 -m pip install --upgrade pip
py -3 -m pip install -r requirements.txt
```

## 3. Set API Key (do not commit it)
### 3.1 Option A (recommended): .env file
Create a file named `.env` in the repo root: `OPENAI_API_KEY=sk-...`

Ensure it’s ignored by git. Add to `.gitignore`: `.env`
### 3.2 Option B: environment variable
#### macOS/Linux
```bash
export OPENAI_API_KEY="sk-..."
```
#### Windows
```powershell
$Env:OPENAI_API_KEY="sk-..."
```

## 4. Run

The script supports several modes via `--mode`:
- `baseline` : single-pass with `prompts/detect_vuln.txt`
- `checklist`: single-pass structured JSON with `prompts/detect_checklist.txt`
- `gen` : generator-only (same template as baseline)
- `gen_judge`: two-pass (generator → judge) with `prompts/judge_verify.txt`

**Common flags**
- `--k` self-consistency votes per item (majority vote), default `1`
- `--retrieval` on|off attach short CWE/API blurbs (default `off`)
- `--blurbs` path to JSON blurb map (default `prompts/cwe_blurbs.json`)
- `--judge-model` optional different model for judge pass
- `--max-output-tokens` cap model output tokens (default `400`)

### 4.1 Examples
#### macOS/Linux
```bash
# Baseline
python3 src/run_inference.py --data data/tiny.csv --mode baseline --model gpt-4.1-mini
# Checklist (recommended)
python3 src/run_inference.py --data data/tiny.csv --mode checklist --model gpt-4.1-mini
# Generator → Judge (two-pass)
python3 src/run_inference.py --data data/tiny.csv --mode gen_judge --model gpt-4.1-mini
# Self-consistency (k=5) with checklist
python3 src/run_inference.py --data data/tiny.csv --mode checklist --k 5 --model gpt-4.1-mini
# With lightweight retrieval (tiny CWE blurbs)
python3 src/run_inference.py --data data/tiny.csv --mode checklist --retrieval on --model gpt-4.1-mini
```
#### Windows
```powershell
# Baseline
py -3 src/run_inference.py --data data/tiny.csv --mode baseline --model gpt-4.1-mini
# Checklist
py -3 src/run_inference.py --data data/tiny.csv --mode checklist --model gpt-4.1-mini
# Generator → Judge
py -3 src/run_inference.py --data data/tiny.csv --mode gen_judge --model gpt-4.1-mini
# Self-consistency (k=5)
py -3 src/run_inference.py --data data/tiny.csv --mode checklist --k 5 --model gpt-4.1-mini
# Retrieval on
py -3 src/run_inference.py --data data/tiny.csv --mode checklist --retrieval on --model gpt-4.1-mini
```

**Output file**

A timestamped JSONL in results/runs/, e.g.: `results/runs/run_YYYYMMDD-HHMMSS.jsonl` 

## 5. Evaluate
#### macOS/Linux
```bash
python3 src/evaluate.py --run results/runs/run_YYYYMMDD-HHMMSS.jsonl
```

#### Windows
```powershell
py -3 src/evaluate.py --run results/runs/run_YYYYMMDD-HHMMSS.jsonl
```

**Printed metrics**:
- **Vulnerability detection**: Accuracy, Precision, Recall, F1
- **CWE classification**: Top-1 Accuracy (on gold-vulnerable items)
- `evaluate.py` automatically uses the judge-adjusted label if `gen_judge` was used.

## 6. Troubleshooting
- Windows venv activation policy
If you see an execution policy error in PowerShell, run (once):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then: 
```powershell
.\.venv\Scripts\Activate.ps1
```
- API key not found
Ensure .env has OPENAI_API_KEY=... or set the env var in the same terminal.