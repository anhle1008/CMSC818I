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

## 4. Repository Layout
```bash
.
├─ data/
│  └─ tiny.csv                 # examples
├─ prompts/
│  ├─ detect_vuln.txt          # few-shot detection (STRICT JSON)
│  └─ classify_cwe.txt         # CWE classification (STRICT JSON)
├─ src/
│  ├─ run_inference.py         # runs model over CSV, saves JSONL
│  └─ evaluate.py              # Accuracy/Precision/Recall/F1 + CWE top-1
├─ results/
│  ├─ runs/                    # raw outputs (.jsonl)
│  └─ reports/                 # optional summaries/plots
└─ requirements.txt
└─ .env
```

## 5. Run
### 5.1 Inference (model → JSONL)
#### macOS/Linux
```bash
python3 src/run_inference.py --data data/tiny.csv --model gpt-4.1-mini
```
#### Windows (PowerShell)
```powershell
py -3 src/run_inference.py --data data/tiny.csv --model gpt-4.1-mini
```
This writes: `results/runs/run_YYYYMMDD-HHMMSS.jsonl`

### 5.2 Evaluate
#### macOS/Linux
```bash
python3 src/evaluate.py --run results/runs/run_YYYYMMDD-HHMMSS.jsonl
```
#### Windows
```powershell
py -3 src/evaluate.py --run results/runs/run_YYYYMMDD-HHMMSS.jsonl
```

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