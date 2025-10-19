# Prompting LLMs to Find Software Vulnerabilities

This is CMSC818I final project.

# Step 1: Set your key
export OPENAI_API_KEY=...

# Step 2: First run (produces JSONL outputs)
python3 src/run_inference.py --data data/tiny.csv --model gpt-4.1-mini

# Step 3: Evaluate
python3 src/evaluate.py --run results/runs/run_YYYYMMDD-HHMMSS.jsonl
