#!/bin/sh
set -e

# Detect Python command
if command -v python3 >/dev/null 2>&1; then
    PY_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PY_CMD="python"
else
    echo "[-] Error: Python is required to run the MAVERICK ML engine."
    exit 1
fi

echo "=================================================================="
echo " MAVERICK — Core Forensic Intelligence & ML Backend System"
echo " Smart India Hackathon 2026"
echo "=================================================================="

echo "[+] Initializing FastAPI ML threat prediction microservice on port 8000..."
$PY_CMD ml/predict.py --serve --port 8000 &
ML_PID=$!
echo "[+] ML Engine started in background (PID: $ML_PID)"

# Wait briefly for FastAPI initialization
sleep 2

echo "[+] Starting MAVERICK Intelligence Gateway on port ${PORT:-5000}..."
exec node server/server.js
