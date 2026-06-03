#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo ""
echo "  ╔═══════════════════════════════════╗"
echo "  ║  PROMET  Android RE  Web UI       ║"
echo "  ╚═══════════════════════════════════╝"
echo ""

if [ ! -d venv ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv venv
fi

source venv/bin/activate

echo "[*] Installing / checking dependencies..."
pip install -q -r requirements.txt

echo ""
echo "[*] Starting PROMET Web UI on http://localhost:8765"
echo "[*] Press Ctrl+C to stop."
echo ""

# Auto-open browser in background
(sleep 2 && xdg-open http://localhost:8765 2>/dev/null || open http://localhost:8765 2>/dev/null || true) &

python3 app.py
