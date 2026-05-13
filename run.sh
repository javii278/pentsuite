#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
    echo "[*] Creando entorno virtual..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -q -r requirements.txt
    echo "[+] Dependencias instaladas."
else
    source venv/bin/activate
    # Actualizar dependencias si requirements.txt cambió
    pip install -q -r requirements.txt 2>/dev/null || true
fi

echo "[*] PentestSuite arrancando en http://localhost:5000"
python3 app.py
