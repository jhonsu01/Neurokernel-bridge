#!/usr/bin/env bash
# LinuxIAKernel - Launcher
# Uso: sudo ./run.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Requiere root. Ejecuta: sudo ./run.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

exec python3 -m execution.orchestrator.main "$@"
