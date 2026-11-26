#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."
python -m PyInstaller --noconfirm --clean packaging/sentinela-web-audit.spec
