"""Configuração global: força backend gráfico headless antes dos imports Qt."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
