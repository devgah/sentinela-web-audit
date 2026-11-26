# -*- mode: python ; coding: utf-8 -*-
"""Especificação PyInstaller para o Sentinela Web Audit."""

import os

SPEC_DIR = os.path.abspath(SPECPATH)
SRC_DIR = os.path.join(SPEC_DIR, "..", "src")
ENTRY = os.path.join(SRC_DIR, "sentinela", "ui", "app.py")
TEMPLATE = os.path.join(
    SRC_DIR, "sentinela", "reports", "templates", "report.html.j2"
)

a = Analysis(
    [ENTRY],
    pathex=[SRC_DIR],
    binaries=[],
    datas=[(TEMPLATE, os.path.join("sentinela", "reports", "templates"))],
    hiddenimports=[
        "sentinela.reports.html",
        "sentinela.reports.pdf",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "pytest"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sentinela-web-audit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="sentinela-web-audit",
)
