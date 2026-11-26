"""Ponto de entrada da interface desktop do Sentinela Web Audit."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QDialog

from sentinela.ui.dialogs import ResponsibleUseDialog
from sentinela.ui.main_window import MainWindow


def main() -> int:
    """Exibe o aviso de uso responsável e inicia a aplicação."""
    app = QApplication(sys.argv)
    app.setApplicationName("Sentinela Web Audit")
    app.setApplicationDisplayName("Sentinela Web Audit")

    dialog = ResponsibleUseDialog()
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return 0

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
