"""Diálogo obrigatório de uso responsável exibido ao iniciar."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sentinela.reports.models import DISCLAIMER


class ResponsibleUseDialog(QDialog):
    """Solicita confirmação explícita antes de liberar a interface."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Aviso de uso responsável")
        self.setModal(True)
        self.resize(640, 440)

        layout = QVBoxLayout(self)
        introduction = QLabel(
            "O Sentinela Web Audit realiza apenas análise passiva e local. "
            "Use a ferramenta somente em domínios que você possui ou para os "
            "quais possui autorização por escrito."
        )
        introduction.setWordWrap(True)

        details = QTextBrowser()
        details.setPlainText(DISCLAIMER)
        details.setReadOnly(True)
        details.setOpenExternalLinks(False)

        self._agreement = QCheckBox(
            "Li e aceito usar esta ferramenta apenas em alvos próprios ou "
            "expressamente autorizados."
        )

        buttons = QDialogButtonBox()
        self._continue = buttons.addButton(QDialogButtonBox.StandardButton.Ok)
        self._continue.setText("Continuar")
        self._continue.setEnabled(False)
        leave = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        leave.setText("Sair")

        layout.addWidget(introduction)
        layout.addWidget(details)
        layout.addWidget(self._agreement)
        layout.addWidget(buttons)

        self._agreement.toggled.connect(self._continue.setEnabled)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
