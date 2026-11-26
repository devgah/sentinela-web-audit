"""Testes headless da interface, sem acesso à rede."""

from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication, QPushButton

from sentinela.core.models import Severity
from sentinela.reports.models import ScanReport
from sentinela.ui import MainWindow, ResponsibleUseDialog
from tests.factories import make_finding


@pytest.fixture(scope="module")
def app() -> QApplication:
    """Reutiliza uma única aplicação Qt para os testes do módulo."""
    return QApplication.instance() or QApplication([])


def test_dialogo_exige_confirmacao(app: QApplication) -> None:
    dialog = ResponsibleUseDialog()
    button = next(
        control
        for control in dialog.findChildren(QPushButton)
        if control.text() == "Continuar"
    )
    assert not button.isEnabled()
    dialog._agreement.setChecked(True)
    assert button.isEnabled()


def test_tabela_ordena_e_mostra_detalhes(app: QApplication) -> None:
    report = ScanReport(
        target="https://exemplo.test/",
        findings=(
            make_finding(code="b.low", severity=Severity.LOW, title="Baixo"),
            make_finding(code="a.high", severity=Severity.HIGH, title="Alto"),
        ),
    )
    window = MainWindow()
    window._populate_table(report)

    assert window._table.rowCount() == 2
    assert window._table.item(0, 0).text() == "Alto"
    window._table.selectRow(0)
    assert "[a.high]" in window._details.toPlainText()
    window.close()
