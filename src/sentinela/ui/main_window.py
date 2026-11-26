"""Janela principal da auditoria passiva local."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sentinela.core.models import Finding, Severity
from sentinela.reports.exporter import ReportFormat, export_report
from sentinela.reports.models import DISCLAIMER, RISK_BY_SEVERITY, STATUS_LABELS, ScanReport
from sentinela.ui.worker import ScanWorker

_SUFFIXES: dict[ReportFormat, str] = {
    ReportFormat.MARKDOWN: ".md",
    ReportFormat.HTML: ".html",
    ReportFormat.PDF: ".pdf",
}

_FILTERS: dict[ReportFormat, str] = {
    ReportFormat.MARKDOWN: "Markdown (*.md)",
    ReportFormat.HTML: "HTML (*.html)",
    ReportFormat.PDF: "PDF (*.pdf)",
}


class MainWindow(QMainWindow):
    """Interface com execução em segundo plano e exportação local."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sentinela Web Audit — auditoria passiva local")
        self.resize(1000, 680)
        self._report: ScanReport | None = None
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._visible_findings: tuple[Finding, ...] = ()
        self._build_ui()

    def _build_ui(self) -> None:
        """Monta os controles da janela principal."""
        central = QWidget(self)
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Alvo (URL):"))
        self._url = QLineEdit()
        self._url.setPlaceholderText("https://exemplo.com")
        self._url.returnPressed.connect(self.start_scan)
        target_row.addWidget(self._url, 1)
        self._analyze_button = QPushButton("Analisar")
        self._analyze_button.clicked.connect(self.start_scan)
        target_row.addWidget(self._analyze_button)
        layout.addLayout(target_row)

        notice = QLabel(
            "Análise 100% local e passiva — sem exploração, payloads, força bruta "
            "ou envio de dados."
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)

        progress_row = QHBoxLayout()
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._status = QLabel("Pronto para analisar.")
        progress_row.addWidget(self._progress, 1)
        progress_row.addWidget(self._status)
        layout.addLayout(progress_row)

        summary_box = QGroupBox("Resumo")
        summary_layout = QHBoxLayout(summary_box)
        self._summary = QLabel("Nenhuma análise executada.")
        self._summary.setWordWrap(True)
        summary_layout.addWidget(self._summary)
        layout.addWidget(summary_box)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(
            ["Severidade", "Código", "Título", "Status"]
        )
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.itemSelectionChanged.connect(self._show_selected_finding)
        layout.addWidget(self._table, 1)

        self._details = QTextBrowser()
        self._details.setReadOnly(True)
        self._details.setOpenExternalLinks(False)
        self._details.setMaximumHeight(150)
        self._details.setPlainText("Selecione um achado para ver os detalhes.")
        layout.addWidget(self._details)

        export_row = QHBoxLayout()
        self._format = QComboBox()
        self._format.addItem("Markdown (.md)", ReportFormat.MARKDOWN)
        self._format.addItem("HTML (.html)", ReportFormat.HTML)
        self._format.addItem("PDF (.pdf)", ReportFormat.PDF)
        self._export_button = QPushButton("Exportar relatório...")
        self._export_button.setEnabled(False)
        self._export_button.clicked.connect(self.export_report_clicked)
        self._disclaimer_button = QPushButton("Ver aviso legal")
        self._disclaimer_button.clicked.connect(self.show_disclaimer)
        export_row.addWidget(QLabel("Formato:"))
        export_row.addWidget(self._format)
        export_row.addWidget(self._export_button)
        export_row.addStretch(1)
        export_row.addWidget(self._disclaimer_button)
        layout.addLayout(export_row)

    def start_scan(self) -> None:
        """Inicia uma varredura passiva em uma thread separada."""
        if self._thread is not None and self._thread.isRunning():
            return

        target = self._url.text().strip()
        if not target:
            QMessageBox.warning(self, "Alvo obrigatório", "Informe uma URL para analisar.")
            return

        self._report = None
        self._visible_findings = ()
        self._table.setRowCount(0)
        self._details.setPlainText("Selecione um achado para ver os detalhes.")
        self._summary.setText("Analisando...")
        self._status.setText("Iniciando análise passiva...")
        self._progress.setValue(0)
        self._export_button.setEnabled(False)
        self._analyze_button.setEnabled(False)

        thread = QThread(self)
        worker = ScanWorker(target)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(self._on_scan_finished)
        worker.failed.connect(self._on_scan_failed)
        worker.done.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._on_thread_finished)

        self._thread = thread
        self._worker = worker
        thread.start()

    @Slot(str, int)
    def _on_progress(self, message: str, percent: int) -> None:
        """Atualiza barra e status com o progresso informado pelo worker."""
        self._status.setText(message)
        self._progress.setValue(max(0, min(100, percent)))

    @Slot(object)
    def _on_scan_finished(self, result: object) -> None:
        """Recebe o relatório concluído e preenche a interface."""
        if not isinstance(result, ScanReport):
            self._on_scan_failed("Resultado inesperado da análise.")
            return

        self._report = result
        self._populate_table(result)
        self._update_summary(result)
        self._status.setText("Análise concluída.")
        self._progress.setValue(100)
        self._export_button.setEnabled(True)

    @Slot(str)
    def _on_scan_failed(self, message: str) -> None:
        """Mostra falhas esperadas sem interromper a aplicação."""
        self._status.setText("Falha na análise.")
        QMessageBox.warning(self, "Não foi possível concluir", message)

    @Slot()
    def _on_thread_finished(self) -> None:
        """Libera os controles após o encerramento da thread."""
        self._analyze_button.setEnabled(True)
        thread = self.sender()
        if isinstance(thread, QThread):
            thread.deleteLater()
        self._thread = None
        self._worker = None

    def _populate_table(self, report: ScanReport) -> None:
        """Preenche a tabela com os achados já ordenados por severidade."""
        ordered = [
            finding
            for _, group in report.findings_by_severity
            for finding in group
        ]
        self._visible_findings = tuple(ordered)
        self._table.setRowCount(0)
        for row, finding in enumerate(ordered):
            self._table.insertRow(row)
            values = (
                finding.severity.label,
                finding.code,
                finding.title,
                STATUS_LABELS.get(finding.status, finding.status),
            )
            for column, value in enumerate(values):
                self._table.setItem(row, column, QTableWidgetItem(value))
        self._table.resizeColumnsToContents()

    def _update_summary(self, report: ScanReport) -> None:
        """Exibe metadados e contagem por severidade."""
        counts = report.counts_by_severity
        pieces = " | ".join(
            f"{severity.label}: {counts[severity]}"
            for severity in sorted(
                Severity, key=lambda item: item.rank, reverse=True
            )
        )
        self._summary.setText(
            f"Alvo: {report.target} | Gerado em: {report.formatted_generated_at} | "
            f"Risco geral: {report.risk_label} | Total: {report.total_findings}\n"
            f"{pieces}"
        )

    @Slot()
    def _show_selected_finding(self) -> None:
        """Mostra os detalhes do achado selecionado como texto simples."""
        row = self._table.currentRow()
        if row < 0 or row >= len(self._visible_findings):
            return
        finding = self._visible_findings[row]
        lines = [
            f"[{finding.code}] {finding.title}",
            f"Severidade: {finding.severity.label}",
            f"Status: {STATUS_LABELS.get(finding.status, finding.status)}",
            f"Risco: {RISK_BY_SEVERITY[finding.severity]}",
            f"Diagnóstico: {finding.message}",
        ]
        if finding.evidence:
            lines.append(f"Evidência: {finding.evidence}")
        lines.append(f"Remediação: {finding.remediation}")
        references = "; ".join(finding.references) if finding.references else "-"
        lines.append(f"Referências: {references}")
        self._details.setPlainText("\n".join(lines))

    def _current_format(self) -> ReportFormat:
        """Retorna o formato selecionado na interface."""
        chosen = self._format.currentData()
        return chosen if isinstance(chosen, ReportFormat) else ReportFormat.MARKDOWN

    def export_report_clicked(self) -> None:
        """Grava o relatório no caminho escolhido pelo usuário."""
        if self._report is None:
            return

        chosen = self._current_format()
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar relatório",
            f"relatorio{_SUFFIXES[chosen]}",
            ";;".join(_FILTERS.values()),
        )
        if not path:
            return

        target = Path(path)
        try:
            selected = ReportFormat.from_suffix(target.suffix)
        except ValueError:
            selected = chosen
            target = target.with_suffix(_SUFFIXES[chosen])

        try:
            written = export_report(self._report, target, selected)
        except OSError as exc:
            QMessageBox.critical(
                self, "Erro ao exportar", f"Falha ao gravar: {type(exc).__name__}."
            )
            return

        self._status.setText(f"Relatório exportado: {written.name}")
        QMessageBox.information(
            self, "Exportação concluída", f"Arquivo salvo em:\n{written}"
        )

    def show_disclaimer(self) -> None:
        """Reexibe o aviso legal sem exigir nova confirmação."""
        QMessageBox.information(self, "Aviso legal", DISCLAIMER)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Encerra a thread de varredura antes de fechar a janela."""
        if self._thread is not None and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(3000)
        super().closeEvent(event)
