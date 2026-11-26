"""Worker que executa a varredura fora da thread da interface."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from sentinela.core.errors import SentinelaError
from sentinela.scanner import run_scan


class ScanWorker(QObject):
    """Executa `run_scan` e publica o resultado por sinais tipados."""

    progress = Signal(str, int)
    finished = Signal(object)
    failed = Signal(str)
    done = Signal()

    def __init__(self, target: str, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._target = target

    @Slot()
    def run(self) -> None:
        """Executa a varredura e sinaliza conclusão, erro e encerramento."""
        try:
            report = run_scan(self._target, self._emit_progress)
        except SentinelaError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # noqa: BLE001 - isola a thread de falhas imprevistas
            self.failed.emit(f"Falha inesperada: {type(exc).__name__}.")
        else:
            self.finished.emit(report)
        finally:
            self.done.emit()

    def _emit_progress(self, message: str, percent: int) -> None:
        """Repassa o progresso para a thread da interface."""
        self.progress.emit(message, percent)
