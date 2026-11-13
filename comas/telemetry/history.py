"""CSV prediction history with explicit construction and no service startup."""

import glob
import logging
import os
import threading
from datetime import datetime
from typing import Any, Dict, Optional, Tuple


logger = logging.getLogger("FlowPredictor")


class PredictionHistoryExporter:
    """
    Persistência incremental do histórico de predição — 1 CSV por série.

    Propriedades garantidas:
      - ADITIVA: chamada após o history.append(); nunca altera a lógica online.
      - SINCRONIZADA: cada linha corresponde exatamente a uma amostra da série
        (mesmo ts/observado/predito do deque e mesmo resíduo visto pelo detector).
      - INCREMENTAL: append-only; header escrito uma única vez por arquivo.
      - LEVE: file handles mantidos abertos em cache (1 open por série na vida
        do processo) com flush a cada EXPORT_FLUSH_EVERY linhas.
      - À PROVA DE FALHA: qualquer exceção de I/O é logada e a predição segue.

    Nome do arquivo: flow:1:10.0.0.1->10.0.0.4  ->  flow_1_10.0.0.1_10.0.0.4.csv
    """

    HEADER = ["timestamp", "datetime_iso", "flow_key", "dpid", "src_ip", "dst_ip",
              "observed_bps", "predicted_bps", "prediction_error", "absolute_error",
              "residual", "z_score", "is_anomaly"]

    def __init__(self, directory: str, prefixes: Tuple[str, ...] = ("flow:",),
                 flush_every: int = 10, enabled: bool = True):
        self.directory = directory
        self.prefixes = prefixes
        self.flush_every = max(1, flush_every)
        self.enabled = enabled
        self.records_written = 0
        self._files: Dict[str, Any] = {}      # key -> file handle (cache)
        self._pending: Dict[str, int] = {}    # key -> linhas desde o último flush
        self._lock = threading.Lock()
        if self.enabled:
            try:
                os.makedirs(self.directory, exist_ok=True)
                logger.info(f"Exporter ativo: dir={self.directory} "
                            f"prefixes={self.prefixes} flush_every={self.flush_every}")
            except OSError as e:
                logger.error(f"Exporter desabilitado (mkdir falhou): {e}")
                self.enabled = False

    @staticmethod
    def _filename_for(key: str) -> str:
        safe = key.replace("->", "_").replace(":", "_").replace("/", "_")
        return f"{safe}.csv"

    def record(self, key: str, meta: Dict[str, Any], ts: float,
               observed_bps: float, predicted_bps: float, residual: float,
               z_score: Optional[float], is_anomaly: bool) -> None:
        """Persiste UMA amostra. z_score=None (warm-up) é gravado como vazio."""
        if not self.enabled or not key.startswith(self.prefixes):
            return
        try:
            err = observed_bps - predicted_bps
            row = ",".join([
                f"{ts:.3f}",
                datetime.fromtimestamp(ts).isoformat(timespec="milliseconds"),
                key,
                str(meta.get("dpid", "")),
                str(meta.get("nw_src", "")),
                str(meta.get("nw_dst", "")),
                f"{observed_bps:.1f}",
                f"{predicted_bps:.1f}",
                f"{err:.1f}",
                f"{abs(err):.1f}",
                f"{residual:.1f}",
                ("" if z_score is None else f"{z_score:.4f}"),
                str(is_anomaly),
            ]) + "\n"

            with self._lock:
                fh = self._files.get(key)
                if fh is None:
                    path = os.path.join(self.directory, self._filename_for(key))
                    write_header = not os.path.exists(path) or os.path.getsize(path) == 0
                    fh = open(path, "a", buffering=8192)
                    if write_header:
                        fh.write(",".join(self.HEADER) + "\n")
                    self._files[key] = fh
                    self._pending[key] = 0
                fh.write(row)
                self._pending[key] += 1
                self.records_written += 1
                if self._pending[key] >= self.flush_every:
                    fh.flush()
                    self._pending[key] = 0
        except Exception as e:
            # I/O nunca pode derrubar o pipeline de predição
            logger.error(f"Exporter: falha ao gravar amostra de {key}: {e}")

    def status(self) -> Dict[str, Any]:
        with self._lock:
            n_disk = len(glob.glob(os.path.join(self.directory, "*.csv"))) \
                     if self.enabled and os.path.isdir(self.directory) else 0
            return {
                "enabled": self.enabled,
                "directory": self.directory,
                "files": n_disk,
                "series_active": len(self._files),
                "records_written": self.records_written,
                "prefixes": list(self.prefixes),
                "flush_every": self.flush_every,
            }

    def close(self) -> None:
        """Flush + close de todos os handles (registrado via atexit)."""
        with self._lock:
            for fh in self._files.values():
                try:
                    fh.flush()
                    fh.close()
                except Exception:
                    pass
            self._files.clear()
