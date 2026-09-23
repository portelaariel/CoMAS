#!/usr/bin/env python3
"""Telemetria de QoS por porta para calibração de previsão de SLA.

As capacidades são obrigatoriamente declaradas por ``dpid:port``. Contadores
OpenFlow cumulativos são convertidos em taxas direcionais; a utilização de um
enlace full-duplex é o maior valor entre RX e TX dividido pela capacidade de
uma direção. Lacunas e resets são persistidos explicitamente como amostras
inválidas e nunca viram taxas artificiais.
"""

from __future__ import annotations

import csv
import json
import math
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


QOS_TELEMETRY_SCHEMA_VERSION = 1
VALID_QUALITY = {
    "PRIMING",
    "VALID",
    "COUNTER_RESET",
    "MISSING_INTERVAL",
    "NON_MONOTONIC_TIMESTAMP",
}


def _finite_positive(value: Any, name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} deve ser numérico") from exc
    if not math.isfinite(parsed) or parsed <= 0.0:
        raise ValueError(f"{name} deve ser positivo e finito")
    return parsed


def _non_negative_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} deve ser inteiro não negativo")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} deve ser inteiro não negativo") from exc
    if parsed != value or parsed < 0:
        raise ValueError(f"{name} deve ser inteiro não negativo")
    return parsed


def port_identity(dpid: Any, port_no: Any) -> str:
    parsed_dpid = _non_negative_int(dpid, "dpid")
    parsed_port = _non_negative_int(port_no, "port_no")
    return f"{parsed_dpid}:{parsed_port}"


class PortCapacityRegistry:
    """Mapa estrito de capacidades direcionais, em bits por segundo."""

    def __init__(self, capacities: Dict[str, Any]):
        if not isinstance(capacities, dict):
            raise ValueError("capacidades de porta devem ser um objeto JSON")
        parsed: Dict[str, float] = {}
        for raw_key, raw_value in capacities.items():
            if not isinstance(raw_key, str) or raw_key.count(":") != 1:
                raise ValueError("cada capacidade deve usar a chave dpid:port")
            raw_dpid, raw_port = raw_key.split(":", 1)
            if not raw_dpid.isdigit() or not raw_port.isdigit():
                raise ValueError("dpid e port da capacidade devem ser decimais")
            key = port_identity(int(raw_dpid), int(raw_port))
            if key in parsed:
                raise ValueError(f"capacidade duplicada para {key}")
            parsed[key] = _finite_positive(raw_value, f"capacity[{key}]")
        self._capacities = parsed

    @classmethod
    def from_json(cls, payload: str) -> "PortCapacityRegistry":
        try:
            decoded = json.loads(payload or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"QOS_PORT_CAPACITIES_JSON inválido: {exc}") from exc
        return cls(decoded)

    def get(self, dpid: Any, port_no: Any) -> Optional[float]:
        return self._capacities.get(port_identity(dpid, port_no))

    def status(self) -> Dict[str, Any]:
        return {
            "configured_ports": len(self._capacities),
            "port_ids": sorted(self._capacities),
        }

    def __bool__(self) -> bool:
        return bool(self._capacities)


class PortCounterSeries:
    """Converte uma sequência de contadores de uma porta em utilização."""

    def __init__(self, *, cid: str, dpid: int, port_no: int,
                 capacity_bps: float, max_gap_s: float):
        self.cid = str(cid)
        self.dpid = _non_negative_int(dpid, "dpid")
        self.port_no = _non_negative_int(port_no, "port_no")
        self.port_id = port_identity(self.dpid, self.port_no)
        self.capacity_bps = _finite_positive(capacity_bps, "capacity_bps")
        self.max_gap_s = _finite_positive(max_gap_s, "max_gap_s")
        self.last_rx_bytes: Optional[int] = None
        self.last_tx_bytes: Optional[int] = None
        self.last_ts_ns: Optional[int] = None

    def ingest(self, *, rx_bytes: Any, tx_bytes: Any, ts_ns: Any) -> Dict[str, Any]:
        rx = _non_negative_int(rx_bytes, "rx_bytes")
        tx = _non_negative_int(tx_bytes, "tx_bytes")
        timestamp_ns = _non_negative_int(ts_ns, "ts_ns")
        if timestamp_ns == 0:
            raise ValueError("ts_ns deve ser positivo")

        previous = (self.last_rx_bytes, self.last_tx_bytes, self.last_ts_ns)
        self.last_rx_bytes = rx
        self.last_tx_bytes = tx
        self.last_ts_ns = timestamp_ns

        sample = {
            "schema_version": QOS_TELEMETRY_SCHEMA_VERSION,
            "cid": self.cid,
            "ts_ns": timestamp_ns,
            "timestamp_iso": datetime.fromtimestamp(
                timestamp_ns / 1e9, tz=timezone.utc
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "dpid": self.dpid,
            "port_no": self.port_no,
            "port_id": self.port_id,
            "capacity_bps": self.capacity_bps,
            "rx_bytes": rx,
            "tx_bytes": tx,
            "delta_rx_bytes": None,
            "delta_tx_bytes": None,
            "interval_s": None,
            "rx_bps": None,
            "tx_bps": None,
            "aggregate_bps": None,
            "utilization_ratio": None,
            "quality": "PRIMING",
            "valid": False,
            "above_capacity": None,
        }
        if previous[2] is None:
            return sample

        previous_rx, previous_tx, previous_ts_ns = previous
        delta_ns = timestamp_ns - int(previous_ts_ns)
        if delta_ns <= 0:
            sample["quality"] = "NON_MONOTONIC_TIMESTAMP"
            return sample
        interval_s = delta_ns / 1e9
        sample["interval_s"] = round(interval_s, 9)
        if interval_s > self.max_gap_s:
            sample["quality"] = "MISSING_INTERVAL"
            return sample

        delta_rx = rx - int(previous_rx)
        delta_tx = tx - int(previous_tx)
        sample["delta_rx_bytes"] = delta_rx
        sample["delta_tx_bytes"] = delta_tx
        if delta_rx < 0 or delta_tx < 0:
            sample["quality"] = "COUNTER_RESET"
            return sample

        rx_bps = delta_rx * 8.0 / interval_s
        tx_bps = delta_tx * 8.0 / interval_s
        aggregate_bps = rx_bps + tx_bps
        utilization = max(rx_bps, tx_bps) / self.capacity_bps
        sample.update({
            "rx_bps": round(rx_bps, 6),
            "tx_bps": round(tx_bps, 6),
            "aggregate_bps": round(aggregate_bps, 6),
            "utilization_ratio": round(utilization, 9),
            "quality": "VALID",
            "valid": True,
            "above_capacity": utilization > 1.0,
        })
        return sample


class QosDatasetExporter:
    """CSV append-only que preserva amostras válidas e marcadores de falha."""

    HEADER = [
        "schema_version", "cid", "ts_ns", "timestamp_iso", "dpid",
        "port_no", "port_id", "capacity_bps", "rx_bytes", "tx_bytes",
        "delta_rx_bytes", "delta_tx_bytes", "interval_s", "rx_bps",
        "tx_bps", "aggregate_bps", "utilization_ratio", "quality",
        "valid", "above_capacity",
    ]

    def __init__(self, directory: str, *, flush_every: int = 10):
        self.directory = Path(directory)
        self.flush_every = int(flush_every)
        if self.flush_every < 1:
            raise ValueError("flush_every deve ser positivo")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "port_utilization.csv"
        self._lock = threading.Lock()
        self._file = None
        self._writer = None
        self._pending = 0
        self.records_written = 0

    def _ensure_open(self) -> None:
        if self._file is not None:
            return
        write_header = not self.path.exists() or self.path.stat().st_size == 0
        self._file = self.path.open("a", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(
            self._file, fieldnames=self.HEADER, extrasaction="raise"
        )
        if write_header:
            self._writer.writeheader()

    def record(self, sample: Dict[str, Any]) -> None:
        if set(sample) != set(self.HEADER):
            raise ValueError("amostra QoS diverge do schema CSV")
        if sample.get("quality") not in VALID_QUALITY:
            raise ValueError("quality de amostra QoS inválida")
        with self._lock:
            self._ensure_open()
            self._writer.writerow({
                key: "" if sample[key] is None else sample[key]
                for key in self.HEADER
            })
            self.records_written += 1
            self._pending += 1
            if self._pending >= self.flush_every:
                self._file.flush()
                self._pending = 0

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.flush()
                self._file.close()
                self._file = None
                self._writer = None

    def status(self) -> Dict[str, Any]:
        return {
            "directory": str(self.directory),
            "file": str(self.path),
            "records_written": self.records_written,
        }


class QosTelemetryManager:
    """Aplica capacidades, mantém séries por porta e persiste o dataset."""

    def __init__(self, *, cid: str, capacities: PortCapacityRegistry,
                 max_gap_s: float, exporter: QosDatasetExporter):
        if not capacities:
            raise ValueError("telemetria QoS requer ao menos uma capacidade explícita")
        self.cid = str(cid)
        self.capacities = capacities
        self.max_gap_s = _finite_positive(max_gap_s, "max_gap_s")
        self.exporter = exporter
        self.series: Dict[str, PortCounterSeries] = {}
        self.latest: Dict[str, Dict[str, Any]] = {}
        self.samples_seen = 0
        self.valid_samples = 0
        self.invalid_samples = 0
        self.unconfigured_samples = 0
        self._lock = threading.Lock()

    def ingest(self, *, dpid: Any, port_no: Any, rx_bytes: Any,
               tx_bytes: Any, ts_ns: Any) -> Optional[Dict[str, Any]]:
        capacity = self.capacities.get(dpid, port_no)
        if capacity is None:
            with self._lock:
                self.unconfigured_samples += 1
            return None
        key = port_identity(dpid, port_no)
        with self._lock:
            series = self.series.get(key)
            if series is None:
                series = PortCounterSeries(
                    cid=self.cid,
                    dpid=int(dpid),
                    port_no=int(port_no),
                    capacity_bps=capacity,
                    max_gap_s=self.max_gap_s,
                )
                self.series[key] = series
            sample = series.ingest(
                rx_bytes=rx_bytes, tx_bytes=tx_bytes, ts_ns=ts_ns
            )
            self.latest[key] = sample
            self.samples_seen += 1
            if sample["valid"]:
                self.valid_samples += 1
            else:
                self.invalid_samples += 1
        self.exporter.record(sample)
        return sample

    def close(self) -> None:
        self.exporter.close()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            latest = [dict(self.latest[key]) for key in sorted(self.latest)]
            counts = {
                "samples_seen": self.samples_seen,
                "valid_samples": self.valid_samples,
                "invalid_samples": self.invalid_samples,
                "unconfigured_samples": self.unconfigured_samples,
                "active_series": len(self.series),
            }
        return {
            "enabled": True,
            "schema_version": QOS_TELEMETRY_SCHEMA_VERSION,
            "max_gap_s": self.max_gap_s,
            **self.capacities.status(),
            **counts,
            "dataset": self.exporter.status(),
            "latest": latest,
        }
