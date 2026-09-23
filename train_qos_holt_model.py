#!/usr/bin/env python3
"""Train and evaluate a multi-horizon Holt QoS artifact from a manifest."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from qos_holt import train_qos_holt_model


MANIFEST_SCHEMA = "comas-qos-holt-training/1"
VALIDATION_SCOPES = {
    "pilot_single_run_temporal_split",
    "independent_run_holdout",
}
SPLITS = ("train", "calibration", "test")


def _grid(raw: str, name: str, *, allow_zero: bool) -> List[float]:
    try:
        values = sorted({float(item.strip()) for item in raw.split(",") if item.strip()})
    except ValueError as exc:
        raise ValueError(f"{name} contém valor não numérico") from exc
    lower = 0.0 if allow_zero else 1e-12
    if (not values or any(
        not math.isfinite(value) or value < lower or value > 1.0
        for value in values
    )):
        raise ValueError(f"{name} contém valor fora do intervalo permitido")
    return values


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _optional_ns(raw: Any, name: str) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError(f"{name} deve ser inteiro positivo")
    try:
        parsed = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} deve ser inteiro positivo") from exc
    if parsed <= 0:
        raise ValueError(f"{name} deve ser inteiro positivo")
    return parsed


def _split_on_invalid_or_gap(
    path: Path, *, cid: str, port_id: str, start_ns: Optional[int],
    end_ns: Optional[int], maximum_gap_ns: int, minimum_length: int,
) -> Tuple[List[List[float]], Dict[str, Any]]:
    sequences: List[List[float]] = []
    current: List[float] = []
    previous_ns: Optional[int] = None
    selected = invalid = gap_breaks = 0

    def finish() -> None:
        nonlocal current
        if len(current) >= minimum_length:
            sequences.append(current)
        current = []

    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"cid", "ts_ns", "port_id", "utilization_ratio", "quality"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"CSV QoS sem colunas obrigatórias: {path}")
        for row in reader:
            if row["cid"] != cid or row["port_id"] != port_id:
                continue
            timestamp = int(row["ts_ns"])
            if start_ns is not None and timestamp < start_ns:
                continue
            if end_ns is not None and timestamp >= end_ns:
                continue
            selected += 1
            if row["quality"] != "VALID" or not row["utilization_ratio"].strip():
                invalid += 1
                finish()
                previous_ns = None
                continue
            if previous_ns is not None:
                delta = timestamp - previous_ns
                if delta <= 0 or delta > maximum_gap_ns:
                    gap_breaks += 1
                    finish()
            value = float(row["utilization_ratio"])
            if not math.isfinite(value) or value < 0.0:
                raise ValueError(f"utilização inválida em {path}: {value!r}")
            current.append(value)
            previous_ns = timestamp
    finish()
    return sequences, {
        "selected_rows": selected,
        "invalid_rows": invalid,
        "gap_breaks": gap_breaks,
        "usable_sequences": len(sequences),
        "usable_samples": sum(len(sequence) for sequence in sequences),
    }


def _validate_no_cross_split_overlap(entries: Sequence[Dict[str, Any]]) -> None:
    normalized: List[Tuple[Tuple[str, str, str], str, float, float]] = []
    for entry in entries:
        key = (str(entry["resolved_csv"]), entry["cid"], entry["port_id"])
        start = float("-inf") if entry["start_ns"] is None else entry["start_ns"]
        end = float("inf") if entry["end_ns"] is None else entry["end_ns"]
        if start >= end:
            raise ValueError("start_ns deve preceder end_ns")
        normalized.append((key, entry["split"], start, end))
    for index, left in enumerate(normalized):
        for right in normalized[index + 1:]:
            if left[0] != right[0] or left[1] == right[1]:
                continue
            if max(left[2], right[2]) < min(left[3], right[3]):
                raise ValueError(
                    "partições temporais se sobrepõem para a mesma série: "
                    f"{left[0]} ({left[1]} e {right[1]})"
                )


def load_manifest(
    path: Path,
) -> Tuple[Dict[str, Any], Dict[str, List[List[float]]], Dict[str, Any]]:
    manifest_path = path.resolve()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError(f"manifesto deve usar schema_version {MANIFEST_SCHEMA}")
    scope = payload.get("validation_scope")
    if scope not in VALIDATION_SCOPES:
        raise ValueError(f"validation_scope inválido: {scope!r}")
    sample_interval_s = float(payload.get("sample_interval_s"))
    if not math.isfinite(sample_interval_s) or sample_interval_s <= 0.0:
        raise ValueError("sample_interval_s deve ser positivo")
    raw_entries = payload.get("series")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ValueError("series deve ser uma lista não vazia")

    entries: List[Dict[str, Any]] = []
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise ValueError("cada entrada de series deve ser um objeto")
        split = str(raw.get("split", ""))
        cid = str(raw.get("cid", "")).strip()
        port_id = str(raw.get("port_id", "")).strip()
        series_id = str(raw.get("series_id", f"series-{index}")).strip()
        if split not in SPLITS or not cid or not port_id or not series_id:
            raise ValueError("split, cid, port_id e series_id são obrigatórios")
        csv_path = Path(str(raw.get("csv", ""))).expanduser()
        if not csv_path.is_absolute():
            csv_path = manifest_path.parent / csv_path
        csv_path = csv_path.resolve()
        if not csv_path.is_file():
            raise ValueError(f"CSV não encontrado: {csv_path}")
        entries.append({
            "split": split,
            "cid": cid,
            "port_id": port_id,
            "series_id": series_id,
            "resolved_csv": csv_path,
            "start_ns": _optional_ns(raw.get("start_ns"), "start_ns"),
            "end_ns": _optional_ns(raw.get("end_ns"), "end_ns"),
        })
    _validate_no_cross_split_overlap(entries)

    horizons = [int(item) for item in payload.get("horizons_steps", [])]
    priming = int(payload.get("priming_samples", 2))
    if not horizons or any(item <= 0 for item in horizons):
        raise ValueError("horizons_steps deve conter inteiros positivos")
    minimum_length = priming + max(horizons) + 1
    maximum_gap_ns = int(
        sample_interval_s * float(payload.get("maximum_gap_factor", 2.5)) * 1e9
    )

    partitions: Dict[str, List[List[float]]] = {name: [] for name in SPLITS}
    sources: List[Dict[str, Any]] = []
    digests: Dict[str, str] = {}
    for entry in entries:
        csv_path = entry["resolved_csv"]
        sequences, stats = _split_on_invalid_or_gap(
            csv_path,
            cid=entry["cid"],
            port_id=entry["port_id"],
            start_ns=entry["start_ns"],
            end_ns=entry["end_ns"],
            maximum_gap_ns=maximum_gap_ns,
            minimum_length=minimum_length,
        )
        if not sequences:
            raise ValueError(
                f"{entry['series_id']} não produziu sequência utilizável"
            )
        partitions[entry["split"]].extend(sequences)
        digest = digests.setdefault(str(csv_path), _digest(csv_path))
        sources.append({
            "series_id": entry["series_id"],
            "split": entry["split"],
            "cid": entry["cid"],
            "port_id": entry["port_id"],
            "csv": str(csv_path),
            "csv_sha256": digest,
            "start_ns": entry["start_ns"],
            "end_ns": entry["end_ns"],
            **stats,
        })
    for split in SPLITS:
        if not partitions[split]:
            raise ValueError(f"partição {split} está vazia")

    metadata = {
        "manifest_schema": MANIFEST_SCHEMA,
        "manifest_sha256": _digest(manifest_path),
        "validation_scope": scope,
        "promotion_eligible": scope == "independent_run_holdout",
        "source_series": sources,
        "partition_summary": {
            split: {
                "sequences": len(partitions[split]),
                "samples": sum(len(item) for item in partitions[split]),
            }
            for split in SPLITS
        },
    }
    return payload, partitions, metadata


def _write_new(path: Path, content: str, *, force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"saída já existe: {path}; use --force para substituir")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Treina Holt multi-horizonte para risco preditivo de SLA"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--alpha-grid", default="0.1,0.2,0.35,0.5,0.7,0.9")
    parser.add_argument("--beta-grid", default="0,0.05,0.1,0.2,0.35,0.5")
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.output.resolve() == args.report.resolve():
            raise ValueError("--output e --report devem apontar para arquivos distintos")
        if not args.force:
            existing = [path for path in (args.output, args.report) if path.exists()]
            if existing:
                raise ValueError(
                    f"saída já existe: {existing[0]}; use --force para substituir"
                )
        manifest, partitions, metadata = load_manifest(args.manifest)
        alphas = _grid(args.alpha_grid, "--alpha-grid", allow_zero=False)
        betas = _grid(args.beta_grid, "--beta-grid", allow_zero=True)
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        model = train_qos_holt_model(
            train_sequences=partitions["train"],
            calibration_sequences=partitions["calibration"],
            test_sequences=partitions["test"],
            horizons_steps=manifest["horizons_steps"],
            sample_interval_s=float(manifest["sample_interval_s"]),
            coverage=float(manifest.get("coverage", 0.95)),
            priming_samples=int(manifest.get("priming_samples", 2)),
            alphas=alphas,
            betas=betas,
            created_at=created_at,
            training_metadata=metadata,
        )
        artifact = model.to_dict()
        report = {
            "schema_version": "comas-qos-holt-evaluation/1",
            "model_id": artifact["model_id"],
            "validation_scope": metadata["validation_scope"],
            "promotion_eligible": metadata["promotion_eligible"],
            "partitions": metadata["partition_summary"],
            "horizons": [
                {
                    "horizon_steps": item.horizon_steps,
                    "horizon_s": item.horizon_steps * model.sample_interval_s,
                    "alpha": item.alpha,
                    "beta": item.beta,
                    "interval_radius": item.interval_radius,
                    "calibration_samples": item.calibration_samples,
                    "calibration": item.calibration_metrics,
                    "test": item.test_metrics,
                }
                for item in model.horizons
            ],
            "limitations": (
                [
                    "Single-run temporal partitions are suitable only for a "
                    "mechanical pilot, not for an independent generalization claim."
                ]
                if metadata["validation_scope"] == "pilot_single_run_temporal_split"
                else []
            ),
        }
        _write_new(
            args.output,
            json.dumps(artifact, indent=2, sort_keys=True) + "\n",
            force=args.force,
        )
        _write_new(
            args.report,
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            force=args.force,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2

    print(f"model:  {args.output}")
    print(f"report: {args.report}")
    print(f"id:     {model.resolved_model_id()}")
    print(f"scope:  {metadata['validation_scope']}")
    for item in model.horizons:
        print(
            f"h={item.horizon_steps}: alpha={item.alpha} beta={item.beta} "
            f"radius={item.interval_radius:.6f} "
            f"test_rmse={item.test_metrics['rmse']:.6f} "
            f"coverage={item.test_metrics['interval_coverage']:.6f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
