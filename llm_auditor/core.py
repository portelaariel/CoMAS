"""Normalização e verificação determinística de artefatos do CoMAS.

Este módulo não importa nem chama o runtime do CoMAS. Ele consome apenas os
artefatos imutáveis de uma execução concluída, preservando a LLM fora do
caminho de detecção, consenso, eleição de executor e mitigação.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .rules import RULES_VERSION, VERDICT_FIELDS, verify_evidence
from .runtime_evidence import normalize_episode


SCHEMA_VERSION = "2.0"


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ValueError(f"invalid JSON in {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected an object in {path.name}")
    return value


def read_ndjson(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError):
            raise ValueError(f"invalid JSON in {path.name}, line {line_number}")
        if isinstance(value, dict):
            value["_audit_source_line"] = line_number
            rows.append(value)
        else:
            raise ValueError(f"expected an object in {path.name}, line {line_number}")
    return rows


def read_ns(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, TypeError, ValueError):
        return 0


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def event_time_ns(event: Dict[str, Any]) -> int:
    audit = event.get("_audit") or {}
    for value in (
        event.get("state_entered_ns"),
        event.get("evaluated_ns"),
        audit.get("sampled_ns"),
    ):
        timestamp = _integer(value)
        if timestamp > 0:
            return timestamp
    return 0


def extract_decision_events(
    timeline_rows: Iterable[Dict[str, Any]],
    *,
    flow: Optional[str] = None,
    minimum_ns: int = 0,
) -> List[Dict[str, Any]]:
    """Extrai transições imutáveis dos agentes e do MCDA, sem snapshots.

    ``monitor_predictors.py`` já evita repetir ``decision_events`` no arquivo,
    mas a deduplicação por ``event_id`` permanece para tolerar artefatos de
    versões anteriores.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    for row_index, row in enumerate(timeline_rows):
        sampled_ns = _integer(row.get("sampled_ns"))
        status_cid = str((row.get("status") or {}).get("cid") or "")
        for section, layer in (("agentic", "agentic"),
                               ("collaboration", "mcda")):
            block = row.get(section)
            if not isinstance(block, dict):
                continue
            observed_by = str(
                block.get("cid") or status_cid or row.get("port") or "unknown"
            )
            events = block.get("decision_events") or []
            if not isinstance(events, list):
                continue
            for event_index, event in enumerate(events):
                if not isinstance(event, dict):
                    continue
                event_flow = str(event.get("flow") or "")
                if flow and event_flow != flow:
                    continue
                enriched = json.loads(json.dumps(event))
                enriched["_audit"] = {
                    "layer": layer,
                    "observed_by": observed_by,
                    "sampled_ns": sampled_ns,
                    "source_line": row.get("_audit_source_line", row_index + 1),
                    "source_pointer": f"/{section}/decision_events/{event_index}",
                    "runtime_config": json.loads(json.dumps(
                        block.get("config")
                        if isinstance(block.get("config"), dict) else {}
                    )),
                }
                timestamp = event_time_ns(enriched)
                if minimum_ns and timestamp and timestamp < minimum_ns:
                    continue
                event_id = str(event.get("event_id") or "")
                if not event_id:
                    event_id = (
                        f"missing:{layer}:{observed_by}:{event_flow}:"
                        f"{event.get('decision')}:{timestamp}:{row_index}:"
                        f"{event_index}"
                    )
                    enriched["event_id"] = event_id
                previous = seen.get(event_id)
                if previous is not None:
                    previous_payload = {key: value for key, value in previous.items() if key != "_audit"}
                    new_payload = {key: value for key, value in enriched.items() if key != "_audit"}
                    if previous_payload != new_payload:
                        raise ValueError(f"conflicting payloads for event_id {event_id}")
                seen.setdefault(event_id, enriched)
    return sorted(
        seen.values(),
        key=lambda item: (event_time_ns(item), str(item.get("event_id"))),
    )


def _episode_identifier(flow: str, events: Sequence[Dict[str, Any]],
                        sequence: int) -> str:
    window_ids = sorted({
        _integer(window_id, -1)
        for event in events
        for window_id in (event.get("window_ids") or [])
        if _integer(window_id, -1) >= 0
    })
    window_part = (
        f"{window_ids[0]}-{window_ids[-1]}" if window_ids else "no-window"
    )
    safe_flow = re.sub(r"[^A-Za-z0-9_.-]+", "_", flow).strip("_")
    return f"{safe_flow}:{window_part}:{sequence}"


def group_decision_events(
    events: Iterable[Dict[str, Any]],
    *,
    gap_s: float = 15.0,
) -> List[Dict[str, Any]]:
    """Agrupa eventos do mesmo fluxo separados por no máximo ``gap_s``."""
    if gap_s <= 0:
        raise ValueError("gap_s deve ser positivo")
    by_flow: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_flow[str(event.get("flow") or "unknown")].append(event)

    episodes: List[Dict[str, Any]] = []
    gap_ns = int(gap_s * 1e9)
    for flow in sorted(by_flow):
        ordered = sorted(
            by_flow[flow],
            key=lambda item: (event_time_ns(item), str(item.get("event_id"))),
        )
        groups: List[List[Dict[str, Any]]] = []
        current: List[Dict[str, Any]] = []
        previous_ns = 0
        for event in ordered:
            timestamp = event_time_ns(event)
            if (current and previous_ns and timestamp
                    and timestamp - previous_ns > gap_ns):
                groups.append(current)
                current = []
            current.append(event)
            if timestamp:
                previous_ns = timestamp
        if current:
            groups.append(current)
        for sequence, group in enumerate(groups, start=1):
            episodes.append({
                "episode_id": _episode_identifier(flow, group, sequence),
                "flow": flow,
                "started_ns": min(
                    (event_time_ns(event) for event in group
                     if event_time_ns(event)),
                    default=0,
                ),
                "ended_ns": max(
                    (event_time_ns(event) for event in group), default=0
                ),
                "events": group,
            })
    return sorted(
        episodes,
        key=lambda item: (item["started_ns"], item["episode_id"]),
    )


def _run_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    runs = summary.get("runs") if isinstance(summary, dict) else None
    if isinstance(runs, list) and runs and isinstance(runs[0], dict):
        if len(runs) != 1:
            raise ValueError("summary.json must describe one run, not a campaign")
        return {**runs[0], "_audit_summary_in_runs": True}
    return summary if isinstance(summary, dict) else {}


def _proposal_model_ids(event: Dict[str, Any]) -> List[str]:
    configured = [
        str(value) for value in (event.get("model_ids") or []) if value
    ]
    if configured:
        return sorted(set(configured))
    return sorted({
        str(proposal.get("model_id"))
        for proposal in (event.get("proposals") or [])
        if isinstance(proposal, dict) and proposal.get("model_id")
    })


def _scenario_correctness(metadata: Dict[str, Any],
                          summary: Dict[str, Any]) -> str:
    # This is a run-level legacy summary only, not the episode's verifier.
    if (metadata.get("ground_truth_available") is False
            or summary.get("measurement_valid") is False
            or summary.get("invalid_reasons") or summary.get("contamination_reasons")
            or metadata.get("validation_status") in {"INVALID", "CONTAMINATED"}):
        return "UNKNOWN"
    scenario = str(metadata.get("scenario") or "")
    classification = str(summary.get("classification") or "")
    if scenario not in {"benign", "ddos"}:
        return "UNKNOWN"
    if classification in {"TP", "TN"}:
        return "CORRECT"
    if classification in {"FP", "FN"}:
        return "INCORRECT"
    return "UNKNOWN"


def _collapsed_transitions(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    transitions: List[Dict[str, Any]] = []
    seen: set = set()
    for event in sorted(events, key=event_time_ns):
        layer = str((event.get("_audit") or {}).get("layer") or "unknown")
        state = str(event.get("decision") or "UNKNOWN")
        key = (layer, state)
        if key in seen:
            continue
        seen.add(key)
        transitions.append({
            "layer": layer,
            "state": state,
            "event_id": str(event.get("event_id") or ""),
            "observed_by": str(
                (event.get("_audit") or {}).get("observed_by") or "unknown"
            ),
            "entered_ns": event_time_ns(event),
        })
    return transitions


def evaluate_episode(
    episode: Dict[str, Any],
    metadata: Dict[str, Any],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Normalize each immutable observation and apply the versioned verifier."""
    events = list(episode.get("events") or [])
    record = normalize_episode(events, metadata, summary)
    state_counts = Counter(str(event.get("decision") or "UNKNOWN")
                           for event in events)
    layer_counts = Counter(str((event.get("_audit") or {}).get("layer")
                               or "unknown") for event in events)
    record.update({
        "episode_id": episode["episode_id"],
        "flow": episode["flow"],
        "started_ns": episode["started_ns"],
        "ended_ns": episode["ended_ns"],
        "event_count": len(events),
        "event_counts_by_layer": dict(sorted(layer_counts.items())),
        "event_counts_by_state": dict(sorted(state_counts.items())),
        "transitions": _collapsed_transitions(events),
        "relevant_domains": sorted({
            str(domain) for event in events
            for domain in (
                list(event.get("relevant_domains") or [])
                + list(event.get("participating_domains") or [])
            ) if domain
        }),
        "model_ids": sorted({
            model_id for event in events
            for model_id in _proposal_model_ids(event)
        }),
        "required_votes": max(
            (_integer(event.get("required_votes")) for event in events),
            default=0,
        ),
        "source_event_ids": [str(event.get("event_id") or "") for event in events],
    })
    record.update(verify_evidence(record))
    return record


def audit_run(run_dir: Path, *, episode_gap_s: float = 15.0) -> Dict[str, Any]:
    """Audita deterministicamente uma execução concluída do CoMAS."""
    run_dir = Path(run_dir)
    metadata = read_json(run_dir / "metadata.json", {}) or {}
    summary_document = read_json(run_dir / "summary.json", {}) or {}
    summary = _run_summary(summary_document)
    timeline_path = run_dir / "timeline.ndjson"
    if not timeline_path.is_file():
        raise FileNotFoundError(f"timeline.ndjson não encontrado em {run_dir}")

    scenario = str(metadata.get("scenario") or "")
    minimum_ns = (
        read_ns(run_dir / "attack_start_ns.txt")
        if scenario == "ddos" else _integer(metadata.get("started_ns"))
    )
    if scenario == "ddos" and minimum_ns <= 0:
        # Without the attack boundary, benign priming windows may be present.
        metadata = {**metadata, "ground_truth_available": False}
    events = extract_decision_events(
        read_ndjson(timeline_path),
        flow=str(metadata.get("flow") or "") or None,
        minimum_ns=minimum_ns,
    )
    grouped = group_decision_events(events, gap_s=episode_gap_s)
    if len(grouped) > 1:
        # A run-level disruption flag cannot attribute effectiveness to each
        # separate episode. Episode-specific outcome artifacts are not present.
        summary = {**summary, "_audit_outcome_scope_unknown": True}
    episodes = [evaluate_episode(episode, metadata, summary)
                for episode in grouped]
    event_counts = Counter(str(event.get("decision") or "UNKNOWN")
                           for event in events)
    return {
        "schema_version": SCHEMA_VERSION,
        "rules_version": RULES_VERSION,
        "audit_type": "post-experiment",
        "run": {
            "directory": str(run_dir),
            "name": run_dir.name,
            "git_commit": metadata.get("git_commit"),
            "flow": metadata.get("flow"),
            "scenario": metadata.get("scenario"),
            "mode": metadata.get("mode"),
            "agentic_mode": metadata.get("agentic_mode"),
            "classification": summary.get("classification"),
            "scenario_correctness": _scenario_correctness(metadata, summary),
            "audit_status": (
                "AUDITED" if episodes else "NO_AUDITABLE_EVENTS"
            ),
        },
        "events_seen": len(events),
        "event_counts_by_state": dict(sorted(event_counts.items())),
        "episodes": episodes,
    }


def evaluation_evidence(record: Dict[str, Any]) -> Dict[str, Any]:
    """Remove o veredito/oráculo antes do modo experimental da LLM."""
    excluded = {
        "checks",
        "decision_stage",
        "execution_status",
        "operational_effectiveness",
        "protocol_consistency",
        "scenario_correctness",
        "source_event_ids",
        "rules_version",
        "verdict_support",
        "limitations",
        "observations",
        "evidence_sources",
        "claim_records",
        "explanation_certificate",
        "certificate_ledger",
        "certificate_context",
        "llm_explanation",
        "llm_evaluation",
        "llm_vs_deterministic",
    }
    evidence = {key: value for key, value in record.items()
                if key not in excluded}
    laboratory = dict(evidence.get("laboratory_context") or {})
    laboratory.pop("classification", None)
    evidence["laboratory_context"] = laboratory
    return evidence


def compare_verdicts(
    deterministic: Dict[str, Any],
    llm: Dict[str, Any],
) -> Dict[str, Any]:
    """Compara apenas as dimensões categóricas do contrato de avaliação."""
    comparisons = {
        field: {
            "deterministic": deterministic.get(field),
            "llm": llm.get(field),
            "matches": deterministic.get(field) == llm.get(field),
        }
        for field in VERDICT_FIELDS
    }
    return {
        "all_match": all(value["matches"] for value in comparisons.values()),
        "fields": comparisons,
    }
