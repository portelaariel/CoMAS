"""Compact, deterministic explanation input; the full proof stays on disk.

Grouping never combines votes or changes verdicts. A group means that the
same rule had the same status on several checks, not that its first witness
describes every event. The ledger resolves all members to the original proof.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from typing import Any, Dict

from .rules import VERDICT_FIELDS


CERTIFICATE_VERSION = "1.0"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def build_certificate(episode: Dict[str, Any]) -> Dict[str, Any]:
    """Return a bounded witness view plus an unabridged membership ledger.

    Every rule/status group is retained, including FAIL and UNKNOWN. Long
    witness values are abbreviated explicitly, never interpreted as false.
    The hash binds the view to supplied audit data; it is not authentication
    or independent proof that the logged network events actually happened.
    """
    omitted = []

    def bounded(value: Any, path: str, depth: int = 0) -> Any:
        if isinstance(value, str) and len(value) > 120:
            omitted.append({"path": path, "kind": "string", "original_length": len(value)})
            return {"preview": value[:120], "abbreviated": True}
        if isinstance(value, (list, dict)) and depth >= 5:
            omitted.append({"path": path, "kind": "depth", "original_length": len(value)})
            return {"abbreviated": True, "item_count": len(value)}
        if isinstance(value, list):
            result = [bounded(item, f"{path}/{i}", depth + 1)
                      for i, item in enumerate(value[:4])]
            if len(value) > 4:
                omitted.append({"path": path, "kind": "list", "original_length": len(value)})
                result.append({"abbreviated": True, "omitted_items": len(value) - 4})
            return result
        if isinstance(value, dict):
            # Do not drop field names silently. Large objects will fail the
            # context admission check instead of hiding relevant fields.
            return {key: bounded(item, f"{path}/{key}", depth + 1)
                    for key, item in value.items()}
        return copy.deepcopy(value)

    checks = episode.get("checks") or []
    groups: Dict[Any, Any] = {}
    seen = set()
    for check in checks:
        check_id = check.get("check_id")
        if not isinstance(check_id, str) or not check_id or check_id in seen:
            raise ValueError("certificado exige check_id único em cada verificação")
        seen.add(check_id)
        dimension = check.get("dimension")
        status = check.get("status")
        if dimension not in VERDICT_FIELDS or status not in {"PASS", "FAIL", "UNKNOWN"}:
            raise ValueError("dimensão/status inválido no certificado")
        key = (dimension, check.get("rule_id"), check.get("name"), status)
        groups.setdefault(key, []).append(check)

    compact_transitions = [
        {key: item.get(key) for key in ("layer", "state", "observed_by")}
        for item in episode.get("transitions") or []
    ]
    evidence = []
    ledger = {}
    support = {field: [] for field in VERDICT_FIELDS}

    def compact_witness(check: Dict[str, Any]) -> Dict[str, Any]:
        original = check["evidence"]
        values: Dict[str, Any] = {}
        for path, value in (original.get("values") or {}).items():
            if path == "transitions" and isinstance(value, list):
                value = [{key: item.get(key) for key in ("layer", "state", "observed_by")}
                         for item in value]
                if value == compact_transitions:
                    value = {"context_ref": "transitions"}
            # Nest dotted fields to avoid repeating long namespaces in every
            # witness. The full check still preserves original paths/values.
            target = values
            parts = path.split(".")
            for part in parts[:-1]:
                target = target.setdefault(part, {})
            target[parts[-1]] = value
        return {"values": values, **{key: value for key, value in original.items() if key != "values"}}

    for (dimension, rule_id, name, status), members in groups.items():
        evidence_id = f"E{len(evidence) + 1:02d}"
        witness = members[0]
        entry = {
            "id": evidence_id, "dimension": dimension, "rule": name,
            "status": status, "check_count": len(members),
            "witness": bounded(compact_witness(witness), f"{evidence_id}/witness"),
        }
        if witness.get("missing_fields"):
            entry["missing_fields"] = bounded(witness["missing_fields"], f"{evidence_id}/missing_fields")
        evidence.append(entry)
        ledger[evidence_id] = {
            "rule_id": rule_id,
            "check_ids": [member["check_id"] for member in members],
            "witness_check_id": witness["check_id"],
        }
        support[dimension].append(evidence_id)

    for field in VERDICT_FIELDS:
        if not isinstance(episode.get(field), str):
            raise ValueError(f"veredito determinístico ausente: {field}")
        if not support[field]:
            evidence_id = f"E{len(evidence) + 1:02d}"
            evidence.append({
                "id": evidence_id, "dimension": field,
                "rule": "no_recorded_checks_for_dimension", "status": "UNKNOWN",
                "check_count": 0, "witness": {"recorded_checks": 0}, "missing_fields": [],
            })
            ledger[evidence_id] = {"check_ids": [], "origin": "absence_of_checks"}
            support[field].append(evidence_id)

    context_keys = (
        "flow", "scope", "evidence_origin", "execution_mode", "agentic_policy_mode", "claim_winners",
        "normalized_facts", "execution_counts_by_layer", "event_counts_by_state",
        "event_counts_by_layer", "event_count", "laboratory_context",
    )
    raw_context = {key: copy.deepcopy(episode[key]) for key in context_keys if key in episode}
    if isinstance(raw_context.get("laboratory_context"), dict):
        raw_context["laboratory_context"].pop("classification", None)
    context = bounded(raw_context, "context")
    # Full timestamps and event IDs belong to the ledger/proof, not the prompt.
    context["transitions"] = bounded(compact_transitions, "context/transitions")
    certificate = {
        "certificate_version": CERTIFICATE_VERSION,
        "rules_version": episode.get("rules_version"),
        "verdicts": {field: episode[field] for field in VERDICT_FIELDS},
        "context": context, "evidence": evidence, "verdict_support": support,
        "coverage": {
            "original_check_count": len(checks), "rule_status_groups": len(groups),
            "status_counts": dict(Counter(check["status"] for check in checks)),
            "witness_policy": "one_example_per_rule_status_group; not_all_events",
            "provenance_policy": "event_ids/timestamps/source_refs_kept_in_full_proof",
            "abbreviation_count": len(omitted),
        },
        "limitations": episode.get("limitations") or [],
    }
    # Exclude derived/LLM fields so retries preserve the same deterministic
    # source digest even after a certificate has been attached to this episode.
    source = {key: value for key, value in episode.items() if key not in {
        "explanation_certificate", "certificate_ledger", "certificate_context",
        "llm_explanation", "llm_evaluation", "llm_vs_deterministic",
    }}
    certificate["source_audit_sha256"] = digest(source)
    certificate["sha256"] = digest(certificate)
    return {
        "certificate": certificate,
        "ledger": {
            "certificate_sha256": certificate["sha256"],
            "source_audit_sha256": certificate["source_audit_sha256"],
            "groups": ledger, "abbreviations": omitted,
            "resolution": "check_ids -> episode.checks -> source_refs",
        },
    }


def attach_certificate(episode: Dict[str, Any]) -> Dict[str, Any]:
    bundle = build_certificate(episode)
    episode["explanation_certificate"] = bundle["certificate"]
    episode["certificate_ledger"] = bundle["ledger"]
    return bundle["certificate"]
