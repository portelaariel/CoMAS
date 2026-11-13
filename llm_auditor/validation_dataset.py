"""Carregamento de fixtures novas sob um contrato de inferência congelado."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from .core import VERDICT_FIELDS
from .ollama import EVALUATION_SCHEMA, evaluation_prompt


HOLDOUT_PATH = Path(__file__).with_name("fixtures") / "holdout_v1.json"
HOLDOUT_SHA256 = (
    "40374010c05f5a9d092819644689aa639fc9ea58589d1f624f1acd99312c1cc2"
)


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def current_contract_hashes() -> Dict[str, str]:
    return {
        "ollama_client_sha256": hashlib.sha256(
            Path(__file__).with_name("ollama.py").read_bytes()
        ).hexdigest(),
        "prompt_template_sha256": hashlib.sha256(
            evaluation_prompt({}).encode("utf-8")
        ).hexdigest(),
        "evaluation_schema_sha256": canonical_sha256(EVALUATION_SCHEMA),
    }


def verify_frozen_contract(expected: Dict[str, str]) -> None:
    actual = current_contract_hashes()
    if expected != actual:
        changed = sorted(
            key for key in set(expected) | set(actual)
            if expected.get(key) != actual.get(key)
        )
        raise ValueError(
            "contrato de inferência alterado desde a versão congelada: "
            + ", ".join(changed)
            + "; não execute holdout-v1 como se fosse o mesmo experimento"
        )


def load_holdout_dataset() -> Dict[str, Any]:
    raw = HOLDOUT_PATH.read_bytes()
    checksum = hashlib.sha256(raw).hexdigest()
    if checksum != HOLDOUT_SHA256:
        raise ValueError("holdout-v1 foi alterado: checksum das fixtures inválido")
    dataset = json.loads(raw)
    verify_frozen_contract(dataset["evaluation_contract"])
    cases = dataset["cases"]
    if len(cases) != 16 or len({case["case_id"] for case in cases}) != 16:
        raise ValueError("holdout-v1 deve conter 16 casos distintos")
    for case in cases:
        expected = case["expected"]
        evidence = case["evidence"]
        if set(expected) != set(VERDICT_FIELDS):
            raise ValueError(f"oráculo incompleto em {case['case_id']}")
        for field in VERDICT_FIELDS:
            if expected[field] not in EVALUATION_SCHEMA["properties"][field]["enum"]:
                raise ValueError(f"valor de oráculo inválido: {case['case_id']}/{field}")
        if set(VERDICT_FIELDS) & set(evidence):
            raise ValueError(f"oráculo exposto na evidência de {case['case_id']}")
        if evidence.get("fixture_id") != case["case_id"]:
            raise ValueError("fixture_id não corresponde ao caso declarado")
        if evidence.get("evidence_origin") != "synthetic_protocol_fixture":
            raise ValueError("origem sintética deve ser explícita")
    dataset["dataset_sha256"] = checksum
    return dataset
