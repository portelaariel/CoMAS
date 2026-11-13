"""Synthetic regression of certificate explanations, not independent evals.

Only certificates enter the existing explanation client. Oracles, rationales,
titles and review targets stay in the report. Structural acceptance is never
reported as factual verification, classification accuracy or network efficacy.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .certificate import attach_certificate, digest
from .certificate_explanation import (
    CertificateExplanationClient, EXPLANATION_CONTRACT_VERSION,
    SYSTEM_PROMPT, context_budget, explanation_schema, validate_explanation,
)
from .core import SCHEMA_VERSION, compare_verdicts
from .ollama import OllamaAuditError
from .rules import RULES_VERSION, VERDICT_FIELDS, verify_evidence
from .validation_dataset import HOLDOUT_PATH, load_holdout_dataset


CRITICAL_CASE_IDS = ("h07", "h08", "h13", "h14", "h15", "h16")


def explanation_contract_hashes() -> Dict[str, Any]:
    root = Path(__file__).parent
    return {
        "contract_version": EXPLANATION_CONTRACT_VERSION,
        "system_prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
        "source_sha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("rules.py", "certificate.py", "certificate_explanation.py",
                         "explanation_campaign.py")
        },
    }


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    evaluations = report["evaluations"]
    accepted = sum(item["llm_explanation"]["status"] == "ACCEPTED_STRUCTURALLY"
                   for item in evaluations)
    return {
        "cases_prepared": len(report["cases"]), "evaluations_completed": len(evaluations),
        "structurally_accepted": accepted, "rejected": len(evaluations) - accepted,
        "pending_manual_review": sum(
            item["llm_explanation"]["status"] == "ACCEPTED_STRUCTURALLY"
            and item["manual_review"]["status"] == "PENDING" for item in evaluations),
        "oracle_mismatches": sum(not item["oracle_comparison"]["all_match"] for item in report["cases"]),
        "estimated_context_oversized": sum(not item["audit"]["certificate_context"]
                                            ["preflight_fits_estimate"] for item in report["cases"]),
        "prose_factually_verified": False,
    }


def prepare_report(
    *, model: str = "qwen3.5:9b", num_ctx: int = 6144, seed: int = 42,
    case_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    dataset = load_holdout_dataset()
    selected = list(CRITICAL_CASE_IDS if case_ids is None else case_ids)
    known = {case["case_id"] for case in dataset["cases"]}
    if not selected or len(selected) != len(set(selected)) or set(selected) - known:
        raise ValueError("informe casos distintos e existentes na fixture congelada")
    cases = []
    for index, original in enumerate(dataset["cases"]):
        if original["case_id"] not in selected:
            continue
        audit = copy.deepcopy(original["evidence"])
        audit["evidence_artifact"] = f"fixtures/holdout_v1.json#/cases/{index}/evidence"
        audit.update(verify_evidence(audit))
        certificate = attach_certificate(audit)
        audit["certificate_context"] = context_budget(certificate, num_ctx)
        checks = {item["check_id"]: item for item in audit["checks"]}
        targets = []
        for entry in certificate["evidence"]:
            if entry["status"] == "PASS":
                continue
            check_id = audit["certificate_ledger"]["groups"][entry["id"]].get("witness_check_id")
            check = checks.get(check_id, {})
            targets.append({
                "evidence_id": entry["id"], "dimension": entry["dimension"],
                "rule": entry["rule"], "status": entry["status"],
                "reason": check.get("reason", "No check was recorded for this dimension."),
                "missing_fields": check.get("missing_fields", []),
            })
        cases.append({
            "case_id": original["case_id"], "group": original["group"],
            "title": original["title"], "audit": audit,
            "expected": copy.deepcopy(original["expected"]),
            "oracle_comparison": compare_verdicts(original["expected"], audit),
            "review_targets": targets,
            "response_schema_sha256": digest(explanation_schema(certificate)),
        })
    report = {
        "schema_version": SCHEMA_VERSION, "rules_version": RULES_VERSION,
        "campaign_type": "synthetic-certificate-explanation-regression",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "campaign_status": "PREPARED", "model": model,
        "inference_parameters": {"num_ctx": num_ctx, "seed": seed, "temperature": 0.0, "keep_alive": 0},
        "dataset": {"dataset_id": dataset["dataset_id"], "dataset_sha256": dataset["dataset_sha256"],
                    "role": "previously-inspected-regression-corpus", "subset_selected": len(cases) != 16},
        "frozen_evaluation_contract": dataset["evaluation_contract"],
        "explanation_contract": explanation_contract_hashes(),
        "selected_inputs_sha256": digest([case["evidence"] for case in dataset["cases"]
                                          if case["case_id"] in selected]),
        "cases": cases, "evaluations": [],
        "limitations": [
            "These previously inspected fixtures are a regression corpus, not a fresh independent holdout or network experiment.",
            "Verdict echoes are schema-constrained; structural acceptance is not independent LLM classification accuracy.",
            "References and non-pass-group citations are checked; free prose needs manual review for contradictions and invented facts.",
            "Source/prompt/schema hashes record this explanation contract; they do not authenticate network events.",
            "No ETCD publication, claim election, FlowBlocker call, OpenFlow rule installation or model download is performed.",
        ],
    }
    report["summary"] = summarize(report)
    return report


def capture_environment(client: CertificateExplanationClient) -> Dict[str, Any]:
    """Read local Ollama metadata; incomplete metadata is explicitly recorded."""
    environment: Dict[str, Any] = {"ollama_version": None, "model_digest": None, "warnings": []}
    for endpoint in ("version", "tags"):
        try:
            request = urllib.request.Request(f"{client.base_url}/api/{endpoint}", method="GET")
            with client.opener(request, timeout=5) as response:
                body = json.loads(response.read().decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("metadata response is not an object")
            if endpoint == "version":
                version = body.get("version")
                if not isinstance(version, str) or not version:
                    raise ValueError("Ollama version unavailable")
                environment["ollama_version"] = version
            else:
                matches = [item for item in body.get("models", []) if isinstance(item, dict)
                           and client.model in (item.get("name"), item.get("model"))]
                value = matches[0].get("digest") if matches else None
                if not isinstance(value, str) or not value:
                    raise ValueError("exact model digest unavailable in /api/tags")
                environment["model_digest"] = value
        except (OSError, ValueError, TypeError) as exc:
            environment["warnings"].append(f"{endpoint}: {exc}")
    return environment


def explain_campaign(
    report: Dict[str, Any], *, client: CertificateExplanationClient,
    checkpoint: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    def save() -> None:
        report["summary"] = summarize(report)
        if checkpoint:
            checkpoint(report)

    if report["evaluations"]:
        raise ValueError("a campanha já contém respostas; preserve-a e prepare uma nova")
    if report["explanation_contract"] != explanation_contract_hashes():
        raise ValueError("o contrato da explicação mudou após a preparação")
    parameters = report["inference_parameters"]
    actual = {"num_ctx": client.num_ctx, "seed": client.seed,
              "temperature": client.temperature, "keep_alive": client.keep_alive}
    if report["model"] != client.model or parameters != actual:
        raise ValueError("modelo/parâmetros do cliente diferem da campanha preparada")
    report["summary"] = summarize(report)
    if report["summary"]["oracle_mismatches"] or report["summary"]["estimated_context_oversized"]:
        report["campaign_status"] = "BLOCKED_PRECHECK"
        save()
        return report
    # Save the entire prepared manifest before any metadata or inference call.
    report["campaign_status"] = "RUNNING"
    save()
    report["environment"] = capture_environment(client)
    save()
    for case in report["cases"]:
        certificate = case["audit"]["explanation_certificate"]
        try:
            response = client.explain(copy.deepcopy(certificate))
            response["grounding_validation"] = validate_explanation(response["result"], certificate)
            if response.get("status") != "ACCEPTED_STRUCTURALLY":
                raise OllamaAuditError("cliente não confirmou aceitação estrutural")
        except (OSError, ValueError, OllamaAuditError) as exc:
            response = {**getattr(exc, "record", {}), "status": "REJECTED", "error": str(exc),
                        "certificate_sha256": certificate["sha256"]}
        report["evaluations"].append({
            "case_id": case["case_id"], "seed": report["inference_parameters"]["seed"],
            "llm_explanation": response,
            "manual_review": {
                "status": "PENDING" if response["status"] == "ACCEPTED_STRUCTURALLY" else "REJECTED_OUTPUT",
                "prose_factually_verified": False,
            },
        })
        save()
        if response["status"] == "REJECTED" and "raw_response" not in response:
            # A transport/no-response failure should not waste five more
            # attempts on a broken reverse tunnel. Completed cases remain.
            report["campaign_status"] = "PARTIAL_ERROR"
            save()
            return report
    report["campaign_status"] = (
        "COMPLETED_WITH_REJECTIONS" if report["summary"]["rejected"] else "COMPLETED"
    )
    save()
    return report


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# CoMAS certificate explanations — synthetic regression", "",
        f"Status: `{report['campaign_status']}`; accepted structurally: "
        f"`{report['summary']['structurally_accepted']}/{report['summary']['evaluations_completed']}`.", "",
        "Structural acceptance is not independent classification accuracy or factual verification of prose.", "",
    ]
    responses = {item["case_id"]: item["llm_explanation"] for item in report["evaluations"]}
    for case in report["cases"]:
        lines.extend([f"## {case['case_id']} — {case['title']}", ""])
        for field in VERDICT_FIELDS:
            lines.append(f"- `{field}`: `{case['audit'][field]}`")
        lines.extend(["", "Manual review targets:", ""])
        for target in case["review_targets"]:
            lines.append(f"- `{target['evidence_id']}` / `{target['status']}` / `{target['rule']}`: {target['reason']}")
        response = responses.get(case["case_id"])
        if response:
            lines.extend(["", f"LLM status: `{response['status']}`", ""])
            if response["status"] == "REJECTED":
                lines.append(response["error"])
            else:
                lines.append(response["result"]["summary"])
                lines.append("")
                for field, item in response["result"]["dimensions"].items():
                    lines.append(f"- `{field}`: {item['explanation']} ({', '.join(item['evidence_ids'])})")
            lines.extend(["", "Manual prose review: PENDING."])
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Testa explicações de certificados sintéticos, sem atuar na rede")
    parser.add_argument("--model", default="qwen3.5:9b")
    parser.add_argument("--ollama-url", default=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
    parser.add_argument("--num-ctx", type=int, default=6144)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--case", action="append", help="seleciona um caso; pode ser repetido; padrão: seis casos críticos")
    parser.add_argument("--manifest-only", action="store_true", help="prepara certificados sem consultar Ollama")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    markdown = args.output.with_suffix(".md")
    report = None
    checkpoint = None
    try:
        if args.output.resolve() == markdown.resolve():
            raise ValueError("JSON e Markdown precisam de caminhos diferentes")
        for path in (args.output, markdown):
            if path.resolve() == HOLDOUT_PATH.resolve():
                raise ValueError("a fixture congelada não é um destino de saída")
            if path.name in {"metadata.json", "summary.json", "timeline.ndjson", "attack_start_ns.txt"}:
                raise ValueError("artefatos de experimento não são destinos de saída")
            if path.exists() and not args.overwrite:
                raise ValueError(f"saída já existe: {path}; use um novo nome ou --overwrite")
        report = prepare_report(model=args.model, num_ctx=args.num_ctx, seed=args.seed, case_ids=args.case)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        progress = 0

        def checkpoint(current: Dict[str, Any]) -> None:
            nonlocal progress
            args.output.write_text(json.dumps(current, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            markdown.write_text(render_markdown(current), encoding="utf-8")
            if len(current["evaluations"]) > progress:
                item = current["evaluations"][-1]
                print(f"{item['case_id']}: {item['llm_explanation']['status']}", flush=True)
                progress = len(current["evaluations"])

        if args.manifest_only:
            report["campaign_status"] = "MANIFEST_ONLY"
            checkpoint(report)
        else:
            client = CertificateExplanationClient(model=args.model, base_url=args.ollama_url,
                                                  num_ctx=args.num_ctx, seed=args.seed, temperature=0.0, keep_alive=0)
            explain_campaign(report, client=client, checkpoint=checkpoint)
    except (OSError, ValueError, OllamaAuditError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        # Each prior response was checkpointed; also mark the interruption.
        if report is not None and checkpoint is not None:
            report["campaign_status"] = "INTERRUPTED"
            checkpoint(report)
        print("campanha interrompida; respostas anteriores preservadas", file=sys.stderr)
        return 130
    print(f"campaign: {report['campaign_status']}")
    print(f"json:     {args.output}")
    print(f"markdown: {markdown}")
    if report["summary"]["oracle_mismatches"] or report["summary"]["estimated_context_oversized"]:
        return 2
    return 0 if report["campaign_status"] in {"MANIFEST_ONLY", "COMPLETED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
