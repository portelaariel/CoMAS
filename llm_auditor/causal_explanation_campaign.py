"""Version 2.3 regression campaign for verifier-derived causal explanations."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .causal_certificate import attach_causal_certificate
from .certificate import digest
from .causal_explanation import (
    CAUSAL_EXPLANATION_CONTRACT_VERSION, CAUSAL_SYSTEM_PROMPT,
    CausalExplanationClient, causal_context_budget, causal_schema,
    validate_causal_explanation,
)
from .explanation_campaign import (
    CRITICAL_CASE_IDS, capture_environment, prepare_report as prepare_v1_report,
    summarize,
)
from .ollama import OllamaAuditError
from .rules import VERDICT_FIELDS
from .validation_dataset import HOLDOUT_PATH


def causal_contract_hashes() -> Dict[str, Any]:
    root = Path(__file__).parent
    return {
        "contract_version": CAUSAL_EXPLANATION_CONTRACT_VERSION,
        "system_prompt_sha256": hashlib.sha256(CAUSAL_SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
        "source_sha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("causal_certificate.py", "causal_explanation.py",
                         "causal_explanation_campaign.py")
        },
    }


def prepare_causal_report(
    *, model: str = "qwen3.5:9b", num_ctx: int = 6144, seed: int = 42,
    case_ids: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    report = prepare_v1_report(model=model, num_ctx=num_ctx, seed=seed, case_ids=case_ids)
    for case in report["cases"]:
        certificate = attach_causal_certificate(case["audit"])
        case["audit"]["certificate_context"] = causal_context_budget(certificate, num_ctx)
        case["response_schema_sha256"] = digest(causal_schema(certificate))
        case["causal_review"] = copy.deepcopy(certificate["decisive_causes"])
    report["campaign_type"] = "synthetic-causal-certificate-explanation-regression"
    report["created_at"] = datetime.now(timezone.utc).isoformat()
    report["campaign_status"] = "PREPARED"
    report["base_v1_explanation_contract"] = report.pop("explanation_contract")
    report["causal_explanation_contract"] = causal_contract_hashes()
    report["limitations"] = [
        "This v2 campaign derives cause codes from verifier outputs; it does not turn the LLM into a verifier.",
        *report["limitations"],
        "Exact cause-code/reference echoes are enforced; free prose still requires manual factual review.",
        "The v1 pilot remains a separate preserved result and is not overwritten or retroactively rescored.",
    ]
    report["evaluations"] = []
    report["summary"] = summarize(report)
    return report


def explain_causal_campaign(
    report: Dict[str, Any], *, client: CausalExplanationClient,
    checkpoint: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    def save() -> None:
        report["summary"] = summarize(report)
        if checkpoint:
            checkpoint(report)

    if report["evaluations"]:
        raise ValueError("a campanha causal já contém respostas; preserve-a e crie outra")
    if report["causal_explanation_contract"] != causal_contract_hashes():
        raise ValueError("o contrato causal mudou após a preparação")
    parameters = report["inference_parameters"]
    actual = {"num_ctx": client.num_ctx, "seed": client.seed,
              "temperature": client.temperature, "keep_alive": client.keep_alive}
    if report["model"] != client.model or parameters != actual:
        raise ValueError("modelo/parâmetros diferem da campanha causal preparada")
    if report["summary"]["oracle_mismatches"] or report["summary"]["estimated_context_oversized"]:
        report["campaign_status"] = "BLOCKED_PRECHECK"
        save()
        return report
    report["campaign_status"] = "RUNNING"
    save()
    report["environment"] = capture_environment(client)
    save()
    for case in report["cases"]:
        certificate = case["audit"]["explanation_certificate"]
        try:
            response = client.explain(copy.deepcopy(certificate))
            response["grounding_validation"] = validate_causal_explanation(
                response["result"], certificate)
            if response.get("status") != "ACCEPTED_STRUCTURALLY":
                raise OllamaAuditError("cliente causal não confirmou aceitação estrutural")
        except (OSError, ValueError, OllamaAuditError) as exc:
            response = {**getattr(exc, "record", {}), "status": "REJECTED",
                        "error": str(exc), "certificate_sha256": certificate["sha256"]}
        report["evaluations"].append({
            "case_id": case["case_id"], "seed": parameters["seed"],
            "llm_explanation": response,
            "manual_review": {"status": ("PENDING" if response["status"] == "ACCEPTED_STRUCTURALLY"
                                         else "REJECTED_OUTPUT"),
                              "prose_factually_verified": False},
        })
        save()
        if response["status"] == "REJECTED" and "raw_response" not in response:
            report["campaign_status"] = "PARTIAL_ERROR"
            save()
            return report
    report["campaign_status"] = (
        "COMPLETED_WITH_REJECTIONS" if report["summary"]["rejected"] else "COMPLETED"
    )
    save()
    return report


def render_markdown(report: Dict[str, Any]) -> str:
    lines = ["# CoMAS causal certificate explanations — synthetic regression", "",
             f"Status: `{report['campaign_status']}`; structurally accepted: "
             f"`{report['summary']['structurally_accepted']}/{report['summary']['evaluations_completed']}`.", "",
             "Cause codes and references are deterministic; free prose remains pending manual review.", ""]
    responses = {item["case_id"]: item["llm_explanation"] for item in report["evaluations"]}
    for case in report["cases"]:
        lines.extend([f"## {case['case_id']} — {case['title']}", ""])
        for field in VERDICT_FIELDS:
            cause = case["causal_review"][field]
            lines.append(f"- `{field}`: `{cause['verdict']}` / `{cause['cause_code']}` / "
                         f"{', '.join(cause['decisive_evidence_ids'])}")
        response = responses.get(case["case_id"])
        if response:
            lines.extend(["", f"LLM status: `{response['status']}`", ""])
            if response["status"] == "REJECTED":
                lines.append(response["error"])
            else:
                lines.append(response["result"]["summary"])
                lines.append("")
                for field, item in response["result"]["dimensions"].items():
                    lines.append(f"- `{field}` / `{item['cause_code']}`: {item['explanation']} "
                                 f"({', '.join(item['evidence_ids'])})")
            lines.extend(["", "Manual prose review: PENDING."])
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Testa explicações causais v2.3 sem atuar na rede")
    parser.add_argument("--model", default="qwen3.5:9b")
    parser.add_argument("--ollama-url", default=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
    parser.add_argument("--num-ctx", type=int, default=6144)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--case", action="append")
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    markdown = args.output.with_suffix(".md")
    report = None
    checkpoint = None
    try:
        for path in (args.output, markdown):
            if path.resolve() == HOLDOUT_PATH.resolve():
                raise ValueError("a fixture congelada não é destino de saída")
            if path.name in {"metadata.json", "summary.json", "timeline.ndjson", "attack_start_ns.txt"}:
                raise ValueError("artefatos de experimento não são destinos de saída")
            if path.exists() and not args.overwrite:
                raise ValueError(f"saída já existe: {path}; use outro nome")
        report = prepare_causal_report(model=args.model, num_ctx=args.num_ctx,
                                       seed=args.seed, case_ids=args.case)
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
            client = CausalExplanationClient(model=args.model, base_url=args.ollama_url,
                                             num_ctx=args.num_ctx, seed=args.seed,
                                             temperature=0.0, keep_alive=0)
            explain_causal_campaign(report, client=client, checkpoint=checkpoint)
    except (OSError, ValueError, OllamaAuditError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        if report is not None and checkpoint is not None:
            report["campaign_status"] = "INTERRUPTED"
            checkpoint(report)
        return 130
    print(f"campaign: {report['campaign_status']}")
    print(f"json:     {args.output}")
    print(f"markdown: {markdown}")
    return 0 if report["campaign_status"] in {"MANIFEST_ONLY", "COMPLETED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
