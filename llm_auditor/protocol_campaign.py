"""Campanha sintética para avaliar a interpretação do protocolo pela LLM.

Os casos deste módulo são fixtures declaradas, não execuções de rede. Eles
isolam seis resultados do protocolo para que erros de interpretação possam ser
medidos separadamente de detecção, consenso e eficácia no plano de dados.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .core import SCHEMA_VERSION, VERDICT_FIELDS, compare_verdicts
from .ollama import OllamaAuditClient, OllamaAuditError
from .validation_dataset import (
    canonical_sha256,
    current_contract_hashes,
    load_holdout_dataset,
)


DOMAINS = ["192.168.10.10", "192.168.11.10"]
FLOW = "10.0.0.1->10.0.0.8"
MODEL_ID = "holt_residual:fixture"


def _transition(layer: str, state: str, observer: str) -> Dict[str, str]:
    return {"layer": layer, "state": state, "observed_by": observer}


def _facts(
    *,
    agreed: int = 0,
    authorized: int = 0,
    winners: int = 0,
    non_winners: int = 0,
    would_execute: int = 0,
) -> Dict[str, Any]:
    return {
        "agentic_agreed_events": agreed,
        "agentic_authorized_events": authorized,
        "atomic_claim_winner_events": winners,
        "authorized_non_winner_events": non_winners,
        "claim_winner_behavior": (
            "SELECTED_WOULD_EXECUTE_DRY_RUN_SUPPRESSED"
            if winners and would_execute else "NO_CLAIM_WINNER"
        ),
        "authorized_non_winner_behavior": (
            "ABSTAINED_OTHER_COORDINATOR"
            if non_winners else "NO_AUTHORIZED_NON_WINNER"
        ),
        "attempted_execution_events": 0,
        "executed_events": 0,
        "would_execute_events": would_execute,
    }


def protocol_cases() -> List[Dict[str, Any]]:
    """Retorna cópias novas das seis fixtures e de seus oráculos declarados."""
    cases = [
        {
            "case_id": "agreed-executor",
            "title": "AGREED — claim winner",
            "evidence": {
                "scope": "local_agent_observation",
                "event_count": 1,
                "event_counts_by_layer": {"agentic": 1},
                "event_counts_by_state": {"AGREED": 1},
                "transitions": [
                    _transition("agentic", "AGREED", DOMAINS[0])
                ],
                "relevant_domains": DOMAINS,
                "participating_domains": DOMAINS,
                "model_ids": [MODEL_ID],
                "required_votes": 2,
                "mitigate_votes": DOMAINS,
                "quorum_reached": True,
                "authority_authorized": True,
                "execution_requested_by_final_decision": True,
                "local_agent_is_claim_winner": True,
                "other_coordinator_elected": False,
                "claim_winners": [DOMAINS[0]],
                "execution_mode": "authority-dry-run",
                "normalized_facts": _facts(
                    agreed=1, authorized=1, winners=1, would_execute=1
                ),
                "laboratory_context": {
                    "scenario": "ddos",
                    "ground_truth_available": True,
                },
            },
            "expected": {
                "protocol_consistency": "CONSISTENT",
                "scenario_correctness": "CORRECT",
                "decision_stage": "FINAL",
                "execution_status": "DRY_RUN_SUPPRESSED",
                "operational_effectiveness": "NOT_APPLICABLE",
            },
        },
        {
            "case_id": "waiting-proposals",
            "title": "WAITING_PROPOSALS — missing domain",
            "evidence": {
                "scope": "local_agent_observation",
                "event_count": 1,
                "event_counts_by_layer": {"agentic": 1},
                "event_counts_by_state": {"WAITING_PROPOSALS": 1},
                "transitions": [
                    _transition("agentic", "WAITING_PROPOSALS", DOMAINS[0])
                ],
                "relevant_domains": DOMAINS,
                "participating_domains": [DOMAINS[0]],
                "missing_domains": [DOMAINS[1]],
                "model_ids": [MODEL_ID],
                "required_votes": 2,
                "mitigate_votes": [DOMAINS[0]],
                "quorum_reached": False,
                "execution_requested_by_final_decision": False,
                "other_coordinator_elected": False,
                "claim_winners": [],
                "execution_mode": "authority-dry-run",
                "normalized_facts": _facts(),
                "laboratory_context": {
                    "scenario": "ddos",
                    "ground_truth_available": True,
                },
            },
            "expected": {
                "protocol_consistency": "CONSISTENT",
                "scenario_correctness": "UNKNOWN",
                "decision_stage": "INTERMEDIATE",
                "execution_status": "NOT_REQUESTED",
                "operational_effectiveness": "NOT_APPLICABLE",
            },
        },
        {
            "case_id": "agreed-non-executor",
            "title": "AGREED — authorized non-winner",
            "evidence": {
                "scope": "local_agent_observation",
                "event_count": 1,
                "event_counts_by_layer": {"agentic": 1},
                "event_counts_by_state": {"AGREED": 1},
                "transitions": [
                    _transition("agentic", "AGREED", DOMAINS[1])
                ],
                "relevant_domains": DOMAINS,
                "participating_domains": DOMAINS,
                "model_ids": [MODEL_ID],
                "required_votes": 2,
                "mitigate_votes": DOMAINS,
                "quorum_reached": True,
                "authority_authorized": True,
                "execution_requested_by_final_decision": True,
                "local_agent_is_claim_winner": False,
                "other_coordinator_elected": True,
                "claim_winners": [],
                "known_claim_coordinator": DOMAINS[0],
                "execution_mode": "authority-dry-run",
                "normalized_facts": _facts(
                    agreed=1, authorized=1, non_winners=1
                ),
                "laboratory_context": {
                    "scenario": "ddos",
                    "ground_truth_available": True,
                },
            },
            "expected": {
                "protocol_consistency": "CONSISTENT",
                "scenario_correctness": "CORRECT",
                "decision_stage": "FINAL",
                "execution_status": "SKIPPED_OTHER_COORDINATOR",
                "operational_effectiveness": "NOT_APPLICABLE",
            },
        },
        {
            "case_id": "corroborated",
            "title": "CORROBORATED — evidence below quorum",
            "evidence": {
                "scope": "local_agent_observation",
                "event_count": 1,
                "event_counts_by_layer": {"mcda": 1},
                "event_counts_by_state": {"CORROBORATED": 1},
                "transitions": [
                    _transition("mcda", "CORROBORATED", DOMAINS[0])
                ],
                "relevant_domains": DOMAINS,
                "participating_domains": [DOMAINS[0]],
                "confirming_domains": [DOMAINS[0]],
                "model_ids": [MODEL_ID],
                "required_votes": 2,
                "quorum_reached": False,
                "execution_requested_by_final_decision": False,
                "other_coordinator_elected": False,
                "claim_winners": [],
                "execution_mode": "authority-dry-run",
                "normalized_facts": _facts(),
                "laboratory_context": {
                    "scenario": "ddos",
                    "ground_truth_available": True,
                },
            },
            "expected": {
                "protocol_consistency": "CONSISTENT",
                "scenario_correctness": "UNKNOWN",
                "decision_stage": "INTERMEDIATE",
                "execution_status": "NOT_REQUESTED",
                "operational_effectiveness": "NOT_APPLICABLE",
            },
        },
        {
            "case_id": "vetoed",
            "title": "VETOED — destination whitelist",
            "evidence": {
                "scope": "local_agent_observation",
                "event_count": 1,
                "event_counts_by_layer": {"agentic": 1},
                "event_counts_by_state": {"VETOED": 1},
                "transitions": [
                    _transition("agentic", "VETOED", DOMAINS[0])
                ],
                "relevant_domains": DOMAINS,
                "participating_domains": DOMAINS,
                "model_ids": [MODEL_ID],
                "required_votes": 2,
                "mitigate_votes": [DOMAINS[0]],
                "veto_domains": [DOMAINS[1]],
                "veto_reason": "destination_whitelist",
                "quorum_reached": False,
                "execution_requested_by_final_decision": False,
                "other_coordinator_elected": False,
                "claim_winners": [],
                "execution_mode": "authority-dry-run",
                "normalized_facts": _facts(),
                "laboratory_context": {
                    "scenario": "ddos_with_destination_whitelist",
                    "ground_truth_available": True,
                    "applicable_policy": "whitelisted destination must veto",
                },
            },
            "expected": {
                "protocol_consistency": "CONSISTENT",
                "scenario_correctness": "CORRECT",
                "decision_stage": "FINAL",
                "execution_status": "NOT_REQUESTED",
                "operational_effectiveness": "NOT_APPLICABLE",
            },
        },
        {
            "case_id": "normal-benign",
            "title": "NORMAL — benign traffic",
            "evidence": {
                "scope": "multi_domain_decision",
                "event_count": 1,
                "event_counts_by_layer": {"mcda": 1},
                "event_counts_by_state": {"NORMAL": 1},
                "transitions": [
                    _transition("mcda", "NORMAL", DOMAINS[0])
                ],
                "relevant_domains": DOMAINS,
                "participating_domains": DOMAINS,
                "confirming_domains": [],
                "normal_votes": DOMAINS,
                "model_ids": [MODEL_ID],
                "required_votes": 2,
                "quorum_reached": False,
                "anomaly_threshold_confirmed": False,
                "execution_requested_by_final_decision": False,
                "other_coordinator_elected": False,
                "claim_winners": [],
                "execution_mode": "authority-dry-run",
                "normalized_facts": _facts(),
                "laboratory_context": {
                    "scenario": "benign",
                    "ground_truth_available": True,
                },
            },
            "expected": {
                "protocol_consistency": "CONSISTENT",
                "scenario_correctness": "CORRECT",
                "decision_stage": "FINAL",
                "execution_status": "NOT_REQUESTED",
                "operational_effectiveness": "NOT_APPLICABLE",
            },
        },
    ]
    for case in cases:
        case["evidence"]["fixture_id"] = case["case_id"]
        case["evidence"]["evidence_origin"] = "synthetic_protocol_fixture"
    # A JSON round-trip prevents callers from sharing mutable nested values.
    return json.loads(json.dumps(cases))


def summarize_campaign(report: Dict[str, Any]) -> Dict[str, Any]:
    evaluations = report.get("evaluations") or []
    completed = [item for item in evaluations if "comparison" in item]
    complete_matches = sum(
        item["comparison"]["all_match"] is True for item in completed
    )
    fields: Dict[str, Dict[str, Any]] = {}
    for field in VERDICT_FIELDS:
        matches = sum(
            item["comparison"]["fields"][field]["matches"] is True
            for item in completed
        )
        fields[field] = {
            "matches": matches,
            "evaluations": len(completed),
            "match_rate": matches / len(completed) if completed else None,
        }

    by_case: Dict[str, Dict[str, Any]] = {}
    for case in report.get("cases") or []:
        case_rows = [
            item for item in completed if item["case_id"] == case["case_id"]
        ]
        matches = sum(
            item["comparison"]["all_match"] is True for item in case_rows
        )
        by_case[case["case_id"]] = {
            "title": case["title"],
            "evaluations": len(case_rows),
            "complete_matches": matches,
            "complete_match_rate": (
                matches / len(case_rows) if case_rows else None
            ),
        }
    group_results: Dict[str, Dict[str, Any]] = {}
    for group in sorted({case.get("group", "development")
                         for case in report.get("cases") or []}):
        group_ids = {case["case_id"] for case in report["cases"]
                     if case.get("group", "development") == group}
        rows = [item for item in completed if item["case_id"] in group_ids]
        matches = sum(item["comparison"]["all_match"] is True for item in rows)
        group_results[group] = {
            "unique_cases": len(group_ids),
            "evaluations": len(rows),
            "complete_matches": matches,
            "complete_match_rate": matches / len(rows) if rows else None,
        }
    field_matches = sum(values["matches"] for values in fields.values())
    fields_total = len(completed) * len(VERDICT_FIELDS)
    return {
        "evaluations_planned": len(report.get("cases") or [])
        * len(report.get("seeds") or []),
        "evaluations_completed": len(completed),
        "complete_matches": complete_matches,
        "complete_match_rate": (
            complete_matches / len(completed) if completed else None
        ),
        "field_results": fields,
        "case_results": by_case,
        "group_results": group_results,
        "individual_fields_matched": field_matches,
        "individual_fields_evaluated": fields_total,
        "individual_field_match_rate": (
            field_matches / fields_total if fields_total else None
        ),
    }


def new_report(
    cases: Sequence[Dict[str, Any]],
    *,
    model: str,
    seeds: Sequence[int],
    temperature: float,
    num_ctx: int,
    keep_alive: Any,
    suite: str = "development",
    dataset_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "campaign_type": "synthetic-protocol-fixtures",
        "suite": suite,
        "evidence_origin": "synthetic_protocol_fixture",
        "limitations": [
            "The fixtures are declared protocol examples, not network runs.",
            "The campaign measures LLM interpretation, not detection accuracy, "
            "coordination scalability, or mitigation effectiveness.",
            "Repeated seeds on the same fixtures are not independent network "
            "experiments.",
        ],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "seeds": list(seeds),
        "inference_parameters": {
            "temperature": temperature,
            "num_ctx": num_ctx,
            "keep_alive": keep_alive,
        },
        "cases": list(cases),
        "evaluations": [],
        "campaign_status": "RUNNING",
        "evaluation_contract": current_contract_hashes(),
        "selected_cases_sha256": canonical_sha256(list(cases)),
    }
    if dataset_metadata:
        report["dataset"] = dataset_metadata
        report["limitations"].extend(dataset_metadata.get("limitations") or [])
    report["summary"] = summarize_campaign(report)
    return report


def evaluate_campaign(
    report: Dict[str, Any],
    *,
    client_factory: Callable[[int], OllamaAuditClient],
    checkpoint: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Executa cada combinação caso/seed e atualiza o relatório incremental."""
    for seed in report["seeds"]:
        client = client_factory(seed)
        for case in report["cases"]:
            response = client.evaluate(case["evidence"])
            report["evaluations"].append({
                "case_id": case["case_id"],
                "seed": seed,
                "expected": case["expected"],
                "llm_evaluation": response,
                "comparison": compare_verdicts(
                    case["expected"], response["result"]
                ),
            })
            report["summary"] = summarize_campaign(report)
            if checkpoint:
                checkpoint(report)
    report["campaign_status"] = "COMPLETED"
    report["summary"] = summarize_campaign(report)
    if checkpoint:
        checkpoint(report)
    return report


def render_markdown(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    rate = summary["complete_match_rate"]
    rate_text = "n/a" if rate is None else f"{100 * rate:.1f}%"
    lines = [
        "# CoMAS LLM protocol campaign",
        "",
        "> These inputs are synthetic protocol fixtures, not network runs. "
        "Results measure interpretation only.",
        "",
        f"- Model: `{report['model']}`",
        f"- Suite: `{report.get('suite', 'development')}`",
        f"- Seeds: `{', '.join(str(seed) for seed in report['seeds'])}`",
        f"- Status: `{report['campaign_status']}`",
        f"- Complete matches: `{summary['complete_matches']}/"
        f"{summary['evaluations_completed']}` (`{rate_text}`)",
        "",
        "## Results",
        "",
        "| Case | Seed | All fields match | Confidence | Duration (s) |",
        "| --- | ---: | :---: | ---: | ---: |",
    ]
    titles = {case["case_id"]: case["title"] for case in report["cases"]}
    for item in report["evaluations"]:
        response = item["llm_evaluation"]
        confidence = response["result"].get("confidence")
        duration_ns = (response.get("metrics") or {}).get("total_duration_ns")
        duration = (
            f"{duration_ns / 1e9:.3f}"
            if isinstance(duration_ns, (int, float)) else "n/a"
        )
        lines.append(
            f"| {titles[item['case_id']]} | {item['seed']} | "
            f"{item['comparison']['all_match']} | {confidence} | {duration} |"
        )
    lines.extend([
        "",
        "## Field-level agreement",
        "",
        "| Field | Matches | Rate |",
        "| --- | ---: | ---: |",
    ])
    for field, values in summary["field_results"].items():
        field_rate = values["match_rate"]
        field_rate_text = (
            "n/a" if field_rate is None else f"{100 * field_rate:.1f}%"
        )
        lines.append(
            f"| `{field}` | {values['matches']}/"
            f"{values['evaluations']} | {field_rate_text} |"
        )
    lines.extend([
        "", "## Case-group agreement", "",
        "| Group | Unique cases | Complete matches |",
        "| --- | ---: | ---: |",
    ])
    for group, values in summary["group_results"].items():
        lines.append(
            f"| {group} | {values['unique_cases']} | "
            f"{values['complete_matches']}/{values['evaluations']} |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.append("")
    return "\n".join(lines)


def _parse_seeds(value: str) -> List[int]:
    try:
        seeds = [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seeds devem ser inteiros") from exc
    if not seeds:
        raise argparse.ArgumentTypeError("informe pelo menos uma seed")
    if len(seeds) != len(set(seeds)):
        raise argparse.ArgumentTypeError("seeds não podem se repetir")
    return seeds


def _parse_keep_alive(value: str) -> Any:
    try:
        return int(value)
    except ValueError:
        return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Avalia fixtures de desenvolvimento ou validação do CoMAS"
    )
    parser.add_argument(
        "--suite", choices=("development", "holdout-v1"), default="development"
    )
    parser.add_argument("--model", default="qwen3.5:9b")
    parser.add_argument(
        "--ollama-url",
        default=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seeds", type=_parse_seeds, default=[42])
    parser.add_argument("--num-ctx", type=int, default=4096)
    parser.add_argument("--keep-alive", type=_parse_keep_alive, default="5m")
    parser.add_argument(
        "--case", action="append",
        help="executa somente o caso indicado; pode ser repetido",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("llm_protocol_campaign.json")
    )
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument(
        "--manifest-only", action="store_true",
        help="materializa entradas, oráculos e checksums sem consultar a LLM",
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="permite sobrescrever arquivos de saída existentes",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cases = protocol_cases()
    metadata = None
    if args.suite == "holdout-v1":
        try:
            dataset = load_holdout_dataset()
        except (OSError, ValueError) as exc:
            print(f"erro: {exc}", file=sys.stderr)
            return 2
        cases = dataset["cases"]
        metadata = {key: value for key, value in dataset.items() if key != "cases"}
        if args.temperature != 0.0 or args.num_ctx != 4096:
            parser.error("holdout-v1 mantém temperature=0 e num_ctx=4096")
    if args.case:
        selected = set(args.case)
        unknown = selected - {case["case_id"] for case in cases}
        if unknown:
            parser.error("casos ausentes da suite: " + ", ".join(sorted(unknown)))
        cases = [case for case in cases if case["case_id"] in selected]
    if metadata:
        metadata["subset_selected"] = len(cases) != 16
    report = new_report(
        cases,
        model=args.model,
        seeds=args.seeds,
        temperature=args.temperature,
        num_ctx=args.num_ctx,
        keep_alive=args.keep_alive,
        suite=args.suite,
        dataset_metadata=metadata,
    )
    markdown = args.markdown_output or args.output.with_suffix(".md")
    if args.output.resolve() == markdown.resolve():
        parser.error("JSON e Markdown precisam de caminhos diferentes")
    if not args.overwrite and (args.output.exists() or markdown.exists()):
        parser.error("saída já existe; use um novo nome ou --overwrite")
    progress = 0

    def checkpoint(current: Dict[str, Any]) -> None:
        nonlocal progress
        args.output.write_text(
            json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        markdown.write_text(render_markdown(current), encoding="utf-8")
        done = current["summary"]["evaluations_completed"]
        if done > progress:
            last = current["evaluations"][-1]
            print(
                f"progress: {done}/{current['summary']['evaluations_planned']} "
                f"case={last['case_id']} seed={last['seed']} "
                f"all_match={last['comparison']['all_match']}",
                flush=True,
            )
            progress = done

    def client_factory(seed: int) -> OllamaAuditClient:
        return OllamaAuditClient(
            model=args.model,
            base_url=args.ollama_url,
            temperature=args.temperature,
            seed=seed,
            num_ctx=args.num_ctx,
            keep_alive=args.keep_alive,
        )

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        markdown.parent.mkdir(parents=True, exist_ok=True)
        if args.manifest_only:
            report["campaign_status"] = "MANIFEST_ONLY"
        checkpoint(report)
        if not args.manifest_only:
            evaluate_campaign(
                report, client_factory=client_factory, checkpoint=checkpoint
            )
    except (OSError, ValueError, OllamaAuditError) as exc:
        report["campaign_status"] = "PARTIAL_ERROR"
        report["error"] = str(exc)
        report["summary"] = summarize_campaign(report)
        try:
            checkpoint(report)
        except OSError:
            pass
        print(f"erro: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    print(f"campaign:  {report['campaign_status']}")
    print(f"fixtures:  {len(cases)}")
    print(f"seeds:     {len(args.seeds)}")
    print(
        f"matches:   {summary['complete_matches']}/"
        f"{summary['evaluations_completed']}"
    )
    print(f"json:      {args.output}")
    print(f"markdown:  {markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
