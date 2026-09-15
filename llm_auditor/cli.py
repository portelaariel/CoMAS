"""Interface de linha de comando do auditor pós-experimento."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .core import audit_run, compare_verdicts, evaluation_evidence
from .ollama import OllamaAuditClient, OllamaAuditError


def apply_llm(
    report: Dict[str, Any],
    *,
    mode: str,
    client: OllamaAuditClient,
) -> Dict[str, Any]:
    for episode in report.get("episodes") or []:
        if mode == "explain":
            episode["llm_explanation"] = client.explain(episode)
        elif mode == "evaluate":
            response = client.evaluate(evaluation_evidence(episode))
            episode["llm_evaluation"] = response
            episode["llm_vs_deterministic"] = compare_verdicts(
                episode, response["result"]
            )
        else:
            raise ValueError(f"modo LLM desconhecido: {mode}")
    return report


def render_markdown(report: Dict[str, Any], mode: str) -> str:
    run = report["run"]
    lines: List[str] = [
        f"# CoMAS post-experiment audit — {run['name']}",
        "",
        f"- Scenario: `{run.get('scenario')}`",
        f"- Classification: `{run.get('classification')}`",
        f"- Agent mode: `{run.get('agentic_mode')}`",
        f"- Audit mode: `{mode}`",
        f"- Rules version: `{report.get('rules_version', 'legacy')}`",
        f"- Events: `{report.get('events_seen')}`",
        f"- Status: `{run.get('audit_status')}`",
        "",
    ]
    if not report.get("episodes"):
        lines.extend([
            "No auditable decision event was recorded for this run.", ""
        ])
        return "\n".join(lines)

    for episode in report["episodes"]:
        lines.extend([
            f"## {episode['flow']} — {episode['episode_id']}",
            "",
            f"- Decision stage: `{episode['decision_stage']}`",
            f"- Protocol consistency: `{episode['protocol_consistency']}`",
            f"- Scenario correctness: `{episode['scenario_correctness']}`",
            f"- Execution status: `{episode['execution_status']}`",
            "- Operational effectiveness: "
            f"`{episode['operational_effectiveness']}`",
            f"- Claim winner(s): `{', '.join(episode.get('claim_winners') or []) or 'not observed'}`",
            "",
            "### Consolidated transitions",
            "",
        ])
        for transition in episode["transitions"]:
            lines.append(
                f"- `{transition['layer']}` → `{transition['state']}` "
                f"(`{transition['observed_by']}`)"
            )
        lines.extend(["", "### Deterministic checks", ""])
        for check in episode["checks"]:
            lines.extend([
                f"- `{check['status']}` — `{check['name']}` "
                f"(`{check.get('dimension', 'protocol_consistency')}`)",
                f"  - Rule: `{check.get('rule_id', check['name'])}`",
                f"  - Reason: {check.get('reason', '')}",
                "  - Evidence: `" + json.dumps(check['evidence'], ensure_ascii=False) + "`",
            ])
            if check.get("missing_fields"):
                lines.append("  - Missing fields: `" + ", ".join(check["missing_fields"]) + "`")
            for ref in check.get("source_refs") or []:
                lines.append(
                    f"  - Source: `{ref.get('artifact')}` "
                    f"line `{ref.get('line', 'n/a')}`, pointer `{ref.get('pointer')}`"
                    + (f", event `{ref['event_id']}`" if ref.get('event_id') else "")
                )

        explanation = episode.get("llm_explanation")
        evaluation = episode.get("llm_evaluation")
        if explanation:
            result = explanation["result"]
            lines.extend(["", "### LLM explanation", "", result["summary"], ""])
        if evaluation:
            result = evaluation["result"]
            agreement = episode["llm_vs_deterministic"]
            lines.extend([
                "", "### Experimental LLM evaluation", "",
                result["summary"], "",
                f"Agreement with deterministic evaluator: `{agreement['all_match']}`",
                "",
            ])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audita decisões do CoMAS após o experimento"
    )
    parser.add_argument("run_dir", type=Path)
    parser.add_argument(
        "--mode", choices=("audit", "explain", "evaluate"), default="audit",
        help="audit é determinístico; explain/evaluate consultam o Ollama",
    )
    parser.add_argument("--model", default="qwen3.5:9b")
    parser.add_argument(
        "--ollama-url",
        default=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--num-ctx", type=int, default=4096)
    parser.add_argument("--episode-gap-s", type=float, default=15.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--overwrite", action="store_true",
                        help="permite substituir relatórios existentes, nunca artefatos de entrada")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    output = args.output or (args.run_dir / f"llm_audit_{args.mode}.json")
    markdown = args.markdown_output or output.with_suffix(".md")
    try:
        if output.resolve() == markdown.resolve():
            raise ValueError("JSON e Markdown precisam de caminhos diferentes")
        inputs = {(args.run_dir / name).resolve() for name in (
            "metadata.json", "summary.json", "timeline.ndjson", "attack_start_ns.txt",
        )}
        for path in (output, markdown):
            if path.resolve() in inputs:
                raise ValueError(f"não é permitido substituir artefato de entrada: {path}")
            if path.exists() and not args.overwrite:
                raise ValueError(f"relatório já existe: {path}; use outro nome ou --overwrite")
            path.parent.mkdir(parents=True, exist_ok=True)
        report = audit_run(args.run_dir, episode_gap_s=args.episode_gap_s)
        if args.mode != "audit":
            client = OllamaAuditClient(
                model=args.model,
                base_url=args.ollama_url,
                temperature=args.temperature,
                seed=args.seed,
                num_ctx=args.num_ctx,
                keep_alive=0,
            )
            apply_llm(report, mode=args.mode, client=client)
        output.write_text(
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        markdown.write_text(render_markdown(report, args.mode), encoding="utf-8")
    except (OSError, ValueError, OllamaAuditError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2

    print(f"audit mode: {args.mode}")
    print(f"events:    {report['events_seen']}")
    print(f"episodes:  {len(report['episodes'])}")
    print(f"json:      {output}")
    print(f"markdown:  {markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
