"""Regression check of deterministic rules against declared synthetic oracles.

This is not another LLM evaluation or an independent accuracy benchmark. The
previous holdout is now a regression corpus: its outcomes have been inspected.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .core import SCHEMA_VERSION, VERDICT_FIELDS, compare_verdicts
from .rules import RULES_VERSION, verify_evidence
from .validation_dataset import HOLDOUT_PATH, load_holdout_dataset


def evaluate_regression() -> Dict[str, Any]:
    dataset = load_holdout_dataset()
    evaluations = []
    for index, case in enumerate(dataset["cases"]):
        # No expected label or rationale is passed to the verifier.
        evidence = dict(case["evidence"])
        evidence["evidence_artifact"] = f"fixtures/holdout_v1.json#/cases/{index}/evidence"
        result = verify_evidence(evidence)
        evaluations.append({
            "case_id": case["case_id"], "group": case["group"],
            "expected": case["expected"], "deterministic_result": result,
            "comparison": compare_verdicts(case["expected"], result),
        })
    complete = sum(item["comparison"]["all_match"] for item in evaluations)
    return {
        "schema_version": SCHEMA_VERSION, "rules_version": RULES_VERSION,
        "audit_type": "deterministic-synthetic-regression",
        "dataset_id": dataset["dataset_id"], "dataset_sha256": dataset["dataset_sha256"],
        "evaluation_contract": dataset["evaluation_contract"],
        "summary": {
            "cases": len(evaluations), "complete_matches": complete,
            "complete_match_rate": complete / len(evaluations),
            "field_results": {
                field: {
                    "matches": sum(item["comparison"]["fields"][field]["matches"] for item in evaluations),
                    "cases": len(evaluations),
                } for field in VERDICT_FIELDS
            },
        },
        "evaluations": evaluations,
        "limitations": [
            "This corpus was inspected during rule development; agreement is a regression check, not generalization evidence.",
            "No LLM inference or network experiment is performed; no inference-quality or deployment-effectiveness claim follows.",
        ],
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# CoMAS deterministic verifier — synthetic regression", "",
        f"Rules version: `{report['rules_version']}`", "",
        f"Complete matches: `{report['summary']['complete_matches']}/{report['summary']['cases']}`", "",
        "This previously inspected corpus is a regression test, not an independent benchmark or LLM evaluation.", "",
    ]
    for item in report["evaluations"]:
        lines.extend([f"## {item['case_id']}", ""])
        result = item["deterministic_result"]
        for field in VERDICT_FIELDS:
            lines.append(f"- {field}: `{result[field]}`")
        lines.extend(["", "Checks:", ""])
        for check in result["checks"]:
            lines.append(f"- `{check['status']}` — `{check['name']}`: {check['reason']}")
        lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify deterministic rules without Ollama")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    markdown = args.output.with_suffix(".md")
    try:
        if args.output.resolve() == markdown.resolve():
            raise ValueError("JSON and Markdown outputs must be different files")
        for path in (args.output, markdown):
            if path.resolve() == HOLDOUT_PATH.resolve():
                raise ValueError("the frozen fixture corpus is not a valid output target")
            if path.exists() and not args.overwrite:
                raise ValueError(f"output already exists: {path}; choose another name or --overwrite")
        report = evaluate_regression()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        markdown.write_text(render_markdown(report), encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"regression: {report['summary']['complete_matches']}/{report['summary']['cases']}")
    print(f"json:       {args.output}")
    print(f"markdown:   {markdown}")
    return 0 if report["summary"]["complete_matches"] == report["summary"]["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
