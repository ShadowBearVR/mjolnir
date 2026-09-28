# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for mjolnir-eval: 3-run ablation studies, baseline comparisons, and scorecard export."""

import argparse
import json
from pathlib import Path
import sys

from evaluation.constants import ABLATION_TIERS
from evaluation.runner import EvaluationRunner
from evaluation.scorecard import ScorecardGenerator
from utilities.logger import setup_logger


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mjolnir-eval",
        description="Mjolnir Evaluation & Ablation Suite",
    )
    parser.add_argument(
        "--spec",
        required=True,
        help="Path to Mjolnir evaluation project spec JSON",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. benchmark subcommand
    bench_parser = subparsers.add_parser(
        "benchmark",
        help="Run 3-run Mjolnir ablation and external CLI/SAST baselines against a vulnerability dataset",
    )
    bench_parser.add_argument(
        "--dataset-id",
        default="v1_ncm",
        help="Dataset identifier to evaluate",
    )
    bench_parser.add_argument(
        "--tiers",
        default="no_tm,no_expert,full",
        help=f"Comma-separated evaluation tiers ({', '.join(ABLATION_TIERS.keys())})",
    )
    bench_parser.add_argument(
        "--repetitions",
        type=int,
        default=1,
        help="Number of statistical repetitions per tier (e.g. 3 or 10)",
    )
    bench_parser.add_argument(
        "--instances",
        help="Optional comma-separated list of vuln_ids to evaluate",
    )
    bench_parser.add_argument(
        "--evaluator-model",
        help="Override LLM model for Mjolnir evaluation runs",
    )
    bench_parser.add_argument(
        "--judge-model",
        help="Optional LLM model for Step-2 semantic root-cause grading (e.g. gemini-3.8-flash)",
    )
    bench_parser.add_argument(
        "--cli-template",
        action="append",
        default=[],
        help="Override CLI command template as KEY=TEMPLATE (e.g. gemini='gemini -p {prompt} --yolo')",
    )
    bench_parser.add_argument(
        "--no-expand-checkpoints",
        action="store_true",
        help="Disable automatic extraction of per-phase history checkpoints (@discovery, @deduplication, etc.)",
    )
    bench_parser.add_argument(
        "--corpus-dir",
        help="Override root corpus directory",
    )
    bench_parser.add_argument(
        "--output-dir",
        help="Override evaluation output directory",
    )

    # 2. scorecard subcommand
    score_parser = subparsers.add_parser(
        "scorecard",
        help="Aggregate grades.json into Markdown tables and USENIX Security LaTeX booktabs",
    )
    score_parser.add_argument(
        "--grades",
        required=True,
        help="Path to grades.json produced by 'mjolnir-eval benchmark'",
    )
    score_parser.add_argument(
        "--output-dir",
        help="Optional directory to write scorecard artifacts",
    )

    args = parser.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        sys.stderr.write(f"Error: Evaluation spec file not found: {spec_path}\n")
        sys.exit(1)

    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    config = spec.get("config", {})
    corpus_root = Path(
        getattr(args, "corpus_dir", None) or config.get("corpusDir") or "./evaluations/corpus"
    )
    output_root = Path(
        getattr(args, "output_dir", None) or config.get("outputDir") or "./test-out/evaluations"
    )
    cache_root = Path(config.get("cacheDir") or "./test-out/eval-cache")
    output_root.mkdir(parents=True, exist_ok=True)
    setup_logger(str(output_root / "mjolnir-eval.log"))

    if args.subcommand == "benchmark":
        tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]
        instance_filter = (
            [i.strip() for i in args.instances.split(",") if i.strip()] if args.instances else None
        )
        cli_overrides: dict[str, str] = {}
        for item in args.cli_template:
            if "=" in item:
                k, v = item.split("=", 1)
                cli_overrides[k.strip()] = v.strip()

        runner = EvaluationRunner(
            spec=spec,
            corpus_root=corpus_root,
            output_root=output_root,
            cache_root=cache_root,
            mjolnir_bin=config.get("mjolnirBin", "mjolnir-run"),
            evaluator_model=args.evaluator_model,
            judge_model=args.judge_model,
            cli_templates=cli_overrides,
        )
        grades = runner.run_benchmark(
            dataset_id=args.dataset_id,
            tiers=tiers,
            repetitions=args.repetitions,
            instance_filter=instance_filter,
            expand_checkpoints=not args.no_expand_checkpoints,
        )
        if grades:
            grades_path = (
                output_root / spec["project"]["repoName"] / args.dataset_id / "grades.json"
            )
            ScorecardGenerator().generate_scorecard(grades_path)
    elif args.subcommand == "scorecard":
        grades_path = Path(args.grades)
        out_dir = Path(args.output_dir) if args.output_dir else grades_path.parent
        ScorecardGenerator().generate_scorecard(grades_path, output_dir=out_dir)


if __name__ == "__main__":
    main()
