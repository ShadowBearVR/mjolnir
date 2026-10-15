# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for mjolnir-eval: real-world pinned RoT evaluations, blind review pooling, and USENIX scorecards."""

import argparse
import json
from pathlib import Path
import sys

from evaluation.constants import ABLATION_TIERS
from evaluation.grader import FindingPooler
from evaluation.models import TrialRunRecord
from evaluation.runner import EvaluationRunner
from evaluation.scorecard import ScorecardGenerator
from utilities.logger import setup_logger


def _add_run_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--run-label",
        "--dataset-id",
        dest="run_label",
        default="pinned",
        help="Run output subdirectory label under <output-dir>/<repo> (default: pinned)",
    )
    p.add_argument(
        "--tiers",
        default="no_tm,no_expert,full",
        help=f"Comma-separated evaluation tiers ({', '.join(ABLATION_TIERS.keys())})",
    )
    p.add_argument(
        "--repetitions",
        type=int,
        default=3,
        help="Number of statistical repetitions per tier (default: 3)",
    )
    p.add_argument(
        "--evaluator-model",
        "--models",
        dest="evaluator_model",
        help="Override LLM model(s) for Mjolnir evaluation runs (comma-separated, e.g. gemini-3.8-flash,gemini-4-argon,vertex_ai/claude-sonnet-4-6)",
    )
    p.add_argument(
        "--judge-model",
        help="Optional LLM model for semantic root-cause clustering (e.g. gemini-3.8-flash)",
    )
    p.add_argument(
        "--cli-template",
        action="append",
        default=[],
        help="Override CLI command template as KEY=TEMPLATE (e.g. antigravity='antigravity -p {prompt} --dangerously-skip-permissions')",
    )
    p.add_argument(
        "--no-expand-checkpoints",
        action="store_true",
        help="Disable automatic extraction of per-phase history checkpoints (@discovery, @deduplication, etc.)",
    )
    p.add_argument(
        "--force-rerun",
        action="store_true",
        help="Re-execute trials even if a successful (tier, repetition) record already exists in trials_manifest.json",
    )
    p.add_argument(
        "--output-dir",
        help="Override evaluation output directory",
    )
    p.add_argument(
        "--scope",
        help="Optional named scope from project spec (e.g. 'default' or 'smoke')",
    )
    p.add_argument(
        "--target-dir",
        help="Optional target directory or file path override relative to repo root",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mjolnir-eval",
        description="Mjolnir Real-World Pinned RoT Evaluation & Blind Review Suite",
    )
    parser.add_argument(
        "--spec",
        required=True,
        help="Path to Mjolnir evaluation project spec JSON",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. run (and alias benchmark) subcommand
    run_parser = subparsers.add_parser(
        "run",
        help="Run Mjolnir ablation tiers and external CLI/SAST baselines on the pinned repository snapshot",
    )
    _add_run_arguments(run_parser)

    bench_parser = subparsers.add_parser(
        "benchmark",
        help="Alias for 'run': execute evaluation tiers on the pinned repository snapshot",
    )
    _add_run_arguments(bench_parser)

    # 2. pool subcommand
    pool_parser = subparsers.add_parser(
        "pool",
        help="Cluster trial findings into a provenance-stripped blind_review_pool.json and blind_review_pool.md",
    )
    pool_parser.add_argument(
        "--eval-dir",
        required=True,
        help="Evaluation output directory containing trials_manifest.json",
    )
    pool_parser.add_argument(
        "--judge-model",
        help="Optional LLM model for semantic root-cause clustering",
    )

    # 3. scorecard subcommand
    score_parser = subparsers.add_parser(
        "scorecard",
        help="Join trials_manifest.json and blind_review_pool.json into RQ1-RQ4 Markdown and USENIX LaTeX tables",
    )
    score_parser.add_argument(
        "--eval-dir",
        "--grades",
        dest="eval_path",
        required=True,
        help="Path to evaluation output directory or trials_manifest.json",
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
    output_root = Path(
        getattr(args, "output_dir", None) or config.get("outputDir") or "./test-out/evaluations"
    )
    cache_root = Path(config.get("cacheDir") or "./test-out/eval-cache")
    output_root.mkdir(parents=True, exist_ok=True)
    setup_logger(str(output_root / "mjolnir-eval.log"))

    if args.subcommand in ("run", "benchmark"):
        tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]
        cli_overrides: dict[str, str] = {}
        for item in args.cli_template:
            if "=" in item:
                k, v = item.split("=", 1)
                cli_overrides[k.strip()] = v.strip()

        runner = EvaluationRunner(
            spec=spec,
            output_root=output_root,
            cache_root=cache_root,
            mjolnir_bin=config.get("mjolnirBin", "mjolnir-run"),
            evaluator_model=args.evaluator_model,
            judge_model=args.judge_model,
            cli_templates=cli_overrides,
            scope=args.scope,
            target_dir=args.target_dir,
        )
        trials = runner.run_evaluation(
            tiers=tiers,
            repetitions=args.repetitions,
            expand_checkpoints=not args.no_expand_checkpoints,
            run_label=args.run_label,
            force_rerun=args.force_rerun,
        )
        if trials:
            eval_dir = output_root / spec["project"]["repoName"] / args.run_label
            ScorecardGenerator().generate_scorecard(eval_dir)
    elif args.subcommand == "pool":
        eval_dir = Path(args.eval_dir)
        manifest_path = eval_dir if eval_dir.is_file() else eval_dir / "trials_manifest.json"
        target_dir = eval_dir.parent if eval_dir.is_file() else eval_dir
        raw_trials = json.loads(manifest_path.read_text(encoding="utf-8"))
        trials = [TrialRunRecord.model_validate(t) for t in raw_trials]
        FindingPooler(
            judge_model=args.judge_model or spec.get("project", {}).get("judgeModel")
        ).build_pool(trials=trials, output_dir=target_dir)
    elif args.subcommand == "scorecard":
        eval_path = Path(args.eval_path)
        out_dir = Path(args.output_dir) if args.output_dir else None
        ScorecardGenerator().generate_scorecard(eval_path, output_dir=out_dir)


if __name__ == "__main__":
    main()
