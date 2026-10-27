# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for mjolnir-eval: real-world pinned RoT evaluations, blind per-finding review, and LaTeX booktabs scorecards."""

import argparse
import json
from pathlib import Path
import sys

from evaluation.constants import ABLATION_TIERS
from evaluation.grader import FindingPooler
from evaluation.models import TrialRunRecord
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
        default="full",
        help=f"Comma-separated evaluation tiers (default: full; choices: {', '.join(ABLATION_TIERS.keys())})",
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
        help="Override LLM model(s) for Mjolnir evaluation runs (comma-separated, e.g. gemini-3.8-flash,gemini-4-argon,vertex_ai/claude-sonnet-5-5)",
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
        required=False,
        help="Path to Mjolnir evaluation project spec JSON (required for 'run'/'benchmark')",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. run (and alias benchmark) subcommand
    run_parser = subparsers.add_parser(
        "run",
        help="Run Mjolnir ablation tiers and single-agent baselines on the pinned repository snapshot",
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
        help="Build provenance-stripped per-finding blind_review_pool.json, blind_review_pool.md, and blind_review/ web bundle",
    )
    pool_parser.add_argument(
        "--eval-dir",
        required=True,
        help="Evaluation output directory containing trials_manifest.json",
    )

    # 3. scorecard subcommand
    score_parser = subparsers.add_parser(
        "scorecard",
        help="Join trials_manifest.json and blind_review_pool.json into RQ1-RQ4 Markdown and LaTeX booktabs tables",
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

    # 4. sample-pool subcommand
    sample_parser = subparsers.add_parser(
        "sample-pool",
        help="Apply deterministic 154-card stratified Horvitz-Thompson sampling and emit Pass-1 SPA deck",
    )
    sample_parser.add_argument(
        "--eval-dir",
        required=True,
        help="Evaluation output directory containing blind_review_pool.json",
    )
    sample_parser.add_argument(
        "--seed",
        default="mjolnir-blind-sample-v1",
        help="Deterministic SHA-256 sampling seed",
    )
    sample_parser.add_argument(
        "--threat-model",
        help="Optional path to verbatim project threat_model.md to bundle into pass1_deck.json",
    )

    # 5. import-labels subcommand
    import_parser = subparsers.add_parser(
        "import-labels",
        help="Import exported Reviewer 1 / Reviewer 2 / Adjudication / Pass-2 JSON files and regenerate scorecard",
    )
    import_parser.add_argument(
        "--eval-dir",
        required=True,
        help="Evaluation output directory containing blind_review_pool.json",
    )
    import_parser.add_argument("--r1", help="Path to Reviewer 1 exported JSON file")
    import_parser.add_argument("--r2", help="Path to Reviewer 2 exported JSON file")
    import_parser.add_argument("--adjudication", help="Path to Adjudication JSON file")
    import_parser.add_argument("--pass2", help="Path to Pass-2 PoC audit JSON file")

    # 6. build-pass2-deck subcommand
    pass2_parser = subparsers.add_parser(
        "build-pass2-deck",
        help="Emit Pass-2 PoC audit SPA deck (confirmed TPs with poc_verified=True) after Pass 1 completes",
    )
    pass2_parser.add_argument(
        "--eval-dir",
        required=True,
        help="Evaluation output directory containing adjudicated blind_review_pool.json",
    )
    pass2_parser.add_argument(
        "--threat-model",
        help="Optional path to verbatim project threat_model.md",
    )

    args = parser.parse_args()

    spec: dict = {}
    if args.spec:
        spec_path = Path(args.spec)
        if not spec_path.exists():
            sys.stderr.write(f"Error: Evaluation spec file not found: {spec_path}\n")
            sys.exit(1)
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
    elif args.subcommand in ("run", "benchmark"):
        sys.stderr.write("Error: --spec is required for 'run' and 'benchmark'\n")
        sys.exit(1)

    config = spec.get("config", {})
    output_root = Path(
        getattr(args, "output_dir", None) or config.get("outputDir") or "./test-out/evaluations"
    )
    cache_root = Path(config.get("cacheDir") or "./test-out/eval-cache")
    output_root.mkdir(parents=True, exist_ok=True)
    setup_logger(str(output_root / "mjolnir-eval.log"))

    if args.subcommand in ("run", "benchmark"):
        from evaluation.runner import EvaluationRunner

        tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]

        runner = EvaluationRunner(
            spec=spec,
            output_root=output_root,
            cache_root=cache_root,
            mjolnir_bin=config.get("mjolnirBin", "mjolnir-run"),
            evaluator_model=args.evaluator_model,
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
        FindingPooler().build_pool(
            trials=trials,
            output_dir=target_dir,
        )
    elif args.subcommand == "scorecard":
        eval_path = Path(args.eval_path)
        out_dir = Path(args.output_dir) if args.output_dir else None
        ScorecardGenerator().generate_scorecard(eval_path, output_dir=out_dir)
    elif args.subcommand == "sample-pool":
        eval_dir = Path(args.eval_dir)
        tm_path = Path(args.threat_model) if args.threat_model else None
        FindingPooler().sample_blind_pool(
            eval_dir=eval_dir,
            seed=args.seed,
            threat_model_path=tm_path,
        )
    elif args.subcommand == "import-labels":
        eval_dir = Path(args.eval_dir)
        FindingPooler().import_reviewer_labels(
            eval_dir=eval_dir,
            r1_path=Path(args.r1) if args.r1 else None,
            r2_path=Path(args.r2) if args.r2 else None,
            adjudication_path=Path(args.adjudication) if args.adjudication else None,
            pass2_path=Path(args.pass2) if args.pass2 else None,
        )
        ScorecardGenerator().generate_scorecard(eval_dir)
    elif args.subcommand == "build-pass2-deck":
        eval_dir = Path(args.eval_dir)
        tm_path = Path(args.threat_model) if args.threat_model else None
        FindingPooler.write_pass2_poc_spa_deck(
            eval_dir=eval_dir,
            out_path=eval_dir / "blind_review" / "pass2_poc_deck.json",
            threat_model_path=tm_path,
        )


if __name__ == "__main__":
    main()
