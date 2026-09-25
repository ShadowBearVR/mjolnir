# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for Nidhogg: synthetic vulnerability generation, benchmarking, and scorecard export."""

import argparse
import json
from pathlib import Path
import sys

from nidhogg.benchmark.runner import BenchmarkRunner
from nidhogg.benchmark.scorecard import ScorecardGenerator
from nidhogg.constants import ABLATION_TIERS, NCM_PROFILES
from nidhogg.generation.pipeline import GenerationPipeline
from utilities.logger import logger, setup_logger


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nidhogg-run",
        description="Nidhogg: Synthetic Vulnerability Generation & Benchmarking Suite for Mjolnir",
    )
    parser.add_argument(
        "--spec",
        required=True,
        help="Path to Nidhogg benchmark project spec JSON",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. generate subcommand
    gen_parser = subparsers.add_parser(
        "generate",
        help="Synthesize CWE-grounded vulnerabilities across the 3D NCM matrix",
    )
    gen_parser.add_argument(
        "--dataset-id",
        default="v1_ncm",
        help="Dataset identifier under benchmarks/corpus/<project>/<dataset_id>",
    )
    gen_parser.add_argument(
        "--profile",
        choices=list(NCM_PROFILES.keys()),
        default="balanced",
        help="Declarative NCM complexity profile",
    )
    gen_parser.add_argument(
        "--count",
        type=int,
        default=3,
        help="Number of synthetic vulnerability instances to generate",
    )
    gen_parser.add_argument(
        "--scope",
        help="Optional target crate/subsystem scope name from project spec",
    )
    gen_parser.add_argument(
        "--generator-model",
        help="Override LLM model for synthetic bug generation (e.g. claude-3-5-sonnet-latest or mock)",
    )
    gen_parser.add_argument(
        "--corpus-dir",
        help="Override root corpus directory (default: ./benchmarks/corpus)",
    )

    # 2. benchmark subcommand
    bench_parser = subparsers.add_parser(
        "benchmark",
        help="Run ablation ladder and external baselines against a synthetic dataset",
    )
    bench_parser.add_argument(
        "--dataset-id",
        default="v1_ncm",
        help="Dataset identifier to evaluate",
    )
    bench_parser.add_argument(
        "--tiers",
        default="raw,threat_model,fast,full",
        help=f"Comma-separated ablation tiers ({', '.join(ABLATION_TIERS.keys())})",
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
        "--corpus-dir",
        help="Override root corpus directory",
    )
    bench_parser.add_argument(
        "--output-dir",
        help="Override benchmark output directory",
    )

    # 3. scorecard subcommand
    score_parser = subparsers.add_parser(
        "scorecard",
        help="Aggregate grades.json into NCM heatmaps, Markdown tables, and USENIX LaTeX booktabs",
    )
    score_parser.add_argument(
        "--grades",
        required=True,
        help="Path to grades.json produced by 'nidhogg-run benchmark'",
    )
    score_parser.add_argument(
        "--output-dir",
        help="Optional directory to write scorecard artifacts",
    )

    args = parser.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        sys.stderr.write(f"Error: Benchmark spec file not found: {spec_path}\n")
        sys.exit(1)

    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    config = spec.get("config", {})
    corpus_root = Path(
        getattr(args, "corpus_dir", None) or config.get("corpusDir") or "./benchmarks/corpus"
    )
    output_root = Path(
        getattr(args, "output_dir", None) or config.get("outputDir") or "./test-out/benchmarks"
    )
    cache_root = Path(config.get("cacheDir") or "./test-out/nidhogg-cache")
    output_root.mkdir(parents=True, exist_ok=True)
    setup_logger(str(output_root / "nidhogg.log"))

    if args.subcommand == "generate":
        pipeline = GenerationPipeline(
            spec=spec,
            corpus_root=corpus_root,
            cache_root=cache_root,
            generator_model=args.generator_model,
        )
        pipeline.generate_dataset(
            dataset_id=args.dataset_id,
            profile=args.profile,
            count=args.count,
            scope_name=args.scope,
        )
    elif args.subcommand == "benchmark":
        tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]
        instance_filter = (
            [i.strip() for i in args.instances.split(",") if i.strip()] if args.instances else None
        )
        runner = BenchmarkRunner(
            spec=spec,
            corpus_root=corpus_root,
            output_root=output_root,
            cache_root=cache_root,
            mjolnir_bin=config.get("mjolnirBin", "mjolnir-run"),
            evaluator_model=args.evaluator_model,
        )
        grades = runner.run_benchmark(
            dataset_id=args.dataset_id,
            tiers=tiers,
            repetitions=args.repetitions,
            instance_filter=instance_filter,
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
