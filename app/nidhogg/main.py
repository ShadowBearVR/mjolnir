# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for Nidhogg: synthetic vulnerability generation."""

import argparse
import json
from pathlib import Path
import sys

from nidhogg.constants import NCM_PROFILES
from nidhogg.generation.pipeline import GenerationPipeline
from utilities.logger import setup_logger


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nidhogg-run",
        description="Nidhogg: Synthetic Vulnerability Generation Suite for Mjolnir",
    )
    parser.add_argument(
        "--spec",
        required=True,
        help="Path to Nidhogg project spec JSON",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # generate subcommand
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
        help="Override LLM model for synthetic bug generation (e.g. gemini-3.8-pro or mock)",
    )
    gen_parser.add_argument(
        "--corpus-dir",
        help="Override root corpus directory (default: ./benchmarks/corpus)",
    )

    args = parser.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        sys.stderr.write(f"Error: Nidhogg spec file not found: {spec_path}\n")
        sys.exit(1)

    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    config = spec.get("config", {})
    corpus_root = Path(
        getattr(args, "corpus_dir", None) or config.get("corpusDir") or "./benchmarks/corpus"
    )
    output_root = Path(config.get("outputDir") or "./test-out/nidhogg")
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


if __name__ == "__main__":
    main()
