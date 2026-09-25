# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Benchmark & Ablation Harness Runner (Mjolnir Ablation Ladder + Antigravity CLI + SAST Baselines)."""

import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from nidhogg.benchmark.grader import BenchmarkGrader
from nidhogg.constants import ABLATION_TIERS
from nidhogg.data.models import DatasetManifest, InstanceGrade, SyntheticVulnManifest
from nidhogg.sandbox.bwrap_runner import IsolatedProcessRunner, audit_run_for_tampering
from nidhogg.sandbox.orphan_snapshot import OrphanSnapshotBuilder
from utilities.logger import logger


class BenchmarkRunner:
    """Executes benchmark datasets across Mjolnir ablation tiers, Antigravity CLI, and SAST baselines."""

    def __init__(
        self,
        spec: dict,
        corpus_root: Path,
        output_root: Path,
        cache_root: Path,
        mjolnir_bin: str = "mjolnir-run",
        evaluator_model: str | None = None,
    ):
        self.spec = spec
        self.project = spec["project"]
        self.corpus_root = corpus_root.expanduser().resolve()
        self.output_root = output_root.expanduser().resolve()
        self.cache_root = cache_root.expanduser().resolve()
        self.mjolnir_bin = mjolnir_bin
        self.evaluator_model = (
            evaluator_model or self.project.get("evaluatorModel") or "gemini-3.8-flash"
        )
        self.snapshot_builder = OrphanSnapshotBuilder(cache_root=self.cache_root)
        self.grader = BenchmarkGrader()

    def run_benchmark(
        self,
        dataset_id: str,
        tiers: list[str] | None = None,
        repetitions: int = 1,
        instance_filter: list[str] | None = None,
    ) -> list[InstanceGrade]:
        """Runs the specified ablation tiers and repetitions across all instances in dataset_id."""
        repo_name = self.project["repoName"]
        dataset_dir = self.corpus_root / repo_name / dataset_id
        manifest_path = dataset_dir / "dataset_manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Dataset manifest not found: {manifest_path}")

        dataset = DatasetManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        baseline_dir = self.snapshot_builder.ensure_pinned_baseline(
            repo_name=repo_name,
            repo_url=dataset.repo_url,
            pinned_rev=dataset.base_commit,
            nix_source_path=self.project.get("nixSourcePath"),
        )

        active_tiers = tiers or ["raw", "threat_model", "fast", "full"]
        instance_ids = (
            [i for i in dataset.instance_ids if i in set(instance_filter)]
            if instance_filter
            else dataset.instance_ids
        )

        bench_out_dir = self.output_root / repo_name / dataset_id
        bench_out_dir.mkdir(parents=True, exist_ok=True)

        # Mask corpus_root, cache_root, and bench_out_dir inside bwrap so evaluated agents cannot cheat
        isolated_runner = IsolatedProcessRunner(
            masked_paths=[self.corpus_root, self.cache_root, bench_out_dir]
        )

        all_grades: list[InstanceGrade] = []

        for vuln_id in instance_ids:
            inst_dir = dataset_dir / "instances" / vuln_id
            gt_path = inst_dir / "ground_truth.json"
            patch_path = inst_dir / "vuln_patch.diff"
            if not gt_path.exists() or not patch_path.exists():
                logger.warning(f"Skipping incomplete instance {vuln_id}")
                continue

            vuln_manifest = SyntheticVulnManifest.model_validate_json(
                gt_path.read_text(encoding="utf-8")
            )
            vuln_patch = patch_path.read_text(encoding="utf-8")

            for tier_key in active_tiers:
                if tier_key not in ABLATION_TIERS:
                    logger.warning(f"Unknown ablation tier '{tier_key}', skipping.")
                    continue
                tier_cfg = ABLATION_TIERS[tier_key]

                for rep in range(1, repetitions + 1):
                    logger.header(
                        f"Benchmarking {vuln_id} | Tier={tier_key} ({tier_cfg['name']}) | Rep {rep}/{repetitions}"
                    )
                    grade = self._execute_single_trial(
                        baseline_dir=baseline_dir,
                        vuln_manifest=vuln_manifest,
                        vuln_patch=vuln_patch,
                        tier_key=tier_key,
                        tier_cfg=tier_cfg,
                        repetition=rep,
                        isolated_runner=isolated_runner,
                        bench_out_dir=bench_out_dir,
                    )
                    all_grades.append(grade)

        grades_path = bench_out_dir / "grades.json"
        grades_path.write_text(
            json.dumps([g.model_dump() for g in all_grades], indent=2),
            encoding="utf-8",
        )
        logger.success(f"Saved {len(all_grades)} graded trial results to {grades_path}")
        return all_grades

    def _execute_single_trial(
        self,
        baseline_dir: Path,
        vuln_manifest: SyntheticVulnManifest,
        vuln_patch: str,
        tier_key: str,
        tier_cfg: dict,
        repetition: int,
        isolated_runner: IsolatedProcessRunner,
        bench_out_dir: Path,
    ) -> InstanceGrade:
        eval_tmp = Path(
            tempfile.mkdtemp(
                prefix=f"nidhogg-eval-{vuln_manifest.vuln_id}-{tier_key}-r{repetition}-"
            )
        )
        snapshot_dir = eval_tmp / "workspace"
        trial_out_dir = eval_tmp / "output"
        trial_out_dir.mkdir(parents=True, exist_ok=True)

        try:
            self.snapshot_builder.materialize_orphan_snapshot(
                baseline_dir=baseline_dir,
                dest_dir=snapshot_dir,
                vuln_patches=[vuln_patch],
            )

            start_t = time.monotonic()
            runner_type = tier_cfg["runner"]
            if runner_type == "mjolnir":
                vulns_data, usage_summary = self._run_mjolnir_tier(
                    snapshot_dir=snapshot_dir,
                    trial_out_dir=trial_out_dir,
                    vuln_manifest=vuln_manifest,
                    tier_cfg=tier_cfg,
                    isolated_runner=isolated_runner,
                )
            elif runner_type == "antigravity_cli":
                vulns_data, usage_summary = self._run_antigravity_cli_tier(
                    snapshot_dir=snapshot_dir,
                    trial_out_dir=trial_out_dir,
                    vuln_manifest=vuln_manifest,
                    isolated_runner=isolated_runner,
                )
            elif runner_type == "clippy":
                vulns_data, usage_summary = self._run_clippy_tier(
                    snapshot_dir=snapshot_dir,
                    isolated_runner=isolated_runner,
                )
            elif runner_type == "semgrep":
                vulns_data, usage_summary = self._run_semgrep_tier(
                    snapshot_dir=snapshot_dir,
                    isolated_runner=isolated_runner,
                )
            else:
                raise ValueError(f"Unsupported runner type: {runner_type}")

            elapsed = time.monotonic() - start_t
            tampered = audit_run_for_tampering(trial_out_dir, vuln_manifest.canary)

            # Archive trial artifacts under bench_out_dir/trials/<vuln_id>/<tier_key>/rep_<rep>/
            archive_dir = (
                bench_out_dir / "trials" / vuln_manifest.vuln_id / tier_key / f"rep_{repetition}"
            )
            if archive_dir.exists():
                shutil.rmtree(archive_dir)
            archive_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(trial_out_dir, archive_dir)

            return self.grader.grade_instance_run(
                manifest=vuln_manifest,
                ablation_tier=tier_key,
                repetition=repetition,
                vulnerabilities_data=vulns_data,
                usage_summary=usage_summary,
                wall_clock_seconds=elapsed,
                tamper_detected=tampered,
            )
        finally:
            shutil.rmtree(eval_tmp, ignore_errors=True)

    def _run_mjolnir_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        vuln_manifest: SyntheticVulnManifest,
        tier_cfg: dict,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        scopes = self.project.get("scopes", [])
        matching_scope = next(
            (s for s in scopes if s["name"] == vuln_manifest.scope),
            {
                "name": vuln_manifest.scope,
                "srcDirs": [f.file_path for f in vuln_manifest.vulnerable_spans],
            },
        )
        # Scope scan to the target crate/directory so ablation runs are reproducible and bounded
        src_dirs = matching_scope.get("srcDirs") or [
            str(Path(f.file_path).parent) for f in vuln_manifest.vulnerable_spans
        ]

        job_spec = {
            "project": {
                "name": self.project["name"],
                "repoName": self.project["repoName"],
                "repoUrl": self.project["repoUrl"],
                "threatModel": None
                if tier_cfg.get("no_threat_model")
                else self.project.get("threatModel"),
            },
            "job": {
                "name": f"bench_{vuln_manifest.vuln_id}",
                "model": self.evaluator_model,
                "batchSize": self.project.get("batchSize", 64),
                "extensions": self.project.get("extensions", ["rs", "c", "h"]),
                "ref": "HEAD",
                "mode": tier_cfg["mode"],
                "minPocSeverity": "Low",
                "srcDirs": src_dirs,
                "excludeDirs": self.project.get("excludeDirs", []),
                "excludePatterns": self.project.get("excludePatterns", []),
                "localDir": str(snapshot_dir),
                "phases": tier_cfg["phases"],
            },
            "config": {
                "workspaceDir": str(snapshot_dir),
                "outputDir": str(trial_out_dir),
                "projectOutputDir": str(trial_out_dir),
            },
        }
        spec_file = trial_out_dir / "job_spec.json"
        spec_file.write_text(json.dumps(job_spec, indent=2), encoding="utf-8")

        cmd = [
            self.mjolnir_bin,
            "--spec",
            str(spec_file),
            "--local-dir",
            str(snapshot_dir),
            "--output-dir",
            str(trial_out_dir),
            "--mode",
            str(tier_cfg["mode"]),
            "--phases",
            ",".join(tier_cfg["phases"]),
        ]
        if tier_cfg.get("no_threat_model"):
            cmd.append("--no-threat-model")

        res = isolated_runner.run_isolated(cmd=cmd, cwd=snapshot_dir, env=os.environ.copy())
        if res.returncode != 0:
            logger.warning(f"mjolnir-run exited with {res.returncode}: {res.stderr[-500:]}")

        run_subdirs = sorted(trial_out_dir.glob("run_*"))
        if not run_subdirs:
            return [], None

        latest_run = run_subdirs[-1]
        vulns_file = latest_run / "vulnerabilities.json"
        usage_file = latest_run / "usage.json"
        vulns_data = (
            json.loads(vulns_file.read_text(encoding="utf-8")) if vulns_file.exists() else []
        )
        usage_data = (
            json.loads(usage_file.read_text(encoding="utf-8")) if usage_file.exists() else None
        )
        return vulns_data, usage_data

    def _run_antigravity_cli_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        vuln_manifest: SyntheticVulnManifest,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        """Runs the Antigravity CLI baseline inside the isolated snapshot with a generic security audit prompt."""
        cli_bin = os.environ.get("ANTIGRAVITY_CLI_BIN", "antigravity")
        out_json = trial_out_dir / "antigravity_findings.json"
        target_files = [s.file_path for s in vuln_manifest.vulnerable_spans]
        prompt = (
            f"Perform a security audit of {', '.join(target_files)} in this repository. "
            f"Write all identified vulnerabilities as a JSON array to {out_json} where each object has "
            'keys: "file", "location", "cwe_id", "severity", "title", "description", and "status": "Open".'
        )
        if not shutil.which(cli_bin):
            logger.warning(
                f"Antigravity CLI binary '{cli_bin}' not found in PATH; recording empty baseline."
            )
            return [], None

        isolated_runner.run_isolated(
            cmd=[cli_bin, "--prompt", prompt],
            cwd=snapshot_dir,
            env=os.environ.copy(),
        )
        if out_json.exists():
            try:
                return json.loads(out_json.read_text(encoding="utf-8")), None
            except Exception:
                return [], None
        return [], None

    def _run_clippy_tier(
        self,
        snapshot_dir: Path,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        res = isolated_runner.run_isolated(
            cmd=["cargo", "clippy", "--message-format=json"],
            cwd=snapshot_dir,
            env=os.environ.copy(),
        )
        vulns: list[dict] = []
        for idx, line in enumerate(res.stdout.splitlines()):
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if msg.get("reason") != "compiler-message":
                continue
            inner = msg.get("message", {})
            if inner.get("level") not in ("warning", "error"):
                continue
            spans = inner.get("spans", [])
            if not spans:
                continue
            primary = spans[0]
            vulns.append(
                {
                    "id": f"clippy-{idx}",
                    "file": primary.get("file_name", ""),
                    "location": f"Line {primary.get('line_start', 1)}",
                    "title": inner.get("message", "Clippy diagnostic"),
                    "description": inner.get("rendered", ""),
                    "severity": "Low",
                    "status": "Open",
                    "history": [],
                }
            )
        return vulns, None

    def _run_semgrep_tier(
        self,
        snapshot_dir: Path,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        if not shutil.which("semgrep"):
            logger.warning("semgrep not found in PATH; returning empty findings.")
            return [], None
        res = isolated_runner.run_isolated(
            cmd=["semgrep", "scan", "--config=auto", "--json", "."],
            cwd=snapshot_dir,
            env=os.environ.copy(),
        )
        try:
            data = json.loads(res.stdout)
        except Exception:
            return [], None

        vulns: list[dict] = []
        for idx, r in enumerate(data.get("results", [])):
            cwe_list = r.get("extra", {}).get("metadata", {}).get("cwe", [])
            cwe_str = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else None
            vulns.append(
                {
                    "id": f"semgrep-{idx}",
                    "file": r.get("path", ""),
                    "location": f"Line {r.get('start', {}).get('line', 1)}",
                    "cwe_id": cwe_str,
                    "title": r.get("check_id", "Semgrep finding"),
                    "description": r.get("extra", {}).get("message", ""),
                    "severity": "Medium",
                    "status": "Open",
                    "history": [],
                }
            )
        return vulns, None
