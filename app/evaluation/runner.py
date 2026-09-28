# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Evaluation & Ablation Harness Runner (3-Run Mjolnir Multi-Checkpoint Ablation + CLI Templates + OpenAnt/SAST)."""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile
import time

from evaluation.constants import ABLATION_TIERS, DEFAULT_CLI_TEMPLATES
from evaluation.grader import BenchmarkGrader, extract_phase_checkpoint_findings
from evaluation.models import DatasetManifest, InstanceGrade, VulnInstanceManifest
from evaluation.sandbox.bwrap_runner import IsolatedProcessRunner, audit_run_for_tampering
from evaluation.sandbox.orphan_snapshot import OrphanSnapshotBuilder
from utilities.discovery import discover_source_files
from utilities.logger import logger
from utilities.threat_model import load_threat_model


def expand_cli_template(
    template: str,
    placeholders: dict[str, str],
) -> list[str]:
    """Safely splits a CLI command template into argv tokens and substitutes placeholders."""
    tokens = shlex.split(template)
    argv: list[str] = []
    for tok in tokens:
        expanded = tok
        for key, val in placeholders.items():
            expanded = expanded.replace(f"{{{key}}}", val)
        argv.append(expanded)
    return argv


def extract_findings_from_cli_output(
    out_json_path: Path,
    stdout_text: str,
    default_file: str = "",
) -> list[dict]:
    """Extracts normalized finding dicts from either {output_json} on disk or CLI stdout."""
    raw_items: list[object] = []

    if out_json_path.exists():
        try:
            parsed = json.loads(out_json_path.read_text(encoding="utf-8"))
            if isinstance(parsed, list):
                raw_items = parsed
            elif isinstance(parsed, dict):
                raw_items = (
                    parsed.get("vulnerabilities")
                    or parsed.get("findings")
                    or parsed.get("results")
                    or []
                )
        except Exception:
            raw_items = []

    if not raw_items and stdout_text.strip():
        # Try fenced ```json ... ``` blocks first, then raw JSON array/object
        candidates = re.findall(r"```(?:json)?\s*([\s\S]*?)```", stdout_text)
        candidates.append(stdout_text.strip())
        for cand in candidates:
            try:
                parsed = json.loads(cand)
                if isinstance(parsed, list):
                    raw_items = parsed
                    break
                if isinstance(parsed, dict):
                    inner = (
                        parsed.get("vulnerabilities")
                        or parsed.get("findings")
                        or parsed.get("results")
                    )
                    if isinstance(inner, list):
                        raw_items = inner
                        break
            except Exception:
                continue

    normalized: list[dict] = []
    for idx, item in enumerate(raw_items):
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "id": str(item.get("id") or f"cli-{idx + 1}"),
                "file": str(item.get("file") or item.get("file_path") or default_file),
                "location": str(
                    item.get("location") or item.get("line") or item.get("function") or "Line 1"
                ),
                "cwe": item.get("cwe") or item.get("cwe_id"),
                "severity": str(item.get("severity") or "Medium").capitalize(),
                "title": str(item.get("title") or item.get("name") or "CLI Finding"),
                "description": str(item.get("description") or item.get("message") or ""),
                "status": str(item.get("status") or "Open").capitalize(),
                "history": item.get("history") if isinstance(item.get("history"), list) else [],
            }
        )
    return normalized


class EvaluationRunner:
    """Executes benchmark datasets across Mjolnir 3-run ablations, CLI templates, OpenAnt, and SAST baselines."""

    def __init__(
        self,
        spec: dict,
        corpus_root: Path,
        output_root: Path,
        cache_root: Path,
        mjolnir_bin: str = "mjolnir-run",
        evaluator_model: str | None = None,
        judge_model: str | None = None,
        cli_templates: dict[str, str] | None = None,
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
        self.cli_templates = {
            **DEFAULT_CLI_TEMPLATES,
            **(self.project.get("cliTemplates") or {}),
            **(cli_templates or {}),
        }
        self.snapshot_builder = OrphanSnapshotBuilder(cache_root=self.cache_root)
        self.grader = BenchmarkGrader(judge_model=judge_model or self.project.get("judgeModel"))

    def resolve_target_dirs(self, vuln_manifest: VulnInstanceManifest) -> list[str]:
        """Resolves the single focused target directory for the project (or falls back to scope/instance files)."""
        target_dir = self.project.get("targetDir")
        if target_dir:
            return [str(target_dir)]

        scopes = self.project.get("scopes", [])
        matching_scope = next(
            (s for s in scopes if s.get("name") == vuln_manifest.scope),
            None,
        )
        if matching_scope and matching_scope.get("srcDirs"):
            return list(matching_scope["srcDirs"])

        return [str(Path(f.file_path).parent) for f in vuln_manifest.vulnerable_spans] or ["."]

    def run_benchmark(
        self,
        dataset_id: str,
        tiers: list[str] | None = None,
        repetitions: int = 1,
        instance_filter: list[str] | None = None,
        expand_checkpoints: bool = True,
    ) -> list[InstanceGrade]:
        """Runs the specified evaluation tiers and repetitions across all instances in dataset_id."""
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

        active_tiers = tiers or ["no_tm", "no_expert", "full"]
        instance_ids = (
            [i for i in dataset.instance_ids if i in set(instance_filter)]
            if instance_filter
            else dataset.instance_ids
        )

        bench_out_dir = self.output_root / repo_name / dataset_id
        bench_out_dir.mkdir(parents=True, exist_ok=True)

        isolated_runner = IsolatedProcessRunner(
            masked_paths=[self.corpus_root, self.cache_root, bench_out_dir]
        )

        all_grades: list[InstanceGrade] = []

        for vuln_id in instance_ids:
            inst_dir = dataset_dir / "instances" / vuln_id
            gt_path = inst_dir / "ground_truth.json"
            patch_path = inst_dir / "vuln_patch.diff"
            if not gt_path.exists():
                logger.warning(f"Skipping incomplete instance {vuln_id}")
                continue

            vuln_manifest = VulnInstanceManifest.model_validate_json(
                gt_path.read_text(encoding="utf-8")
            )
            vuln_patch = patch_path.read_text(encoding="utf-8") if patch_path.exists() else ""

            for tier_key in active_tiers:
                if tier_key not in ABLATION_TIERS:
                    logger.warning(f"Unknown evaluation tier '{tier_key}', skipping.")
                    continue
                tier_cfg = ABLATION_TIERS[tier_key]

                for rep in range(1, repetitions + 1):
                    logger.header(
                        f"Evaluating {vuln_id} | Tier={tier_key} ({tier_cfg['name']}) | Rep {rep}/{repetitions}"
                    )
                    trial_grades = self._execute_single_trial(
                        baseline_dir=baseline_dir,
                        vuln_manifest=vuln_manifest,
                        vuln_patch=vuln_patch,
                        tier_key=tier_key,
                        tier_cfg=tier_cfg,
                        repetition=rep,
                        isolated_runner=isolated_runner,
                        bench_out_dir=bench_out_dir,
                        expand_checkpoints=expand_checkpoints,
                    )
                    all_grades.extend(trial_grades)

        grades_path = bench_out_dir / "grades.json"
        grades_path.write_text(
            json.dumps([g.model_dump() for g in all_grades], indent=2),
            encoding="utf-8",
        )
        logger.success(f"Saved {len(all_grades)} graded results to {grades_path}")
        return all_grades

    def _execute_single_trial(
        self,
        baseline_dir: Path,
        vuln_manifest: VulnInstanceManifest,
        vuln_patch: str,
        tier_key: str,
        tier_cfg: dict,
        repetition: int,
        isolated_runner: IsolatedProcessRunner,
        bench_out_dir: Path,
        expand_checkpoints: bool = True,
    ) -> list[InstanceGrade]:
        eval_tmp = Path(
            tempfile.mkdtemp(
                prefix=f"mjolnir-eval-{vuln_manifest.vuln_id}-{tier_key}-r{repetition}-"
            )
        )
        snapshot_dir = eval_tmp / "workspace"
        trial_out_dir = eval_tmp / "output"
        trial_out_dir.mkdir(parents=True, exist_ok=True)

        try:
            patches = [vuln_patch] if vuln_patch.strip() else []
            self.snapshot_builder.materialize_orphan_snapshot(
                baseline_dir=baseline_dir,
                dest_dir=snapshot_dir,
                vuln_patches=patches,
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
            elif runner_type == "cli_template":
                vulns_data, usage_summary = self._run_cli_template_tier(
                    snapshot_dir=snapshot_dir,
                    trial_out_dir=trial_out_dir,
                    vuln_manifest=vuln_manifest,
                    tier_cfg=tier_cfg,
                    isolated_runner=isolated_runner,
                )
            elif runner_type == "openant":
                vulns_data, usage_summary = self._run_openant_tier(
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
                    vuln_manifest=vuln_manifest,
                    isolated_runner=isolated_runner,
                )
            else:
                raise ValueError(f"Unsupported runner type: {runner_type}")

            elapsed = time.monotonic() - start_t
            tampered = audit_run_for_tampering(trial_out_dir, vuln_manifest.canary)

            archive_dir = (
                bench_out_dir / "trials" / vuln_manifest.vuln_id / tier_key / f"rep_{repetition}"
            )
            if archive_dir.exists():
                shutil.rmtree(archive_dir)
            archive_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(trial_out_dir, archive_dir)

            primary_grade = self.grader.grade_instance_run(
                manifest=vuln_manifest,
                ablation_tier=tier_key,
                repetition=repetition,
                vulnerabilities_data=vulns_data,
                vuln_patch=vuln_patch,
                usage_summary=usage_summary,
                wall_clock_seconds=elapsed,
                tamper_detected=tampered,
            )

            grades = [primary_grade]

            # Extract intermediate phase checkpoints from a single Mjolnir run (e.g. full@initial_review = no_poc)
            checkpoints = tier_cfg.get("checkpoints") if expand_checkpoints else None
            if isinstance(checkpoints, list) and vulns_data:
                for cp_phase in checkpoints:
                    cp_vulns = extract_phase_checkpoint_findings(vulns_data, str(cp_phase))
                    cp_grade = self.grader.grade_instance_run(
                        manifest=vuln_manifest,
                        ablation_tier=f"{tier_key}@{cp_phase}",
                        repetition=repetition,
                        vulnerabilities_data=cp_vulns,
                        vuln_patch=vuln_patch,
                        usage_summary=usage_summary,
                        wall_clock_seconds=elapsed,
                        tamper_detected=tampered,
                    )
                    grades.append(cp_grade)

            return grades
        finally:
            shutil.rmtree(eval_tmp, ignore_errors=True)

    def _run_mjolnir_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        vuln_manifest: VulnInstanceManifest,
        tier_cfg: dict,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        src_dirs = self.resolve_target_dirs(vuln_manifest)

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
                "name": f"eval_{vuln_manifest.vuln_id}",
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
        usage_file = latest_run / "token_usage.json"
        vulns_data = (
            json.loads(vulns_file.read_text(encoding="utf-8")) if vulns_file.exists() else []
        )
        usage_data = (
            json.loads(usage_file.read_text(encoding="utf-8")) if usage_file.exists() else None
        )
        return vulns_data, usage_data

    def _run_cli_template_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        vuln_manifest: VulnInstanceManifest,
        tier_cfg: dict,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        """Executes a host/Nix-provided CLI command template in either directory or per-file mode."""
        cli_key = str(tier_cfg.get("cli_key", "gemini"))
        template = str(tier_cfg.get("cmd_template") or self.cli_templates.get(cli_key, ""))
        if not template:
            logger.warning(f"No CLI command template configured for '{cli_key}'.")
            return [], None

        base_bin = shlex.split(template)[0]
        if not shutil.which(base_bin):
            logger.warning(f"CLI binary '{base_bin}' not found in PATH; recording empty baseline.")
            return [], None

        no_tm = bool(tier_cfg.get("no_threat_model", False))
        tm_path = "" if no_tm else str(self.project.get("threatModel") or "")
        tm_text = "" if no_tm else load_threat_model(tm_path if tm_path else None)
        tm_prefix = (
            f"Use the following project threat model context:\n{tm_text}\n\n"
            if tm_text.strip()
            else ""
        )

        target_dirs = self.resolve_target_dirs(vuln_manifest)
        granularity = str(tier_cfg.get("granularity", "dir"))

        if granularity == "per_file":
            files_to_scan = discover_source_files(
                code_dir=str(snapshot_dir),
                src_dirs=target_dirs,
                extensions=set(self.project.get("extensions", ["rs", "c", "h"])),
                exclude_dirs=self.project.get("excludeDirs", []),
                exclude_patterns=self.project.get("excludePatterns", []),
            )
            aggregated: list[dict] = []
            for idx, rel_file in enumerate(files_to_scan):
                out_json = trial_out_dir / f"{cli_key}_file_{idx}.json"
                prompt = (
                    f"{tm_prefix}Perform a security audit of `{rel_file}` in this repository. "
                    f"Output a JSON array of identified security vulnerabilities to `{out_json}` (or in a ```json block) "
                    'where each object has keys: "file", "location", "cwe", "severity", "title", "description", "status": "Open".'
                )
                argv = expand_cli_template(
                    template,
                    {
                        "prompt": prompt,
                        "output_json": str(out_json),
                        "target_dir": target_dirs[0],
                        "file": rel_file,
                        "threat_model": tm_path,
                    },
                )
                res = isolated_runner.run_isolated(
                    cmd=argv, cwd=snapshot_dir, env=os.environ.copy()
                )
                aggregated.extend(
                    extract_findings_from_cli_output(out_json, res.stdout, default_file=rel_file)
                )
            return aggregated, None

        out_json = trial_out_dir / f"{cli_key}_findings.json"
        target_str = ", ".join(target_dirs)
        prompt = (
            f"{tm_prefix}Perform a security audit of `{target_str}` in this repository. "
            f"Output a JSON array of identified security vulnerabilities to `{out_json}` (or in a ```json block) "
            'where each object has keys: "file", "location", "cwe", "severity", "title", "description", "status": "Open".'
        )
        argv = expand_cli_template(
            template,
            {
                "prompt": prompt,
                "output_json": str(out_json),
                "target_dir": target_dirs[0],
                "file": target_dirs[0],
                "threat_model": tm_path,
            },
        )
        res = isolated_runner.run_isolated(cmd=argv, cwd=snapshot_dir, env=os.environ.copy())
        return extract_findings_from_cli_output(out_json, res.stdout), None

    def _run_openant_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        vuln_manifest: VulnInstanceManifest,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        openant_bin = shutil.which("openant")
        if not openant_bin:
            logger.warning("openant binary not found in PATH; recording empty baseline.")
            return [], None
        target_dirs = self.resolve_target_dirs(vuln_manifest)
        out_json = trial_out_dir / "openant_results.json"
        res = isolated_runner.run_isolated(
            cmd=[openant_bin, "scan", target_dirs[0], "--output", str(out_json)],
            cwd=snapshot_dir,
            env=os.environ.copy(),
        )
        return extract_findings_from_cli_output(out_json, res.stdout), None

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
        vuln_manifest: VulnInstanceManifest,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        if not shutil.which("semgrep"):
            logger.warning("semgrep not found in PATH; returning empty findings.")
            return [], None
        target_dirs = self.resolve_target_dirs(vuln_manifest)
        res = isolated_runner.run_isolated(
            cmd=["semgrep", "scan", "--config=auto", "--json", *target_dirs],
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
                    "cwe": cwe_str,
                    "title": r.get("check_id", "Semgrep finding"),
                    "description": r.get("extra", {}).get("message", ""),
                    "severity": "Medium",
                    "status": "Open",
                    "history": [],
                }
            )
        return vulns, None
