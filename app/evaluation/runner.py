# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Real-World Pinned Evaluation & Ablation Runner (Mjolnir Multi-Checkpoint Ablation + Controlled Single-Agent ADK Baselines)."""

import concurrent.futures
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import threading
import time

from evaluation.constants import ABLATION_TIERS, ORDERED_PIPELINE_PHASES
from evaluation.grader import (
    FindingPooler,
    compute_phase_transitions,
    extract_phase_checkpoint_findings,
    normalize_phase_id,
)
from evaluation.models import TrialRunRecord
from evaluation.sandbox.bwrap_runner import IsolatedProcessRunner
from evaluation.sandbox.orphan_snapshot import OrphanSnapshotBuilder
from executors.file_reader import FileReader
from executors.glob import GlobRunner
from executors.ripgrep import RipgrepRunner
from google.adk.tools import ToolContext
from security.path_sanitizer import resolve_workspace_path
from utilities.decorators import limit_tool_output
from utilities.discovery import discover_source_files
from utilities.logger import logger
from utilities.threat_model import load_threat_model

VANILLA_BASELINE_MAX_LLM_CALLS = 1000

VANILLA_BASELINE_SYSTEM_INSTRUCTION = """You are an expert security researcher and code auditor.
Your objective is to perform a thorough security audit of the target source code and identify genuine, exploitable security vulnerabilities.

Audit Guidelines:
1. Focus on concrete, exploitable security vulnerabilities with real security impact (e.g., memory corruption, buffer or integer overflows/underflows, missing bounds or length validation, cryptographic or authentication bypasses, state machine or lifecycle violations, privilege escalation, unauthorized access to hardware/key material, or denial of service).
2. Do not report stylistic issues, code quality nitpicks, best-practice suggestions without a concrete exploit path, or purely theoretical issues that are prevented by existing checks.
3. For each vulnerability you identify, populate all fields of the structured report:
   - `file`: Relative path to the source file from the repository root.
   - `location`: Specific function name and 1-indexed line number (e.g., `func_name (Line 120)`).
   - `cwe`: Applicable MITRE CWE identifier and name (e.g., `CWE-190: Integer Overflow or Wraparound`).
   - `severity`: Severity assessment (`Critical`, `High`, `Medium`, `Low`, or `Informational`).
   - `title`: Concise, specific title summarizing the vulnerability.
   - `description`: Detailed technical explanation of the root cause, how an attacker can trigger it, and the resulting security impact.
   - `recommendation`: Concrete code fix or mitigation.
If no genuine security vulnerabilities are present, return an empty `vulnerabilities` list."""


@limit_tool_output
async def vanilla_glob(
    pattern: str,
    dir_path: str = ".",
    case_sensitive: bool = False,
    respect_git_ignore: bool = True,
    tool_context: ToolContext | None = None,
) -> str:
    """Finds file paths matching a glob pattern in the workspace.

    Args:
        pattern: Filename or path glob pattern (e.g., `*.rs`, `**/*.c`).
        dir_path: Optional relative directory scope within the workspace (defaults to `.`).
        case_sensitive: Whether filename matching is case-sensitive (defaults to `False`).
        respect_git_ignore: Whether to exclude `.gitignore`d files (defaults to `True`).

    Returns:
        Newline-separated list of matching relative file paths.
    """
    base_dir = tool_context.state.get("code_dir", ".") if tool_context else "."
    try:
        search_path = resolve_workspace_path(dir_path, base_dir=base_dir)
    except ValueError as err:
        return f"Error: {err}"
    if not search_path.exists():
        return f"Error: Path '{dir_path}' does not exist."
    runner = GlobRunner(
        search_path,
        code_dir=base_dir,
        case_sensitive=case_sensitive,
        respect_git_ignore=respect_git_ignore,
    )
    return await runner.search_async(pattern, dir_path=dir_path)


vanilla_glob.__name__ = "glob"


@limit_tool_output
async def vanilla_read_file(
    file_path: str,
    start_line: int = 1,
    end_line: int | None = None,
    tool_context: ToolContext | None = None,
) -> str:
    """Reads the contents of a file from the workspace, optionally scoped to a line range.

    Args:
        file_path: Relative path to the file from the repository root.
        start_line: 1-indexed starting line number to read from (defaults to `1`).
        end_line: Optional 1-indexed ending line number (inclusive). Omit to read to end of file.

    Returns:
        Line-numbered source file content for the requested range.
    """
    code_dir = tool_context.state.get("code_dir", ".") if tool_context else "."
    try:
        safe_path = resolve_workspace_path(file_path, base_dir=code_dir)
    except ValueError as err:
        return f"Error: {err}"
    if not safe_path.exists() or not safe_path.is_file():
        return f"Error: File '{file_path}' does not exist or is not a regular file."
    reader = FileReader(safe_path)
    return await reader.read_async(file_path, start_line=start_line, end_line=end_line)


vanilla_read_file.__name__ = "read_file"


@limit_tool_output
async def vanilla_grep_search(
    pattern: str,
    dir_path: str = ".",
    include_pattern: str | None = None,
    exclude_pattern: str | None = None,
    case_sensitive: bool = True,
    tool_context: ToolContext | None = None,
) -> str:
    """Searches for a regular expression or literal pattern within file contents using `ripgrep`.

    Args:
        pattern: Regular expression pattern to search for.
        dir_path: Optional relative directory scope to narrow the search.
        include_pattern: Optional glob filter for included filenames (e.g., `*.rs`, `*.c`).
        exclude_pattern: Optional glob filter to exclude paths (e.g., `*test*`).
        case_sensitive: Whether the regex match is case-sensitive (defaults to `True`).

    Returns:
        Matching lines formatted with relative file paths and 1-indexed line numbers.
    """
    code_dir = tool_context.state.get("code_dir", ".") if tool_context else "."
    try:
        search_path = resolve_workspace_path(dir_path, base_dir=code_dir)
    except ValueError as err:
        return f"Error: {err}"
    if not search_path.exists():
        return f"Error: Path '{dir_path}' does not exist."
    runner = RipgrepRunner(case_sensitive=case_sensitive)
    return await runner.search_async(
        pattern,
        search_path,
        dir_path=dir_path,
        include_pattern=include_pattern,
        exclude_pattern=exclude_pattern,
    )


vanilla_grep_search.__name__ = "grep_search"

VANILLA_HOLISTIC_TOOLS = [vanilla_glob, vanilla_read_file, vanilla_grep_search]


def build_vanilla_baseline_instruction(
    threat_model_context: str = "",
    has_tools: bool = False,
) -> str:
    """Builds the fair, generic system instruction for the Vanilla Single-Agent Baseline."""
    instruction = VANILLA_BASELINE_SYSTEM_INSTRUCTION
    if has_tools:
        instruction += (
            "\n\nAvailable File-Browsing Tools:\n"
            "- `glob`: Find file paths matching a glob pattern in the workspace.\n"
            "- `grep_search`: Search for regular expressions or literal strings across files.\n"
            "- `read_file`: Read source file contents (optionally scoped to a line range)."
        )
    if threat_model_context and threat_model_context.strip():
        instruction += f"\n\n## Project Threat Model Context\n\n{threat_model_context.strip()}\n"
    return instruction


def _parse_single_usage_bucket(bucket: dict) -> tuple[int, int, int, int]:
    """Extracts (total_tokens, cached_tokens, uncached_input_tokens, output_tokens) from a single usage bucket."""
    total_tokens = int(bucket.get("total_tokens", 0) or 0)
    cached_tokens = int(
        bucket.get(
            "cache_tokens",
            bucket.get("cached_tokens", bucket.get("cache_read_input_tokens", 0)),
        )
        or 0
    )
    prompt_tokens = int(
        bucket.get("prompt_tokens", bucket.get("input_tokens", bucket.get("total_input_tokens", 0)))
        or 0
    )
    uncached_input = int(
        bucket.get(
            "uncached_tokens",
            bucket.get(
                "uncached_input_tokens",
                max(0, prompt_tokens - cached_tokens),
            ),
        )
        or 0
    )
    output_tokens = int(
        bucket.get(
            "total_output_tokens",
            bucket.get("output_tokens", bucket.get("completion_tokens", 0)),
        )
        or 0
    )
    if total_tokens == 0 and (cached_tokens or uncached_input or output_tokens):
        total_tokens = cached_tokens + uncached_input + output_tokens
    return total_tokens, cached_tokens, uncached_input, output_tokens


def parse_usage_metrics(
    usage_summary: dict | None,
    checkpoint_phase: str | None = None,
) -> tuple[int, int, int, int]:
    """Extracts (total_tokens, cached_tokens, uncached_input_tokens, output_tokens).

    When `checkpoint_phase` is provided and `by_phase` (or `by_agent`) is present in `usage_summary`,
    computes cumulative token usage up to and including `checkpoint_phase`.
    """
    if not usage_summary or not isinstance(usage_summary, dict):
        return 0, 0, 0, 0

    norm_cp = normalize_phase_id(checkpoint_phase) if checkpoint_phase else ""
    if norm_cp and norm_cp in ORDERED_PIPELINE_PHASES and norm_cp != "final_review":
        cp_idx = ORDERED_PIPELINE_PHASES.index(norm_cp)
        allowed_phases = {"project_exploration", *ORDERED_PIPELINE_PHASES[: cp_idx + 1]}
        by_phase = usage_summary.get("by_phase")
        if isinstance(by_phase, dict) and by_phase:
            tot_t = cac_t = unc_t = out_t = 0
            for pid, p_bucket in by_phase.items():
                if normalize_phase_id(pid) in allowed_phases or pid == "project_exploration":
                    if isinstance(p_bucket, dict):
                        t, c, u, o = _parse_single_usage_bucket(p_bucket)
                        tot_t += t
                        cac_t += c
                        unc_t += u
                        out_t += o
            return tot_t, cac_t, unc_t, out_t

        by_agent = usage_summary.get("by_agent")
        if isinstance(by_agent, dict) and by_agent:
            agent_phase_map = {
                "ProjectExpertAgent": "project_exploration",
                "AuditorAgent": "discovery",
                "DeduplicationAgent": "deduplication",
                "AdversarialReviewerAgent": "initial_review",
                "ExploitCreationAgent": "poc_creation",
            }
            tot_t = cac_t = unc_t = out_t = 0
            for a_name, a_bucket in by_agent.items():
                mapped_phase = agent_phase_map.get(a_name, "discovery")
                if mapped_phase in allowed_phases and isinstance(a_bucket, dict):
                    t, c, u, o = _parse_single_usage_bucket(a_bucket)
                    tot_t += t
                    cac_t += c
                    unc_t += u
                    out_t += o
            return tot_t, cac_t, unc_t, out_t

    bucket = usage_summary.get("total") or usage_summary.get("totals") or usage_summary
    if not isinstance(bucket, dict):
        return 0, 0, 0, 0
    return _parse_single_usage_bucket(bucket)


def format_model_slug(model: str) -> str:
    """Normalizes a model identifier (e.g. 'vertex_ai/claude-sonnet-5-5@20260514') to a concise slug."""
    slug = str(model or "").strip().split("/")[-1].split("@")[0]
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", slug).strip("-") or "default"


class EvaluationRunner:
    """Executes real-world pinned RoT evaluations across Mjolnir ablations and controlled single-agent baselines."""

    def __init__(
        self,
        spec: dict,
        output_root: Path,
        cache_root: Path,
        corpus_root: Path | None = None,
        mjolnir_bin: str = "mjolnir-run",
        evaluator_model: str | list[str] | None = None,
        scope: str | None = None,
        target_dir: str | None = None,
    ):
        self.spec = spec
        self.project = spec["project"]
        self.scope = scope
        self.target_dir_override = target_dir
        self.output_root = output_root.expanduser().resolve()
        self.cache_root = cache_root.expanduser().resolve()
        self.corpus_root = corpus_root.expanduser().resolve() if corpus_root else None
        self.mjolnir_bin = mjolnir_bin
        self.default_model = str(self.project.get("evaluatorModel") or "gemini-3.8-flash")
        raw_models = evaluator_model or self.default_model
        if isinstance(raw_models, list):
            self.evaluator_models = [str(m).strip() for m in raw_models if str(m).strip()]
        else:
            self.evaluator_models = [m.strip() for m in str(raw_models).split(",") if m.strip()]
        if not self.evaluator_models:
            self.evaluator_models = [self.default_model]
        self.evaluator_model = self.evaluator_models[0]
        self.snapshot_builder = OrphanSnapshotBuilder(cache_root=self.cache_root)
        self.pooler = FindingPooler()

    def resolve_target_dirs(self) -> list[str]:
        """Resolves the focused target directory for the pinned RoT project."""
        if self.target_dir_override:
            return [m.strip() for m in self.target_dir_override.split(",") if m.strip()]

        scopes = self.project.get("scopes", [])
        active_scope = self.scope or "default"
        if scopes:
            for sc in scopes:
                if isinstance(sc, dict) and sc.get("name") == active_scope and sc.get("srcDirs"):
                    return list(sc["srcDirs"])
            if self.scope:
                logger.warning(
                    f"Requested scope '{self.scope}' not found in spec; falling back to default."
                )

        target_dir = self.project.get("targetDir")
        if target_dir:
            if isinstance(target_dir, list):
                return [str(d) for d in target_dir]
            return [m.strip() for m in str(target_dir).split(",") if m.strip()]

        if scopes and isinstance(scopes[0], dict) and scopes[0].get("srcDirs"):
            return list(scopes[0]["srcDirs"])

        return ["."]

    def run_evaluation(
        self,
        tiers: list[str] | None = None,
        repetitions: int = 1,
        expand_checkpoints: bool = True,
        run_label: str = "pinned",
        force_rerun: bool = False,
    ) -> list[TrialRunRecord]:
        """Runs the specified evaluation tiers and repetitions against the pinned project source tree."""
        repo_name = self.project["repoName"]
        pinned_rev = str(self.project.get("pinnedRev") or "HEAD")
        baseline_dir = self.snapshot_builder.ensure_pinned_baseline(
            repo_name=repo_name,
            repo_url=self.project["repoUrl"],
            pinned_rev=pinned_rev,
            nix_source_path=self.project.get("nixSourcePath"),
        )

        raw_tiers = tiers or ["base", "full"]
        active_tiers: list[str] = []
        for t in raw_tiers:
            if t not in active_tiers:
                active_tiers.append(t)

        eval_out_dir = self.output_root / repo_name / run_label
        eval_out_dir.mkdir(parents=True, exist_ok=True)

        masked = [self.cache_root, eval_out_dir]
        if self.corpus_root:
            masked.append(self.corpus_root)
        isolated_runner = IsolatedProcessRunner(masked_paths=masked)

        # Load any existing trials so incremental runs across tiers accumulate cleanly
        manifest_path = eval_out_dir / "trials_manifest.json"
        existing_by_key: dict[tuple[str, int], TrialRunRecord] = {}
        if run_label == "stability" and not force_rerun:
            pinned_manifest = self.output_root / repo_name / "pinned" / "trials_manifest.json"
            if pinned_manifest.exists():
                try:
                    for item in json.loads(pinned_manifest.read_text(encoding="utf-8")):
                        rec = TrialRunRecord.model_validate(item)
                        if rec.ablation_tier == "full" or rec.ablation_tier.startswith("full@"):
                            existing_by_key[(rec.ablation_tier, rec.repetition)] = rec
                except Exception as e:
                    logger.warning(f"Could not seed stability manifest from pinned: {e}")

        if manifest_path.exists():
            try:
                raw_prev = json.loads(manifest_path.read_text(encoding="utf-8"))
                for item in raw_prev:
                    rec = TrialRunRecord.model_validate(item)
                    existing_by_key[(rec.ablation_tier, rec.repetition)] = rec
            except Exception as e:
                logger.warning(f"Could not load existing trials_manifest.json: {e}")

        pending_trials: list[tuple[str, str, dict, int, str, bool, str]] = []

        for raw_tier_key in active_tiers:
            # Support optional inline model override syntax: e.g. full[gemini-4-argon]
            m_inline = re.match(r"^([^\[\]]+)\[([^\[\]]+)\]$", raw_tier_key)
            if m_inline:
                base_tier_key = m_inline.group(1)
                tier_models = [m_inline.group(2)]
                force_qualify = True
            else:
                base_tier_key = raw_tier_key
                tier_models = self.evaluator_models
                force_qualify = len(self.evaluator_models) > 1

            if base_tier_key not in ABLATION_TIERS:
                logger.warning(f"Unknown evaluation tier '{raw_tier_key}', skipping.")
                continue
            tier_cfg = ABLATION_TIERS[base_tier_key]
            is_mjolnir_tier = tier_cfg.get("runner") in ("mjolnir", "vanilla_agent")
            models_for_tier = tier_models if is_mjolnir_tier else [""]

            for model_id in models_for_tier:
                qualify_model = is_mjolnir_tier and (
                    force_qualify or (model_id and model_id != self.default_model)
                )
                if qualify_model:
                    slug = format_model_slug(model_id)
                    eff_tier_key = f"{base_tier_key}[{slug}]"
                    eff_tier_name = f"{tier_cfg['name']} ({slug})"
                else:
                    eff_tier_key = base_tier_key
                    eff_tier_name = str(tier_cfg["name"])

                for rep in range(1, repetitions + 1):
                    model_note = f" | Model={model_id}" if model_id else ""
                    cached_rec = existing_by_key.get((eff_tier_key, rep))
                    trial_archive_dir = eval_out_dir / "trials" / eff_tier_key / f"rep_{rep}"
                    if (
                        not force_rerun
                        and cached_rec is not None
                        and (
                            cached_rec.total_tokens > 0
                            if is_mjolnir_tier
                            else (
                                cached_rec.total_reported_findings > 0 or trial_archive_dir.exists()
                            )
                        )
                    ):
                        logger.info(
                            f"Skipping already-completed trial: Tier={eff_tier_key} ({eff_tier_name}){model_note} | Rep {rep}/{repetitions} (cached in {manifest_path.name})"
                        )
                        continue

                    if not force_rerun and cached_rec is None and trial_archive_dir.exists():
                        recovered = self._recover_trial_records_from_archive(
                            archive_dir=trial_archive_dir,
                            tier_key=eff_tier_key,
                            tier_cfg={**tier_cfg, "name": eff_tier_name},
                            repetition=rep,
                            expand_checkpoints=expand_checkpoints,
                            model_override=model_id if is_mjolnir_tier else None,
                        )
                        if recovered and (
                            not is_mjolnir_tier or any(r.total_tokens > 0 for r in recovered)
                        ):
                            for rec in recovered:
                                existing_by_key[(rec.ablation_tier, rec.repetition)] = rec
                            self._flush_manifest(manifest_path, existing_by_key)
                            logger.info(
                                f"Recovered completed trial from disk: Tier={eff_tier_key} ({eff_tier_name}){model_note} | Rep {rep}/{repetitions}"
                            )
                            continue

                    # If running multi-model suite and the default model already completed unqualified (e.g. 'full'), reuse it
                    base_cached = existing_by_key.get((base_tier_key, rep))
                    if (
                        not force_rerun
                        and qualify_model
                        and model_id == self.default_model
                        and base_cached is not None
                        and (
                            base_cached.total_tokens > 0 or base_cached.total_reported_findings > 0
                        )
                    ):
                        logger.info(
                            f"Reusing completed default-model trial '{base_tier_key}' (Rep {rep}) for '{eff_tier_key}' without re-running LLM."
                        )
                        for (k_tier, k_rep), prev_rec in list(existing_by_key.items()):
                            if k_rep == rep and (
                                k_tier == base_tier_key or k_tier.startswith(f"{base_tier_key}@")
                            ):
                                suffix = k_tier[len(base_tier_key) :]
                                aliased_tier = f"{eff_tier_key}{suffix}"
                                existing_by_key[(aliased_tier, rep)] = prev_rec.model_copy(
                                    update={
                                        "ablation_tier": aliased_tier,
                                    }
                                )
                        self._flush_manifest(manifest_path, existing_by_key)
                        continue

                    pending_trials.append(
                        (
                            eff_tier_key,
                            eff_tier_name,
                            tier_cfg,
                            rep,
                            model_id,
                            is_mjolnir_tier,
                            model_note,
                        )
                    )

        manifest_lock = threading.Lock()

        def _run_and_record_trial(
            item: tuple[str, str, dict, int, str, bool, str],
        ) -> None:
            eff_tier_key, eff_tier_name, tier_cfg, rep, model_id, is_mjolnir_tier, model_note = item
            logger.header(
                f"Evaluating {repo_name} ({pinned_rev[:12]}) | Tier={eff_tier_key} ({eff_tier_name}){model_note} | Rep {rep}/{repetitions}"
            )
            trial_records = self._execute_single_trial(
                baseline_dir=baseline_dir,
                tier_key=eff_tier_key,
                tier_cfg={**tier_cfg, "name": eff_tier_name},
                repetition=rep,
                isolated_runner=isolated_runner,
                eval_out_dir=eval_out_dir,
                expand_checkpoints=expand_checkpoints,
                model_override=model_id if is_mjolnir_tier else None,
            )
            with manifest_lock:
                for rec in trial_records:
                    existing_by_key[(rec.ablation_tier, rec.repetition)] = rec
                self._flush_manifest(manifest_path, existing_by_key)
            if trial_records:
                p_rec = trial_records[0]
                logger.success(
                    f"Completed Tier={eff_tier_key} | Rep {rep}/{repetitions}: "
                    f"findings={p_rec.open_findings_count}, tokens={p_rec.total_tokens:,}, "
                    f"elapsed={p_rec.wall_clock_seconds:.1f}s"
                )

        parallel_vanilla_trials = [
            t for t in pending_trials if t[2].get("runner") == "vanilla_agent"
        ]
        sequential_trials = [t for t in pending_trials if t[2].get("runner") != "vanilla_agent"]

        mjolnir_concurrency = max(1, int(os.environ.get("MJOLNIR_EVAL_CONCURRENCY", "1")))
        if sequential_trials:
            if mjolnir_concurrency > 1 and len(sequential_trials) > 1:
                workers = min(mjolnir_concurrency, len(sequential_trials))
                logger.info(
                    f"Launching {len(sequential_trials)} trial(s) in parallel (max_workers={workers})..."
                )
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [
                        pool.submit(_run_and_record_trial, item) for item in sequential_trials
                    ]
                    for fut in concurrent.futures.as_completed(futures):
                        fut.result()
            else:
                for item in sequential_trials:
                    _run_and_record_trial(item)

        if parallel_vanilla_trials:
            max_workers = min(12, len(parallel_vanilla_trials))
            logger.info(
                f"Launching {len(parallel_vanilla_trials)} single-agent baseline trial(s) in parallel (max_workers={max_workers})..."
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [
                    pool.submit(_run_and_record_trial, item) for item in parallel_vanilla_trials
                ]
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()

        all_trials = list(existing_by_key.values())
        self._flush_manifest(manifest_path, existing_by_key)
        logger.success(f"Saved {len(all_trials)} trial records to {manifest_path}")

        # Build / update the provenance-stripped per-finding blind review deck
        self.pooler.build_pool(trials=all_trials, output_dir=eval_out_dir)
        return all_trials

    def run_benchmark(
        self,
        dataset_id: str = "pinned",
        tiers: list[str] | None = None,
        repetitions: int = 1,
        expand_checkpoints: bool = True,
        **_kwargs: object,
    ) -> list[TrialRunRecord]:
        """Alias for run_evaluation using dataset_id as run_label."""
        return self.run_evaluation(
            tiers=tiers,
            repetitions=repetitions,
            expand_checkpoints=expand_checkpoints,
            run_label=dataset_id,
        )

    def _execute_single_trial(
        self,
        baseline_dir: Path,
        tier_key: str,
        tier_cfg: dict,
        repetition: int,
        isolated_runner: IsolatedProcessRunner,
        eval_out_dir: Path,
        expand_checkpoints: bool = True,
        model_override: str | None = None,
    ) -> list[TrialRunRecord]:
        repo_name = self.project["repoName"]
        safe_tier_prefix = re.sub(r"[^a-zA-Z0-9._-]+", "_", tier_key)
        eval_tmp = Path(
            tempfile.mkdtemp(prefix=f"mjolnir-eval-{repo_name}-{safe_tier_prefix}-r{repetition}-")
        )
        snapshot_dir = eval_tmp / "workspace"
        trial_out_dir = eval_tmp / "output"
        trial_out_dir.mkdir(parents=True, exist_ok=True)
        active_model = model_override or (
            self.evaluator_model
            if tier_cfg.get("runner") in ("mjolnir", "vanilla_agent")
            else str(tier_cfg["name"])
        )

        try:
            runner_type = tier_cfg["runner"]
            self.snapshot_builder.materialize_orphan_snapshot(
                baseline_dir=baseline_dir,
                dest_dir=snapshot_dir,
                skip_ctags=(runner_type == "vanilla_agent"),
            )

            start_t = time.monotonic()
            if runner_type == "mjolnir":
                vulns_data, usage_summary = self._run_mjolnir_tier(
                    snapshot_dir=snapshot_dir,
                    trial_out_dir=trial_out_dir,
                    tier_key=tier_key,
                    tier_cfg=tier_cfg,
                    isolated_runner=isolated_runner,
                    model_override=active_model,
                )
            elif runner_type == "vanilla_agent":
                vulns_data, usage_summary = self._run_vanilla_agent_tier(
                    snapshot_dir=snapshot_dir,
                    trial_out_dir=trial_out_dir,
                    tier_key=tier_key,
                    tier_cfg=tier_cfg,
                    model_override=active_model,
                )
            else:
                raise ValueError(f"Unsupported runner type: {runner_type}")

            elapsed = time.monotonic() - start_t

            if runner_type != "mjolnir":
                self._write_trial_artifacts(
                    trial_out_dir=trial_out_dir,
                    tier_key=tier_key,
                    tier_cfg=tier_cfg,
                    vulns_data=vulns_data,
                )

            archive_dir = eval_out_dir / "trials" / tier_key / f"rep_{repetition}"
            if archive_dir.exists():
                shutil.rmtree(archive_dir)
            archive_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                trial_out_dir,
                archive_dir,
                ignore=shutil.ignore_patterns(".cargo_target_cache", "poc_worktrees"),
            )

            primary_record = self._build_trial_record(
                ablation_tier=tier_key,
                tier_name=str(tier_cfg["name"]),
                model=active_model,
                repetition=repetition,
                is_checkpoint=False,
                vulnerabilities_data=vulns_data,
                usage_summary=usage_summary,
                wall_clock_seconds=elapsed,
            )
            records = [primary_record]

            checkpoints = tier_cfg.get("checkpoints") if expand_checkpoints else None
            if isinstance(checkpoints, list) and vulns_data:
                for cp_phase in checkpoints:
                    cp_vulns = extract_phase_checkpoint_findings(vulns_data, str(cp_phase))
                    cp_record = self._build_trial_record(
                        ablation_tier=f"{tier_key}@{cp_phase}",
                        tier_name=f"{tier_cfg['name']} [{cp_phase}]",
                        model=active_model,
                        repetition=repetition,
                        is_checkpoint=True,
                        vulnerabilities_data=cp_vulns,
                        usage_summary=usage_summary,
                        wall_clock_seconds=elapsed,
                        checkpoint_phase=str(cp_phase),
                    )
                    records.append(cp_record)

            return records
        finally:
            shutil.rmtree(eval_tmp, ignore_errors=True)

    def _build_trial_record(
        self,
        ablation_tier: str,
        tier_name: str,
        repetition: int,
        is_checkpoint: bool,
        vulnerabilities_data: list[dict],
        usage_summary: dict | None,
        wall_clock_seconds: float,
        model: str = "",
        checkpoint_phase: str | None = None,
    ) -> TrialRunRecord:
        tot_tok, cached_tok, uncached_in, out_tok = parse_usage_metrics(
            usage_summary, checkpoint_phase=checkpoint_phase
        )
        open_findings = [
            v
            for v in vulnerabilities_data
            if str(getattr(v.get("status"), "value", v.get("status", "Open"))).lower() == "open"
        ]
        poc_verified = [
            v
            for v in open_findings
            if v.get("poc_verified")
            or (isinstance(v.get("poc"), dict) and v["poc"].get("verified"))
        ]
        target_dirs = self.resolve_target_dirs()
        mjolnir_commit = ""
        mjolnir_dirty = False
        try:
            import subprocess

            repo_root = Path(__file__).resolve().parents[2]
            res = subprocess.run(
                ["git", "-C", str(repo_root), "rev-parse", "--short=12", "HEAD"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if res.returncode == 0:
                mjolnir_commit = res.stdout.strip()
            st = subprocess.run(
                ["git", "-C", str(repo_root), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if st.returncode == 0:
                mjolnir_dirty = bool(st.stdout.strip())
        except Exception:
            pass
        return TrialRunRecord(
            project_name=str(self.project.get("name") or self.project["repoName"]),
            repo_name=str(self.project["repoName"]),
            pinned_rev=str(self.project.get("pinnedRev") or "HEAD"),
            target_dir=target_dirs[0] if target_dirs else ".",
            ablation_tier=ablation_tier,
            tier_name=tier_name,
            model=model,
            mjolnir_commit=mjolnir_commit,
            mjolnir_dirty=mjolnir_dirty,
            repetition=repetition,
            is_checkpoint=is_checkpoint,
            wall_clock_seconds=round(wall_clock_seconds, 3),
            total_tokens=tot_tok,
            cached_tokens=cached_tok,
            uncached_input_tokens=uncached_in,
            output_tokens=out_tok,
            total_reported_findings=len(vulnerabilities_data),
            open_findings_count=len(open_findings),
            poc_verified_count=len(poc_verified),
            phase_transitions=compute_phase_transitions(vulnerabilities_data),
            findings=vulnerabilities_data,
        )

    def _flush_manifest(
        self,
        manifest_path: Path,
        existing_by_key: dict[tuple[str, int], TrialRunRecord],
    ) -> None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        if manifest_path.exists():
            try:
                disk_items = json.loads(manifest_path.read_text(encoding="utf-8"))
                for item in disk_items:
                    rec = TrialRunRecord.model_validate(item)
                    key = (rec.ablation_tier, rec.repetition)
                    if key not in existing_by_key:
                        existing_by_key[key] = rec
            except Exception:
                pass
        tmp_path = manifest_path.with_suffix(f".tmp.{os.getpid()}.{threading.get_ident()}")
        tmp_path.write_text(
            json.dumps([t.model_dump(mode="json") for t in existing_by_key.values()], indent=2),
            encoding="utf-8",
        )
        os.replace(tmp_path, manifest_path)

    def _recover_trial_records_from_archive(
        self,
        archive_dir: Path,
        tier_key: str,
        tier_cfg: dict,
        repetition: int,
        expand_checkpoints: bool = True,
        model_override: str | None = None,
    ) -> list[TrialRunRecord]:
        run_subdirs = sorted(archive_dir.glob("run_*"))
        if run_subdirs:
            latest_run = run_subdirs[-1]
            vulns_file = latest_run / "vulnerabilities.json"
            usage_file = latest_run / "token_usage.json"
        else:
            vulns_file = archive_dir / "vulnerabilities.json"
            usage_file = archive_dir / "token_usage.json"
        if not vulns_file.exists():
            return []

        vulns_data = json.loads(vulns_file.read_text(encoding="utf-8"))
        usage_summary = (
            json.loads(usage_file.read_text(encoding="utf-8")) if usage_file.exists() else None
        )
        job_spec_file = archive_dir / "job_spec.json"
        elapsed = 0.0
        if job_spec_file.exists():
            elapsed = max(0.0, vulns_file.stat().st_mtime - job_spec_file.stat().st_mtime)

        active_model = model_override or (
            self.evaluator_model
            if tier_cfg.get("runner") in ("mjolnir", "vanilla_agent")
            else str(tier_cfg["name"])
        )
        primary_record = self._build_trial_record(
            ablation_tier=tier_key,
            tier_name=str(tier_cfg["name"]),
            model=active_model,
            repetition=repetition,
            is_checkpoint=False,
            vulnerabilities_data=vulns_data,
            usage_summary=usage_summary,
            wall_clock_seconds=elapsed,
        )
        records = [primary_record]

        checkpoints = tier_cfg.get("checkpoints") if expand_checkpoints else None
        if isinstance(checkpoints, list) and vulns_data:
            for cp_phase in checkpoints:
                cp_vulns = extract_phase_checkpoint_findings(vulns_data, str(cp_phase))
                cp_record = self._build_trial_record(
                    ablation_tier=f"{tier_key}@{cp_phase}",
                    tier_name=f"{tier_cfg['name']} [{cp_phase}]",
                    model=active_model,
                    repetition=repetition,
                    is_checkpoint=True,
                    vulnerabilities_data=cp_vulns,
                    usage_summary=usage_summary,
                    wall_clock_seconds=elapsed,
                    checkpoint_phase=str(cp_phase),
                )
                records.append(cp_record)

        return records

    def _run_mjolnir_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        tier_key: str,
        tier_cfg: dict,
        isolated_runner: IsolatedProcessRunner,
        model_override: str | None = None,
    ) -> tuple[list[dict], dict | None]:
        src_dirs = self.resolve_target_dirs()
        min_poc_severity = str(self.project.get("minPocSeverity") or "Informational")
        model_id = model_override or self.evaluator_model
        safe_job_tier = re.sub(r"[^a-zA-Z0-9._-]+", "_", tier_key)
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
                "name": f"eval_{self.project['repoName']}_{safe_job_tier}",
                "model": model_id,
                "batchSize": self.project.get("batchSize", 64),
                "extensions": self.project.get("extensions", ["rs", "c", "h"]),
                "ref": "HEAD",
                "mode": tier_cfg["mode"],
                "minPocSeverity": min_poc_severity,
                "srcDirs": src_dirs,
                "excludeDirs": self.project.get("excludeDirs", []),
                "excludePatterns": self.project.get("excludePatterns", []),
                "testPathTokens": self.project.get("testPathTokens", []),
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
            "--min-poc-severity",
            min_poc_severity,
            "--phases",
            ",".join(tier_cfg["phases"]),
        ]
        if tier_cfg.get("no_threat_model"):
            cmd.append("--no-threat-model")

        res = isolated_runner.run_isolated(
            cmd=cmd,
            cwd=snapshot_dir,
            env=os.environ.copy(),
            stream_output=True,
        )
        if res.returncode != 0:
            logger.warning(f"mjolnir-run exited with {res.returncode}")

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

    def _resolve_in_scope_file(
        self,
        raw_file: str,
        snapshot_dir: Path,
        in_scope_files: set[str],
        fallback_file: str = "unknown_file",
    ) -> str | None:
        """Resolves a model-emitted file path against the in-scope file set."""
        stripped = str(raw_file or "").split(":")[0].strip()
        clean = self._normalize_rel_path(stripped, snapshot_dir)
        if not clean or clean == "unknown_file":
            return fallback_file
        if clean in in_scope_files:
            return clean
        matches = [f for f in in_scope_files if f == clean or f.endswith(f"/{clean}")]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return sorted(matches)[0]
        if in_scope_files:
            return None
        return clean

    def _run_vanilla_agent_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        tier_key: str,
        tier_cfg: dict,
        model_override: str | None = None,
    ) -> tuple[list[dict], dict | None]:
        """Executes the Controlled Vanilla Single-Agent ADK Baseline (Whole-Dir or Single-Shot Per-File)."""
        import asyncio
        from google.adk import Context, Workflow
        from google.adk.agents.run_config import RunConfig
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        from google.adk.workflow import node
        from google.genai import types
        from data.security_report import SecurityReport
        from data.vulnerability import Vulnerability
        from providers.adk.agents.isolated_agent import IsolatedAgent
        from providers.adk.utilities.async_runner import (
            run_agent_node,
            run_batch_with_concurrency,
        )
        from providers.adk.utilities.usage_tracker import UsageTracker

        model_id = model_override or self.evaluator_model
        no_tm = bool(tier_cfg.get("no_threat_model", False))
        tm_path = "" if no_tm else str(self.project.get("threatModel") or "")
        tm_text = "" if no_tm else load_threat_model(tm_path if tm_path else None)
        granularity = str(tier_cfg.get("granularity", "dir"))
        target_dirs = self.resolve_target_dirs()
        target_str = ", ".join(target_dirs)
        batch_size = int(self.project.get("batchSize", 64))

        files_to_scan = discover_source_files(
            code_dir=str(snapshot_dir),
            src_dirs=target_dirs,
            extensions=set(self.project.get("extensions", ["rs", "c", "h"])),
            exclude_dirs=self.project.get("excludeDirs", []),
            exclude_patterns=self.project.get("excludePatterns", []),
        )
        in_scope_files = {p.replace("\\", "/").lstrip("./") for p in files_to_scan}

        # Write job_spec.json for archive provenance & elapsed time recovery
        (trial_out_dir / "job_spec.json").write_text(
            json.dumps(
                {
                    "tier": tier_key,
                    "granularity": granularity,
                    "no_threat_model": no_tm,
                    "model": model_id,
                    "target_dirs": target_dirs,
                    "in_scope_file_count": len(files_to_scan),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        @node(rerun_on_resume=True)
        async def vanilla_audit_node(
            ctx: Context, _node_input: object = None
        ) -> list[Vulnerability]:
            has_tools = granularity == "dir"
            tools = list(VANILLA_HOLISTIC_TOOLS) if has_tools else []
            instruction = build_vanilla_baseline_instruction(
                threat_model_context=tm_text,
                has_tools=has_tools,
            )

            def _wrap_up_before_limit_callback(
                callback_context: object, llm_request: object
            ) -> None:
                inv_ctx = getattr(callback_context, "_invocation_context", None)
                cost_mgr = getattr(inv_ctx, "_invocation_cost_manager", None)
                calls = getattr(cost_mgr, "_number_of_llm_calls", 0)
                if has_tools and calls >= VANILLA_BASELINE_MAX_LLM_CALLS - 5:
                    contents = getattr(llm_request, "contents", None)
                    if isinstance(contents, list):
                        contents.append(
                            types.Content(
                                role="user",
                                parts=[
                                    types.Part.from_text(
                                        text=(
                                            "IMPORTANT: You have reached the turn ceiling. "
                                            "Do NOT call `glob`, `grep_search`, or `read_file` again. "
                                            "Immediately call `set_model_response` with your final structured "
                                            "`SecurityReport` containing all vulnerabilities identified so far."
                                        )
                                    )
                                ],
                            )
                        )

            if has_tools:
                agent = IsolatedAgent(
                    name="AuditorAgent",
                    model=model_id,
                    instruction=instruction,
                    tools=tools,
                    output_schema=SecurityReport,
                    before_model_callback=_wrap_up_before_limit_callback,
                    run_config=RunConfig(max_llm_calls=VANILLA_BASELINE_MAX_LLM_CALLS),
                )
                prompt = (
                    f"Target Directory: {target_str}\n\n"
                    f"Perform a security audit of the non-test source files under `{target_str}` in this repository. "
                    f"Use your `glob`, `grep_search`, and `read_file` tools to explore and inspect the codebase, "
                    f"and report all identified security vulnerabilities."
                )
                report = await run_agent_node(
                    ctx,
                    agent,
                    node_input=prompt,
                    expected_schema=SecurityReport,
                    run_id=f"holistic_{tier_key}",
                )
                if not report or not getattr(report, "vulnerabilities", None):
                    return []
                vulns: list[Vulnerability] = []
                for af in report.vulnerabilities:
                    resolved_file = self._resolve_in_scope_file(
                        raw_file=af.file or "",
                        snapshot_dir=snapshot_dir,
                        in_scope_files=in_scope_files,
                        fallback_file=target_dirs[0] if target_dirs else "unknown_file",
                    )
                    if resolved_file is None:
                        continue
                    af.file = resolved_file
                    vulns.append(
                        Vulnerability.from_audit_finding(
                            af,
                            file_path=resolved_file,
                            phase_id="discovery",
                            phase_name="Vanilla Single-Agent Baseline",
                        )
                    )
                return vulns

            agent = IsolatedAgent(
                name="AuditorAgent",
                model=model_id,
                instruction=instruction,
                tools=tools,
                output_schema=SecurityReport,
                run_config=RunConfig(max_llm_calls=10),
            )

            async def audit_single_file(f_path: str) -> list[Vulnerability]:
                full_file_path = snapshot_dir / f_path
                try:
                    contents = await asyncio.to_thread(
                        full_file_path.read_text, encoding="utf-8", errors="ignore"
                    )
                except Exception as e:
                    logger.error(f"Could not read {f_path}: {e}")
                    return []
                file_prompt = (
                    f"Filename: {f_path}\n\n"
                    f"Perform a security audit of `{f_path}` and report all identified security vulnerabilities.\n\n"
                    f"### Full File Content:\n{contents}"
                )
                report = None
                try:
                    report = await asyncio.wait_for(
                        run_agent_node(
                            ctx,
                            agent,
                            node_input=file_prompt,
                            expected_schema=SecurityReport,
                            run_id=f_path,
                        ),
                        timeout=300.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Per-file baseline call timed out after 300s on {f_path}")
                if not report or not getattr(report, "vulnerabilities", None):
                    return []
                file_vulns: list[Vulnerability] = []
                for af in report.vulnerabilities:
                    af.file = f_path
                    file_vulns.append(
                        Vulnerability.from_audit_finding(
                            af,
                            file_path=f_path,
                            phase_id="discovery",
                            phase_name="Vanilla Single-Agent Baseline",
                        )
                    )
                return file_vulns

            results, _exceptions = await run_batch_with_concurrency(
                items=files_to_scan,
                worker_fn=audit_single_file,
                concurrency_limit=min(batch_size, 16),
                desc=f"Vanilla per-file ({tier_key})",
                unit="file",
                usage_tracker=ctx.state.get("usage_tracker"),
            )
            return [v for f_vulns in results for v in f_vulns]

        workflow = Workflow(
            name=f"VanillaBaseline_{tier_key}",
            edges=[("START", vanilla_audit_node)],
        )
        session_service = InMemorySessionService()
        runner = Runner(
            agent=workflow,
            app_name="mjolnir_vanilla_baseline",
            session_service=session_service,
        )
        usage_tracker = UsageTracker(run_dir=str(trial_out_dir))
        initial_state = {
            "model": model_id,
            "code_dir": str(snapshot_dir),
            "files": files_to_scan,
            "threat_model_context": tm_text,
            "batch_size": batch_size,
            "run_dir": str(trial_out_dir),
            "mode": "baseline",
            "enable_project_expert": False,
            "usage_tracker": usage_tracker,
            "vulnerabilities": [],
        }
        session = asyncio.run(
            session_service.create_session(
                app_name="mjolnir_vanilla_baseline",
                user_id="mjolnir_eval_user",
                state=initial_state,
            )
        )
        user_msg = types.Content(
            role="user",
            parts=[types.Part.from_text(text=json.dumps({"tier": tier_key}))],
        )

        emitted_vulns: list[Vulnerability] = []
        try:
            for ev in runner.run(
                user_id="mjolnir_eval_user",
                session_id=session.id,
                new_message=user_msg,
            ):
                usage_tracker.add(ev)
                if ev.node_name == "vanilla_audit_node" and isinstance(ev.output, list):
                    emitted_vulns = ev.output
        except Exception as e:
            logger.error(f"Vanilla baseline trial '{tier_key}' encountered error: {e}")

        usage_tracker.write_to_disk(str(trial_out_dir))
        usage_file = trial_out_dir / "token_usage.json"
        usage_data = (
            json.loads(usage_file.read_text(encoding="utf-8")) if usage_file.exists() else None
        )
        vulns_data = [
            v.model_dump(mode="json") if hasattr(v, "model_dump") else v
            for v in (emitted_vulns or [])
        ]
        return vulns_data, usage_data

    def _get_in_scope_files(self, snapshot_dir: Path) -> set[str]:
        """Returns the normalized relative paths of all in-scope source files for this evaluation target."""
        return {
            p.replace("\\", "/").lstrip("./")
            for p in discover_source_files(
                code_dir=str(snapshot_dir),
                src_dirs=self.resolve_target_dirs(),
                extensions=set(self.project.get("extensions", ["rs", "c", "h"])),
                exclude_dirs=self.project.get("excludeDirs", []),
                exclude_patterns=self.project.get("excludePatterns", []),
            )
        }

    def _normalize_rel_path(self, raw_path: str, snapshot_dir: Path) -> str:
        """Normalizes a tool-emitted file path to a workspace-relative path."""
        clean = raw_path.replace("\\", "/").strip()
        snap_str = str(snapshot_dir.resolve()).replace("\\", "/").rstrip("/") + "/"
        if clean.startswith(snap_str):
            clean = clean[len(snap_str) :]
        return clean.lstrip("./")

    def _write_trial_artifacts(
        self,
        trial_out_dir: Path,
        tier_key: str,
        tier_cfg: dict,
        vulns_data: list[dict],
    ) -> None:
        """Writes Web-UI compatible metadata.json, vulnerabilities.json, and vulnerabilities_minimal.json."""
        metadata = {
            "repo": self.project.get("repoUrl", ""),
            "model": str(tier_cfg.get("name", tier_key)),
            "ref": str(self.project.get("pinnedRev", "HEAD"))[:12],
            "target_commit": str(self.project.get("pinnedRev", "HEAD")),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "mode": f"Evaluation ({tier_key})",
            "trigger": "mjolnir-eval",
            "auth_mode": "SAST / Baseline",
            "status": "Success",
        }
        (trial_out_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )
        (trial_out_dir / "vulnerabilities.json").write_text(
            json.dumps(vulns_data, indent=2), encoding="utf-8"
        )
        minimal = []
        for v in vulns_data:
            minimal.append(
                {
                    "id": v.get("id", ""),
                    "file": v.get("file", ""),
                    "title": v.get("title", ""),
                    "severity": v.get("severity", "Low"),
                    "location": v.get("location", "Line 1"),
                    "description": v.get("description", ""),
                    "recommendation": v.get("recommendation", ""),
                    "verdict": v.get("verdict"),
                    "justification": v.get("justification", ""),
                    "attack_vector": v.get("attack_vector", ""),
                    "cwe": v.get("cwe") or "",
                    "attack_boundary": v.get("attack_boundary", ""),
                    "demonstrated_impact": v.get("demonstrated_impact", ""),
                    "cvss_score": v.get("cvss_score"),
                    "cvss_vector": v.get("cvss_vector", ""),
                    "security_objective_violation": v.get("security_objective_violation", ""),
                    "poc": v.get("poc"),
                    "poc_verified": v.get("poc_verified"),
                    "test_command": v.get("test_command"),
                    "status": v.get("status", "Open"),
                    "duplicate_of": v.get("duplicate_of"),
                    "related_locations": v.get("related_locations", []),
                }
            )
        (trial_out_dir / "vulnerabilities_minimal.json").write_text(
            json.dumps(minimal, indent=2), encoding="utf-8"
        )
