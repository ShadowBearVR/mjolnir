# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Real-World Pinned Evaluation & Ablation Runner (Mjolnir Multi-Checkpoint Ablation + CLI Templates + OpenAnt/SAST)."""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile
import time

from evaluation.constants import ABLATION_TIERS, DEFAULT_CLI_TEMPLATES, ORDERED_PIPELINE_PHASES
from evaluation.grader import (
    FindingPooler,
    compute_phase_transitions,
    extract_phase_checkpoint_findings,
    normalize_phase_id,
)
from evaluation.models import TrialRunRecord
from evaluation.sandbox.bwrap_runner import IsolatedProcessRunner
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


def extract_or_estimate_cli_usage(
    stdout_text: str,
    stderr_text: str,
    out_json_path: Path | None,
    prompt_text: str,
    scanned_files_bytes: int = 0,
) -> dict:
    """Extracts token telemetry from CLI output/JSON if emitted, or computes a deterministic char/4 token estimate."""
    # 1. Check out_json_path for embedded usage metadata
    if out_json_path and out_json_path.exists():
        try:
            parsed = json.loads(out_json_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                for key in ("usage", "token_usage", "usage_metadata", "total"):
                    sub = parsed.get(key)
                    if isinstance(sub, dict):
                        tot, cac, unc, out = _parse_single_usage_bucket(sub)
                        if tot > 0:
                            return {
                                "total": {
                                    "prompt_tokens": cac + unc,
                                    "cache_tokens": cac,
                                    "uncached_tokens": unc,
                                    "output_tokens": out,
                                    "total_input_tokens": cac + unc,
                                    "total_output_tokens": out,
                                    "total_tokens": tot,
                                },
                                "source": "cli_json_telemetry",
                            }
        except Exception:
            pass

    # 2. Check stdout / stderr for JSON usage lines or regex token counters
    combined = f"{stdout_text or ''}\n{stderr_text or ''}"
    for line in combined.splitlines():
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
                if isinstance(obj, dict):
                    cand = obj.get("usage") if isinstance(obj.get("usage"), dict) else obj
                    tot, cac, unc, out = _parse_single_usage_bucket(cand)
                    if tot > 0:
                        return {
                            "total": {
                                "prompt_tokens": cac + unc,
                                "cache_tokens": cac,
                                "uncached_tokens": unc,
                                "output_tokens": out,
                                "total_input_tokens": cac + unc,
                                "total_output_tokens": out,
                                "total_tokens": tot,
                            },
                            "source": "cli_stream_telemetry",
                        }
            except Exception:
                pass

    m_in = re.search(
        r"(?:input_tokens|prompt_tokens|input tokens)\s*[:=]\s*([0-9,]+)", combined, re.IGNORECASE
    )
    m_out = re.search(
        r"(?:output_tokens|completion_tokens|output tokens)\s*[:=]\s*([0-9,]+)",
        combined,
        re.IGNORECASE,
    )
    m_cac = re.search(
        r"(?:cache_tokens|cached_tokens|cache_read_input_tokens)\s*[:=]\s*([0-9,]+)",
        combined,
        re.IGNORECASE,
    )
    if m_in or m_out:
        in_tok = int(m_in.group(1).replace(",", "")) if m_in else 0
        out_tok = int(m_out.group(1).replace(",", "")) if m_out else 0
        cac_tok = int(m_cac.group(1).replace(",", "")) if m_cac else 0
        unc_tok = max(0, in_tok - cac_tok)
        return {
            "total": {
                "prompt_tokens": in_tok,
                "cache_tokens": cac_tok,
                "uncached_tokens": unc_tok,
                "output_tokens": out_tok,
                "total_input_tokens": in_tok,
                "total_output_tokens": out_tok,
                "total_tokens": in_tok + out_tok,
            },
            "source": "cli_regex_telemetry",
        }

    # 3. Deterministic fallback estimate (~4 bytes/token across prompt + scanned in-scope files + output)
    out_file_bytes = (
        out_json_path.stat().st_size if (out_json_path and out_json_path.exists()) else 0
    )
    est_in = max(1, (len(prompt_text.encode("utf-8")) + max(0, scanned_files_bytes)) // 4)
    est_out = max(1, (len((stdout_text or "").encode("utf-8")) + out_file_bytes) // 4)
    return {
        "total": {
            "prompt_tokens": est_in,
            "cache_tokens": 0,
            "uncached_tokens": est_in,
            "output_tokens": est_out,
            "total_input_tokens": est_in,
            "total_output_tokens": est_out,
            "total_tokens": est_in + est_out,
        },
        "source": "estimated_char_4",
    }


def format_model_slug(model: str) -> str:
    """Normalizes a model identifier (e.g. 'vertex_ai/claude-sonnet-4-6@20260514') to a concise slug."""
    slug = str(model or "").strip().split("/")[-1].split("@")[0]
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", slug).strip("-") or "default"


class EvaluationRunner:
    """Executes real-world pinned RoT evaluations across Mjolnir ablations, CLI agents, OpenAnt, and SAST baselines."""

    def __init__(
        self,
        spec: dict,
        output_root: Path,
        cache_root: Path,
        corpus_root: Path | None = None,
        mjolnir_bin: str = "mjolnir-run",
        evaluator_model: str | list[str] | None = None,
        judge_model: str | None = None,
        cli_templates: dict[str, str] | None = None,
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
        self.judge_model = judge_model or self.project.get("judgeModel")
        self.cli_templates = {
            **DEFAULT_CLI_TEMPLATES,
            **(self.project.get("cliTemplates") or {}),
            **(cli_templates or {}),
        }
        self.snapshot_builder = OrphanSnapshotBuilder(cache_root=self.cache_root)
        self.pooler = FindingPooler(judge_model=self.judge_model)

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
            if t == "sast":
                sast_list = self.project.get("sastTiers") or ["semgrep", "clippy"]
                for st in sast_list:
                    if st not in active_tiers:
                        active_tiers.append(str(st))
            elif t not in active_tiers:
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
        if manifest_path.exists():
            try:
                raw_prev = json.loads(manifest_path.read_text(encoding="utf-8"))
                for item in raw_prev:
                    rec = TrialRunRecord.model_validate(item)
                    existing_by_key[(rec.ablation_tier, rec.repetition)] = rec
            except Exception as e:
                logger.warning(f"Could not load existing trials_manifest.json: {e}")

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
            is_mjolnir_tier = tier_cfg.get("runner") == "mjolnir"
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
                    for rec in trial_records:
                        existing_by_key[(rec.ablation_tier, rec.repetition)] = rec

        all_trials = list(existing_by_key.values())
        manifest_path.write_text(
            json.dumps([t.model_dump() for t in all_trials], indent=2),
            encoding="utf-8",
        )
        logger.success(f"Saved {len(all_trials)} trial records to {manifest_path}")

        # Build / update the provenance-stripped blind review pool and provenance mapping
        # For deterministic SAST-only runs, default to heuristic pooling unless judge_model was explicitly overridden
        pooler = (
            FindingPooler(judge_model="heuristic")
            if set(active_tiers).issubset({"semgrep", "clippy"})
            else self.pooler
        )
        pooler.build_pool(trials=all_trials, output_dir=eval_out_dir)
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
            self.evaluator_model if tier_cfg.get("runner") == "mjolnir" else str(tier_cfg["name"])
        )

        try:
            runner_type = tier_cfg["runner"]
            self.snapshot_builder.materialize_orphan_snapshot(
                baseline_dir=baseline_dir,
                dest_dir=snapshot_dir,
                skip_ctags=(runner_type in ("semgrep", "clippy")),
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
            elif runner_type == "cli_template":
                vulns_data, usage_summary = self._run_cli_template_tier(
                    snapshot_dir=snapshot_dir,
                    trial_out_dir=trial_out_dir,
                    tier_cfg=tier_cfg,
                    isolated_runner=isolated_runner,
                )
            elif runner_type == "openant":
                vulns_data, usage_summary = self._run_openant_tier(
                    snapshot_dir=snapshot_dir,
                    trial_out_dir=trial_out_dir,
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
            shutil.copytree(trial_out_dir, archive_dir)

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
            v for v in vulnerabilities_data if str(v.get("status", "Open")).lower() == "open"
        ]
        poc_verified = [
            v
            for v in open_findings
            if v.get("poc_verified")
            or (isinstance(v.get("poc"), dict) and v["poc"].get("verified"))
        ]
        target_dirs = self.resolve_target_dirs()
        return TrialRunRecord(
            project_name=str(self.project.get("name") or self.project["repoName"]),
            repo_name=str(self.project["repoName"]),
            pinned_rev=str(self.project.get("pinnedRev") or "HEAD"),
            target_dir=target_dirs[0] if target_dirs else ".",
            ablation_tier=ablation_tier,
            tier_name=tier_name,
            model=model,
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

    def _run_cli_template_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        tier_cfg: dict,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        """Executes a host/Nix-provided CLI command template in either directory or per-file mode."""
        cli_key = str(tier_cfg.get("cli_key", "antigravity"))
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

        target_dirs = self.resolve_target_dirs()
        granularity = str(tier_cfg.get("granularity", "dir"))
        files_to_scan = discover_source_files(
            code_dir=str(snapshot_dir),
            src_dirs=target_dirs,
            extensions=set(self.project.get("extensions", ["rs", "c", "h"])),
            exclude_dirs=self.project.get("excludeDirs", []),
            exclude_patterns=self.project.get("excludePatterns", []),
        )

        if granularity == "per_file":
            aggregated: list[dict] = []
            tot_in = tot_cac = tot_unc = tot_out = 0
            usage_source = "estimated_char_4"
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
                f_path = snapshot_dir / rel_file
                f_bytes = f_path.stat().st_size if f_path.exists() else 0
                file_usage = extract_or_estimate_cli_usage(
                    stdout_text=res.stdout,
                    stderr_text=res.stderr,
                    out_json_path=out_json,
                    prompt_text=prompt,
                    scanned_files_bytes=f_bytes,
                )
                _, cac, unc, out = parse_usage_metrics(file_usage)
                tot_cac += cac
                tot_unc += unc
                tot_in += cac + unc
                tot_out += out
                if file_usage.get("source") != "estimated_char_4":
                    usage_source = str(file_usage.get("source"))
                aggregated.extend(
                    extract_findings_from_cli_output(out_json, res.stdout, default_file=rel_file)
                )
            usage_summary = {
                "total": {
                    "prompt_tokens": tot_in,
                    "cache_tokens": tot_cac,
                    "uncached_tokens": tot_unc,
                    "output_tokens": tot_out,
                    "total_input_tokens": tot_in,
                    "total_output_tokens": tot_out,
                    "total_tokens": tot_in + tot_out,
                },
                "source": usage_source,
            }
            (trial_out_dir / "token_usage.json").write_text(
                json.dumps(usage_summary, indent=2), encoding="utf-8"
            )
            return aggregated, usage_summary

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
        total_scanned_bytes = sum(
            (snapshot_dir / rf).stat().st_size
            for rf in files_to_scan
            if (snapshot_dir / rf).exists()
        )
        usage_summary = extract_or_estimate_cli_usage(
            stdout_text=res.stdout,
            stderr_text=res.stderr,
            out_json_path=out_json,
            prompt_text=prompt,
            scanned_files_bytes=total_scanned_bytes,
        )
        (trial_out_dir / "token_usage.json").write_text(
            json.dumps(usage_summary, indent=2), encoding="utf-8"
        )
        return extract_findings_from_cli_output(out_json, res.stdout), usage_summary

    def _run_openant_tier(
        self,
        snapshot_dir: Path,
        trial_out_dir: Path,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        openant_bin = shutil.which("openant")
        if not openant_bin:
            logger.warning("openant binary not found in PATH; recording empty baseline.")
            return [], None
        target_dirs = self.resolve_target_dirs()
        out_json = trial_out_dir / "openant_results.json"
        res = isolated_runner.run_isolated(
            cmd=[openant_bin, "scan", target_dirs[0], "--output", str(out_json)],
            cwd=snapshot_dir,
            env=os.environ.copy(),
        )
        return extract_findings_from_cli_output(out_json, res.stdout), None

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

    def _run_clippy_tier(
        self,
        snapshot_dir: Path,
        isolated_runner: IsolatedProcessRunner,
    ) -> tuple[list[dict], dict | None]:
        in_scope_files = self._get_in_scope_files(snapshot_dir)
        lint_cmd_str = str(self.project.get("lintCmd") or "").strip()
        has_cargo_toml = (snapshot_dir / "Cargo.toml").exists()

        if has_cargo_toml:
            if lint_cmd_str.startswith("cargo clippy"):
                tokens = shlex.split(lint_cmd_str)
                if "--" in tokens:
                    dash_idx = tokens.index("--")
                    base_tokens = tokens[:dash_idx]
                else:
                    base_tokens = tokens
                if "--message-format=json" not in base_tokens:
                    base_tokens.append("--message-format=json")
                if "--ignore-rust-version" not in base_tokens:
                    base_tokens.append("--ignore-rust-version")
                cmd = base_tokens
            else:
                cmd = [
                    "cargo",
                    "clippy",
                    "--workspace",
                    "--message-format=json",
                    "--ignore-rust-version",
                ]
        elif lint_cmd_str:
            cmd = shlex.split(lint_cmd_str)
            if cmd[0] in ("bazel", "bazelisk") and "--@rules_rust//:error_format=json" not in cmd:
                cmd.insert(2, "--@rules_rust//:error_format=json")
        else:
            logger.info("No Cargo.toml or lintCmd configured for project; skipping clippy tier.")
            return [], None

        env = os.environ.copy()
        if has_cargo_toml:
            repo_name = self.project.get("repoName", "default")
            shared_cargo_target = Path(f"/tmp/mjolnir-eval-cargo-target/{repo_name}")
            shared_cargo_target.mkdir(parents=True, exist_ok=True)
            env["CARGO_TARGET_DIR"] = str(shared_cargo_target)

        res = isolated_runner.run_isolated(
            cmd=cmd,
            cwd=snapshot_dir,
            env=env,
        )

        vulns: list[dict] = []
        seen_keys: set[tuple[str, int, str]] = set()
        combined_lines = res.stdout.splitlines() + res.stderr.splitlines()

        for line in combined_lines:
            line_str = line.strip()
            if not line_str.startswith("{"):
                continue
            try:
                msg = json.loads(line_str)
            except Exception:
                continue
            inner = msg.get("message") if msg.get("reason") == "compiler-message" else msg
            if not isinstance(inner, dict):
                continue
            level = str(inner.get("level") or "").lower()
            if level not in ("warning", "error"):
                continue
            spans = inner.get("spans", [])
            if not isinstance(spans, list) or not spans:
                continue
            primary = next((s for s in spans if s.get("is_primary")), spans[0])
            rel_file = self._normalize_rel_path(str(primary.get("file_name", "")), snapshot_dir)
            if in_scope_files and rel_file not in in_scope_files:
                continue
            line_start = int(primary.get("line_start") or 1)
            code_obj = inner.get("code")
            code_str = code_obj.get("code") if isinstance(code_obj, dict) else None
            raw_title = str(inner.get("message") or "Clippy diagnostic")
            title = f"[{code_str}] {raw_title}" if code_str else raw_title
            dedup_key = (rel_file, line_start, title)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            severity = "Medium" if level == "error" else "Low"
            vulns.append(
                {
                    "id": f"clippy-{len(vulns) + 1}",
                    "file": rel_file,
                    "location": f"Line {line_start}",
                    "cwe": None,
                    "title": title,
                    "description": str(inner.get("rendered") or raw_title),
                    "severity": severity,
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

        in_scope_files = self._get_in_scope_files(snapshot_dir)
        target_dirs = self.resolve_target_dirs()

        rules_cfg = self.spec.get("config", {}).get("semgrepRulesPath")
        local_fallback = (
            Path(__file__).resolve().parent.parent.parent
            / "evaluations"
            / "semgrep-rules"
            / "pinned-rules.yaml"
        )
        if rules_cfg and Path(rules_cfg).exists():
            config_arg = f"--config={rules_cfg}"
        elif local_fallback.exists():
            config_arg = f"--config={local_fallback}"
        else:
            config_arg = "--config=auto"

        cmd = [
            "semgrep",
            "scan",
            config_arg,
            "--no-git-ignore",
            "--metrics=off",
            "--disable-version-check",
            "--json",
            *target_dirs,
        ]
        res = isolated_runner.run_isolated(
            cmd=cmd,
            cwd=snapshot_dir,
            env=os.environ.copy(),
        )
        try:
            data = json.loads(res.stdout)
        except Exception:
            return [], None

        severity_map = {
            "CRITICAL": "Critical",
            "ERROR": "High",
            "HIGH": "High",
            "WARNING": "Medium",
            "MEDIUM": "Medium",
            "INFO": "Low",
            "LOW": "Low",
            "INVENTORY": "Informational",
        }

        vulns: list[dict] = []
        for r in data.get("results", []):
            rel_file = self._normalize_rel_path(str(r.get("path", "")), snapshot_dir)
            if in_scope_files and rel_file not in in_scope_files:
                continue
            extra = r.get("extra", {}) or {}
            cwe_list = (extra.get("metadata", {}) or {}).get("cwe", [])
            if isinstance(cwe_list, list) and cwe_list:
                cwe_str = str(cwe_list[0])
            elif isinstance(cwe_list, str) and cwe_list:
                cwe_str = cwe_list
            else:
                cwe_str = None
            raw_sev = str(extra.get("severity") or "WARNING").upper()
            severity = severity_map.get(raw_sev, "Medium")
            line_num = (r.get("start") or {}).get("line", 1)
            raw_check_id = str(r.get("check_id", "Semgrep finding"))
            clean_check_id = re.sub(
                r"^.*?(?=(?:rust|c|cpp|generic|dockerfile|yaml|bash|python|go|java|javascript|typescript|security)\.)",
                "",
                raw_check_id,
            )
            vulns.append(
                {
                    "id": f"semgrep-{len(vulns) + 1}",
                    "file": rel_file,
                    "location": f"Line {line_num}",
                    "cwe": cwe_str,
                    "title": clean_check_id,
                    "description": str(extra.get("message", "")),
                    "severity": severity,
                    "status": "Open",
                    "history": [],
                }
            )
        return vulns, None
