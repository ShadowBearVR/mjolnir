# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Aggregates real-world pinned trials, blind review adjudications, and RQ1-RQ4 metrics into Markdown and USENIX LaTeX tables."""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess

from evaluation.constants import ABLATION_TIERS, ORDERED_PIPELINE_PHASES
from evaluation.grader import (
    FindingPooler,
    compute_inter_rater_stats,
    compute_phase_transitions,
    normalize_phase_id,
)
from evaluation.models import (
    CanonicalFinding,
    CrossModelConsistencySummary,
    FindingOccurrence,
    FindingPoolMapping,
    InterRaterStats,
    TierEvaluationSummary,
    TrialRunRecord,
)
from utilities.logger import logger


class ScorecardGenerator:
    """Joins trial manifests with blind review labels to compute RQ1-RQ4 USENIX Security scorecards."""

    MODEL_PRICING_SCHEDULES_USD_PER_1M: dict[str, dict[str, float | str]] = {
        "gemini-3.8-flash": {
            "uncached_input": 0.75,
            "cached_input": 0.075,
            "output_and_thoughts": 3.75,
            "as_of": "2026-10-19",
        },
        "gemini-4-argon": {
            "uncached_input": 2.00,
            "cached_input": 0.10,
            "output_and_thoughts": 10.00,
            "as_of": "2026-10-19",
        },
        "claude-sonnet-5-5": {
            "uncached_input": 2.00,
            "cached_input": 0.20,
            "output_and_thoughts": 10.00,
            "as_of": "2026-10-19",
        },
    }

    @staticmethod
    def _get_mjolnir_commit() -> str:
        try:
            repo_root = Path(__file__).resolve().parent.parent.parent
            return (
                subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=repo_root, stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .strip()
            )
        except Exception:
            return "unknown"

    @staticmethod
    def _is_mjolnir_dirty() -> bool:
        try:
            repo_root = Path(__file__).resolve().parent.parent.parent
            out = (
                subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=repo_root, stderr=subprocess.DEVNULL
                )
                .decode("utf-8")
                .strip()
            )
            return bool(out)
        except Exception:
            return False

    @staticmethod
    def _load_trial_thoughts_and_output_tokens(
        eval_dir: Path, tier_key: str, trial: TrialRunRecord
    ) -> tuple[int, int]:
        """Reads separated (thoughts_tokens, pure_output_tokens) from trial token_usage.json."""
        base_tier = tier_key.split("@")[0]
        rep_dir = eval_dir / "trials" / base_tier / f"rep_{trial.repetition}"
        tu_files = (
            sorted(rep_dir.glob("run_*/token_usage.json"))
            or sorted(rep_dir.glob("token_usage.json"))
            if rep_dir.is_dir()
            else []
        )
        if tu_files:
            try:
                tu_data = json.loads(tu_files[-1].read_text(encoding="utf-8"))
                if "@" in tier_key:
                    ckpt = normalize_phase_id(tier_key.split("@", 1)[1])
                    by_phase = tu_data.get("by_phase") or {}
                    if isinstance(by_phase, dict) and ckpt in ORDERED_PIPELINE_PHASES:
                        idx = ORDERED_PIPELINE_PHASES.index(ckpt)
                        allowed = {"project_exploration", *ORDERED_PIPELINE_PHASES[: idx + 1]}
                        tho = sum(
                            int((by_phase.get(p) or {}).get("thoughts_tokens", 0) or 0)
                            for p in allowed
                        )
                        out = sum(
                            int((by_phase.get(p) or {}).get("output_tokens", 0) or 0)
                            for p in allowed
                        )
                        if tho + out > 0:
                            return tho, out
                tot = tu_data.get("total") or {}
                tho = int(tot.get("thoughts_tokens", 0) or 0)
                out = int(tot.get("output_tokens", 0) or 0)
                if tho + out > 0:
                    return tho, out
            except Exception:
                pass
        return 0, int(trial.output_tokens)

    def generate_scorecard(
        self, eval_path: Path, output_dir: Path | None = None
    ) -> list[TierEvaluationSummary]:
        eval_dir = eval_path if eval_path.is_dir() else eval_path.parent
        out_dir = output_dir or eval_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        manifest_path = (
            eval_path
            if eval_path.is_file() and eval_path.name == "trials_manifest.json"
            else eval_dir / "trials_manifest.json"
        )
        if not manifest_path.exists():
            raise FileNotFoundError(f"Trials manifest not found: {manifest_path}")

        raw_trials = json.loads(manifest_path.read_text(encoding="utf-8"))
        trials = [TrialRunRecord.model_validate(t) for t in raw_trials]

        pool_path = eval_dir / "blind_review_pool.json"
        mapping_path = eval_dir / "finding_pool_mapping.json"
        if not pool_path.exists() or not mapping_path.exists():
            FindingPooler().build_pool(trials=trials, output_dir=eval_dir)

        pool = [
            CanonicalFinding.model_validate(c)
            for c in json.loads(pool_path.read_text(encoding="utf-8"))
        ]
        mappings = [
            FindingPoolMapping.model_validate(m)
            for m in json.loads(mapping_path.read_text(encoding="utf-8"))
        ]

        inter_rater = compute_inter_rater_stats(pool)
        canon_by_id: dict[str, CanonicalFinding] = {c.canonical_id: c for c in pool}

        # Map (ablation_tier, repetition) -> list[(canonical_id, FindingOccurrence)]
        occs_by_trial: dict[tuple[str, int], list[tuple[str, FindingOccurrence]]] = defaultdict(
            list
        )
        for m in mappings:
            for occ in m.occurrences:
                occs_by_trial[(occ.ablation_tier, occ.repetition)].append((m.canonical_id, occ))

        # Precompute discovery-stage TPs and FPs per (base_tier, repetition) for RQ2 funnel rates
        discovery_tps_by_run: dict[tuple[str, int], set[str]] = defaultdict(set)
        discovery_fps_by_run: dict[tuple[str, int], set[str]] = defaultdict(set)
        for (tier_key, rep), pairs in occs_by_trial.items():
            if tier_key.endswith("@discovery"):
                base_tier = tier_key.split("@")[0]
                for cid, occ in pairs:
                    if occ.status.lower() != "open":
                        continue
                    cf = canon_by_id.get(cid)
                    if not cf:
                        continue
                    if cf.resolved_label == "TP":
                        discovery_tps_by_run[(base_tier, rep)].add(cid)
                    elif cf.resolved_label == "FP":
                        discovery_fps_by_run[(base_tier, rep)].add(cid)

        by_tier: dict[str, list[TrialRunRecord]] = defaultdict(list)
        for t in trials:
            by_tier[t.ablation_tier].append(t)

        summaries: list[TierEvaluationSummary] = []
        for tier_key, tier_trials in by_tier.items():
            summaries.append(
                self._aggregate_tier(
                    eval_dir=eval_dir,
                    tier_key=tier_key,
                    tier_trials=tier_trials,
                    canon_by_id=canon_by_id,
                    occs_by_trial=occs_by_trial,
                    discovery_tps_by_run=discovery_tps_by_run,
                    discovery_fps_by_run=discovery_fps_by_run,
                )
            )

        cross_model = self._compute_cross_model_consistency(
            summaries=summaries,
            canon_by_id=canon_by_id,
            occs_by_trial=occs_by_trial,
        )

        payload = {
            "inter_rater_stats": inter_rater.model_dump(),
            "cross_model_consistency": cross_model.model_dump() if cross_model else None,
            "tiers": [s.model_dump() for s in summaries],
        }
        (out_dir / "scorecard.json").write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )
        (out_dir / "scorecard.md").write_text(
            self._render_markdown(summaries, inter_rater, cross_model),
            encoding="utf-8",
        )
        (out_dir / "scorecard_tables.tex").write_text(
            self._render_latex_booktabs(summaries, inter_rater, cross_model),
            encoding="utf-8",
        )
        self._export_modular_paper_tables(
            out_dir=out_dir,
            trials=trials,
            summaries=summaries,
            inter_rater=inter_rater,
            cross_model=cross_model,
            manifest_path=manifest_path,
            pool_path=pool_path,
        )

        logger.success(
            f"Generated scorecard artifacts in {out_dir} (scorecard.json, scorecard.md, scorecard_tables.tex, paper_tables/)"
        )
        return summaries

    def _aggregate_tier(
        self,
        eval_dir: Path,
        tier_key: str,
        tier_trials: list[TrialRunRecord],
        canon_by_id: dict[str, CanonicalFinding],
        occs_by_trial: dict[tuple[str, int], list[tuple[str, FindingOccurrence]]],
        discovery_tps_by_run: dict[tuple[str, int], set[str]],
        discovery_fps_by_run: dict[tuple[str, int], set[str]],
    ) -> TierEvaluationSummary:
        all_tp_canons = [c for c in canon_by_id.values() if c.resolved_label == "TP"]
        total_pooled_tps = len(all_tp_canons)
        base_tier = tier_key.split("@")[0]

        open_counts: list[float] = []
        unique_rca_counts: list[float] = []
        redundant_dup_counts: list[float] = []
        tp_counts: list[float] = []
        fp_counts: list[float] = []
        unlabeled_counts: list[float] = []
        poc_counts: list[float] = []
        poc_tp_counts: list[float] = []
        open_unverified_counts: list[float] = []
        harness_limitation_counts: list[float] = []
        disproved_by_harness_counts: list[float] = []
        precisions: list[float] = []
        recalls: list[float] = []
        false_disproofs: list[float] = []
        fp_eliminations: list[float] = []
        poc_pass_rates: list[float] = []

        run_tokens: list[int] = []
        run_cached_tokens: list[int] = []
        run_uncached_tokens: list[int] = []
        run_thoughts_tokens: list[int] = []
        run_pure_output_tokens: list[int] = []
        run_output_tokens: list[int] = []
        run_times: list[float] = []
        rep_open_sets: list[set[str]] = []
        rep_poc_sets: list[set[str]] = []
        rep_tp_sets: list[set[str]] = []
        rep_fp_sets: list[set[str]] = []
        severity_totals: dict[str, int] = defaultdict(int)
        module_totals: dict[str, int] = defaultdict(int)

        for trial in sorted(tier_trials, key=lambda x: x.repetition):
            rep = trial.repetition
            pairs = occs_by_trial.get((tier_key, rep), [])

            open_cids: set[str] = set()
            poc_cids: set[str] = set()
            tp_cids: set[str] = set()
            fp_cids: set[str] = set()
            unlabeled_cids: set[str] = set()
            poc_tp_cids: set[str] = set()

            for cid, occ in pairs:
                if occ.status.split(".")[-1].lower() != "open":
                    continue
                open_cids.add(cid)
                if occ.poc_verified:
                    poc_cids.add(cid)
                cf = canon_by_id.get(cid)
                sev = (occ.severity or (cf.severity if cf else "") or "Informational").capitalize()
                severity_totals[sev] += 1
                fp_str = cf.file if cf and cf.file else "unknown"
                parts = [p for p in Path(fp_str).parts if p not in (".", "")]
                mod_key = (
                    "/".join(parts[:2]) if len(parts) >= 2 else (parts[0] if parts else "unknown")
                )
                module_totals[mod_key] += 1
                label = cf.resolved_label if cf else None
                if label == "TP":
                    tp_cids.add(cid)
                    if occ.poc_verified:
                        poc_tp_cids.add(cid)
                elif label == "FP":
                    fp_cids.add(cid)
                else:
                    unlabeled_cids.add(cid)

            n_tp = len(tp_cids)
            n_fp = len(fp_cids)
            n_labeled_open = n_tp + n_fp
            open_findings = [
                v
                for v in trial.findings
                if str(getattr(v.get("status"), "value", v.get("status", "Open"))).lower() == "open"
            ]
            n_open = trial.open_findings_count or len(open_findings)
            n_unique_rca = len(open_cids)
            n_redundant_dup = max(0, n_open - n_unique_rca)
            n_poc = trial.poc_verified_count
            trial_pts = (
                compute_phase_transitions(trial.findings)
                if ("@" not in tier_key and trial.findings)
                else trial.phase_transitions
            )
            has_poc_stage = any(pt.phase_id == "poc_creation" for pt in trial_pts) or (
                "@" in tier_key and tier_key.split("@", 1)[1] in ("poc_creation", "final_review")
            )
            n_open_unverified = max(0, n_open - n_poc) if has_poc_stage else 0
            n_harness_limitation = (
                sum(
                    1
                    for v in open_findings
                    if not (
                        v.get("poc_verified")
                        or (isinstance(v.get("poc"), dict) and v["poc"].get("verified"))
                    )
                    and "[HARNESS_LIMITATION]" in json.dumps(v)
                )
                if has_poc_stage
                else 0
            )
            n_disproved_by_harness = (
                sum(1 for v in trial.findings if "[DISPROVED_BY_HARNESS]" in json.dumps(v))
                if has_poc_stage
                else 0
            )

            open_counts.append(float(n_open))
            unique_rca_counts.append(float(n_unique_rca))
            redundant_dup_counts.append(float(n_redundant_dup))
            tp_counts.append(float(n_tp))
            fp_counts.append(float(n_fp))
            unlabeled_counts.append(float(len(unlabeled_cids)))
            poc_counts.append(float(n_poc))
            poc_tp_counts.append(float(len(poc_tp_cids)))
            open_unverified_counts.append(float(n_open_unverified))
            harness_limitation_counts.append(float(n_harness_limitation))
            disproved_by_harness_counts.append(float(n_disproved_by_harness))

            precisions.append(n_tp / n_labeled_open if n_labeled_open > 0 else 0.0)
            recalls.append(n_tp / total_pooled_tps if total_pooled_tps > 0 else 0.0)
            poc_pass_rates.append(n_poc / n_open if n_open > 0 else 0.0)

            disc_tps = discovery_tps_by_run.get((base_tier, rep), set())
            if disc_tps:
                disproved_tps = disc_tps - tp_cids
                false_disproofs.append(len(disproved_tps) / len(disc_tps))
            else:
                false_disproofs.append(0.0)

            disc_fps = discovery_fps_by_run.get((base_tier, rep), set())
            if disc_fps:
                eliminated_fps = disc_fps - fp_cids
                fp_eliminations.append(len(eliminated_fps) / len(disc_fps))
            else:
                fp_eliminations.append(0.0)

            tho_tok, pure_out_tok = self._load_trial_thoughts_and_output_tokens(
                eval_dir=eval_dir, tier_key=tier_key, trial=trial
            )
            rep_open_sets.append(open_cids)
            rep_poc_sets.append(poc_cids)
            rep_tp_sets.append(tp_cids)
            rep_fp_sets.append(fp_cids)
            run_tokens.append(trial.total_tokens)
            run_cached_tokens.append(trial.cached_tokens)
            run_uncached_tokens.append(trial.uncached_input_tokens)
            run_thoughts_tokens.append(tho_tok)
            run_pure_output_tokens.append(pure_out_tok)
            run_output_tokens.append(trial.output_tokens)
            run_times.append(trial.wall_clock_seconds)

        funnel_acc: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "entering": 0,
                "surviving": 0,
                "closed": 0,
                "duplicate": 0,
                "poc_verified": 0,
                "upgraded": 0,
                "downgraded": 0,
                "unchanged": 0,
            }
        )
        base_tier_unqual = re.sub(r"\[.*\]$", "", base_tier)
        requires_full_pipeline = "@" not in tier_key and base_tier_unqual in (
            "full",
            "no_tm",
            "no_expert",
        )
        funnel_trial_pts: list[list] = []
        for trial in tier_trials:
            pts = (
                compute_phase_transitions(trial.findings)
                if ("@" not in tier_key and trial.findings)
                else trial.phase_transitions
            )
            if not pts:
                continue
            if (
                requires_full_pipeline
                and "final_review" not in {pt.phase_id for pt in pts}
                and pts[-1].surviving_open_count > 0
            ):
                continue
            funnel_trial_pts.append(pts)
        if not funnel_trial_pts:
            for trial in tier_trials:
                pts = (
                    compute_phase_transitions(trial.findings)
                    if ("@" not in tier_key and trial.findings)
                    else trial.phase_transitions
                )
                if pts:
                    funnel_trial_pts.append(pts)
        for pts in funnel_trial_pts:
            for pt in pts:
                bucket = funnel_acc[pt.phase_id]
                bucket["entering"] += pt.entering_count
                bucket["surviving"] += pt.surviving_open_count
                bucket["closed"] += pt.closed_count
                bucket["duplicate"] += pt.duplicate_count
                bucket["poc_verified"] += pt.poc_verified_count
                bucket["upgraded"] += pt.severity_upgraded_count
                bucket["downgraded"] += pt.severity_downgraded_count
                bucket["unchanged"] += pt.severity_unchanged_count

        n_reps = max(1, len(tier_trials))
        n_funnel_reps = max(1, len(funnel_trial_pts))
        phase_funnel_summary = {
            pid: {k: round(v / n_funnel_reps, 2) for k, v in counts.items()}
            for pid, counts in funnel_acc.items()
        }

        unique_open_across_reps = len(set().union(*rep_open_sets)) if rep_open_sets else 0
        consistent_open_all_reps = len(set.intersection(*rep_open_sets)) if rep_open_sets else 0
        unique_tps_across_reps = len(set().union(*rep_tp_sets)) if rep_tp_sets else 0
        consistent_tps_all_reps = len(set.intersection(*rep_tp_sets)) if rep_tp_sets else 0
        if len(rep_open_sets) > 1:
            jaccards: list[float] = []
            for i in range(len(rep_open_sets)):
                for j in range(i + 1, len(rep_open_sets)):
                    u_sz = len(rep_open_sets[i] | rep_open_sets[j])
                    jaccards.append(
                        len(rep_open_sets[i] & rep_open_sets[j]) / u_sz if u_sz > 0 else 1.0
                    )
            consistency_jaccard_mean: float | None = round(statistics.fmean(jaccards), 4)
            consistency_jaccard_std: float | None = round(
                statistics.stdev(jaccards) if len(jaccards) > 1 else 0.0, 4
            )
        else:
            consistency_jaccard_mean = None
            consistency_jaccard_std = None

        N = len(rep_open_sets)
        open_freq: dict[str, int] = defaultdict(int)
        poc_freq: dict[str, int] = defaultdict(int)
        tp_freq: dict[str, int] = defaultdict(int)
        fp_freq: dict[str, int] = defaultdict(int)
        for s_open, s_poc, s_tp, s_fp in zip(rep_open_sets, rep_poc_sets, rep_tp_sets, rep_fp_sets):
            for cid in s_open:
                open_freq[cid] += 1
            for cid in s_poc:
                poc_freq[cid] += 1
            for cid in s_tp:
                tp_freq[cid] += 1
            for cid in s_fp:
                fp_freq[cid] += 1

        def _expected_accumulation(freq_map: dict[str, int], k: int, n_total: int) -> float:
            if n_total <= 0 or k <= 0:
                return 0.0
            denom = math.comb(n_total, k)
            if denom == 0:
                return 0.0
            total_exp = 0.0
            for c_v in freq_map.values():
                missed = math.comb(n_total - c_v, k) if (n_total - c_v) >= k else 0
                total_exp += 1.0 - (missed / denom)
            return round(total_exp, 2)

        saturation_curve: dict[int, dict[str, float]] = {}
        for k in range(1, N + 1):
            saturation_curve[k] = {
                "expected_open": _expected_accumulation(open_freq, k, N),
                "expected_poc_verified": _expected_accumulation(poc_freq, k, N),
                "expected_tp": _expected_accumulation(tp_freq, k, N),
                "expected_fp": _expected_accumulation(fp_freq, k, N),
            }

        severity_distribution_mean = {
            sev: round(cnt / n_reps, 2) for sev, cnt in sorted(severity_totals.items())
        }
        module_distribution_mean = {
            mod: round(cnt / n_reps, 2)
            for mod, cnt in sorted(module_totals.items(), key=lambda x: (-x[1], x[0]))
        }
        finding_detection_frequencies = {
            cid: round(cnt / n_reps, 4)
            for cid, cnt in sorted(open_freq.items(), key=lambda x: (-x[1], x[0]))
        }

        mean_open = statistics.fmean(open_counts) if open_counts else 0.0
        mean_unique_rca = statistics.fmean(unique_rca_counts) if unique_rca_counts else 0.0
        mean_redundant_dups = (
            statistics.fmean(redundant_dup_counts) if redundant_dup_counts else 0.0
        )
        redundancy_ratio = round(mean_open / mean_unique_rca, 2) if mean_unique_rca > 0 else 1.0
        mean_tp = statistics.fmean(tp_counts) if tp_counts else 0.0
        mean_tok = statistics.fmean(run_tokens) if run_tokens else 0.0
        tokens_per_tp = round(mean_tok / mean_tp, 1) if mean_tp > 0 else None

        lookup_base = re.sub(r"\[.*\]$", "", base_tier)
        fallback_name = str(ABLATION_TIERS.get(lookup_base, {}).get("name", tier_key))
        tier_name = (
            tier_trials[0].tier_name
            if tier_trials and tier_trials[0].tier_name
            else (
                f"{fallback_name} [{tier_key.split('@')[1]}]" if "@" in tier_key else fallback_name
            )
        )
        model_str = tier_trials[0].model if tier_trials else ""

        return TierEvaluationSummary(
            ablation_tier=tier_key,
            tier_name=tier_name,
            model=model_str,
            repetitions=len(tier_trials),
            total_pooled_tps=total_pooled_tps,
            mean_open_findings=round(mean_open, 2),
            std_open_findings=round(
                statistics.stdev(open_counts) if len(open_counts) > 1 else 0.0, 2
            ),
            mean_unique_root_causes=round(mean_unique_rca, 2),
            mean_redundant_duplicates=round(mean_redundant_dups, 2),
            redundancy_ratio=redundancy_ratio,
            mean_true_positives=round(mean_tp, 2),
            std_true_positives=round(statistics.stdev(tp_counts) if len(tp_counts) > 1 else 0.0, 2),
            unique_open_across_reps=unique_open_across_reps,
            consistent_open_all_reps=consistent_open_all_reps,
            unique_tps_across_reps=unique_tps_across_reps,
            consistent_tps_all_reps=consistent_tps_all_reps,
            consistency_jaccard_mean=consistency_jaccard_mean,
            consistency_jaccard_std=consistency_jaccard_std,
            mean_false_positives=round(statistics.fmean(fp_counts), 2) if fp_counts else 0.0,
            mean_unlabeled_open=round(statistics.fmean(unlabeled_counts), 2)
            if unlabeled_counts
            else 0.0,
            mean_poc_verified=round(statistics.fmean(poc_counts), 2) if poc_counts else 0.0,
            std_poc_verified=round(statistics.stdev(poc_counts) if len(poc_counts) > 1 else 0.0, 2),
            mean_poc_verified_tps=round(statistics.fmean(poc_tp_counts), 2)
            if poc_tp_counts
            else 0.0,
            mean_open_unverified=round(statistics.fmean(open_unverified_counts), 2)
            if open_unverified_counts
            else 0.0,
            mean_harness_limitation=round(statistics.fmean(harness_limitation_counts), 2)
            if harness_limitation_counts
            else 0.0,
            mean_disproved_by_harness=round(statistics.fmean(disproved_by_harness_counts), 2)
            if disproved_by_harness_counts
            else 0.0,
            precision_mean=round(statistics.fmean(precisions), 4) if precisions else 0.0,
            precision_std=round(statistics.stdev(precisions) if len(precisions) > 1 else 0.0, 4),
            pooled_recall_mean=round(statistics.fmean(recalls), 4) if recalls else 0.0,
            pooled_recall_std=round(statistics.stdev(recalls) if len(recalls) > 1 else 0.0, 4),
            false_disproof_rate_mean=round(statistics.fmean(false_disproofs), 4)
            if false_disproofs
            else 0.0,
            fp_elimination_rate_mean=round(statistics.fmean(fp_eliminations), 4)
            if fp_eliminations
            else 0.0,
            poc_pass_rate_mean=round(statistics.fmean(poc_pass_rates), 4)
            if poc_pass_rates
            else 0.0,
            mean_tokens_per_run=round(mean_tok, 1),
            mean_cached_tokens_per_run=round(statistics.fmean(run_cached_tokens), 1)
            if run_cached_tokens
            else 0.0,
            mean_uncached_input_tokens_per_run=round(statistics.fmean(run_uncached_tokens), 1)
            if run_uncached_tokens
            else 0.0,
            mean_thoughts_tokens_per_run=round(statistics.fmean(run_thoughts_tokens), 1)
            if run_thoughts_tokens
            else 0.0,
            mean_pure_output_tokens_per_run=round(statistics.fmean(run_pure_output_tokens), 1)
            if run_pure_output_tokens
            else 0.0,
            mean_output_tokens_per_run=round(statistics.fmean(run_output_tokens), 1)
            if run_output_tokens
            else 0.0,
            tokens_per_tp=tokens_per_tp,
            mean_wall_clock_seconds=None
            if "@" in tier_key
            else (round(statistics.fmean(run_times), 2) if run_times else 0.0),
            phase_funnel_summary=phase_funnel_summary,
            saturation_curve=saturation_curve,
            severity_distribution_mean=severity_distribution_mean,
            module_distribution_mean=module_distribution_mean,
            finding_detection_frequencies=finding_detection_frequencies,
        )

    def _compute_cross_model_consistency(
        self,
        summaries: list[TierEvaluationSummary],
        canon_by_id: dict[str, CanonicalFinding],
        occs_by_trial: dict[tuple[str, int], list[tuple[str, FindingOccurrence]]],
    ) -> CrossModelConsistencySummary | None:
        """Computes cross-model / cross-provider root-cause overlap and consensus when >=2 models exist."""
        primary = [s for s in summaries if "@" not in s.ablation_tier and s.model]
        # Prefer comparing identical base tiers across different models (e.g. full[modelA] vs full[modelB])
        full_tiers = [s for s in primary if re.sub(r"\[.*\]$", "", s.ablation_tier) == "full"]
        candidates = full_tiers if len({s.model for s in full_tiers}) >= 2 else primary
        unique_models = sorted({s.model for s in candidates if s.model})
        if len(unique_models) < 2:
            return None

        open_by_model: dict[str, set[str]] = defaultdict(set)
        tp_by_model: dict[str, set[str]] = defaultdict(set)
        for s in candidates:
            for rep in range(1, s.repetitions + 1):
                for cid, occ in occs_by_trial.get((s.ablation_tier, rep), []):
                    if occ.status.lower() != "open":
                        continue
                    open_by_model[s.model].add(cid)
                    cf = canon_by_id.get(cid)
                    if cf and cf.resolved_label == "TP":
                        tp_by_model[s.model].add(cid)

        all_open = set().union(*open_by_model.values()) if open_by_model else set()
        all_tp = set().union(*tp_by_model.values()) if tp_by_model else set()

        consensus_all_open = (
            len(set.intersection(*(open_by_model[m] for m in unique_models)))
            if unique_models
            else 0
        )
        consensus_maj_open = sum(
            1 for cid in all_open if sum(1 for m in unique_models if cid in open_by_model[m]) >= 2
        )
        consensus_all_tp = (
            len(set.intersection(*(tp_by_model[m] for m in unique_models))) if unique_models else 0
        )
        consensus_maj_tp = sum(
            1 for cid in all_tp if sum(1 for m in unique_models if cid in tp_by_model[m]) >= 2
        )

        pairwise_open: dict[str, float] = {}
        pairwise_tp: dict[str, float] = {}
        for i in range(len(unique_models)):
            for j in range(i + 1, len(unique_models)):
                m1, m2 = unique_models[i], unique_models[j]
                pair_key = f"{m1} vs {m2}"
                u_open = len(open_by_model[m1] | open_by_model[m2])
                pairwise_open[pair_key] = round(
                    len(open_by_model[m1] & open_by_model[m2]) / u_open if u_open > 0 else 1.0, 4
                )
                u_tp = len(tp_by_model[m1] | tp_by_model[m2])
                pairwise_tp[pair_key] = round(
                    len(tp_by_model[m1] & tp_by_model[m2]) / u_tp if u_tp > 0 else 0.0, 4
                )

        return CrossModelConsistencySummary(
            models=unique_models,
            total_unique_open_across_models=len(all_open),
            consensus_all_models_open=consensus_all_open,
            consensus_majority_models_open=consensus_maj_open,
            total_unique_tps_across_models=len(all_tp),
            consensus_all_models_tp=consensus_all_tp,
            consensus_majority_models_tp=consensus_maj_tp,
            pairwise_open_jaccard=pairwise_open,
            pairwise_tp_jaccard=pairwise_tp,
            mean_cross_model_open_jaccard=round(statistics.fmean(pairwise_open.values()), 4)
            if pairwise_open
            else 0.0,
            mean_cross_model_tp_jaccard=round(statistics.fmean(pairwise_tp.values()), 4)
            if pairwise_tp
            else 0.0,
        )

    def _render_markdown(
        self,
        summaries: list[TierEvaluationSummary],
        inter_rater: InterRaterStats,
        cross_model: CrossModelConsistencySummary | None = None,
    ) -> str:
        lines = [
            "# Mjolnir Real-World Evaluation Scorecard",
            "",
            "## 1. Blind Dual-Expert Review & Inter-Rater Reliability",
            "",
            f"- **Total Canonical Findings in Pool**: `{inter_rater.total_canonical_findings}`",
            f"- **Adjudicated Findings**: `{inter_rater.adjudicated_count}` "
            f"(Confirmed TPs: `{inter_rater.confirmed_tp_count}`, Confirmed FPs: `{inter_rater.confirmed_fp_count}`, Unlabeled: `{inter_rater.unlabeled_count}`)",
            f"- **Double-Reviewed Findings**: `{inter_rater.double_reviewed_count}` "
            f"| **Raw Agreement**: `{inter_rater.raw_agreement_rate:.1%}` | **Cohen's Kappa ($\\kappa$)**: `{inter_rater.cohens_kappa:.3f}`",
            "",
            "## 2. RQ1, RQ2 & RQ4: Quality, Redundancy & Token Cost Comparison",
            "",
            "| Tier | Mean Open | Unique RCAs | Redundancy | TPs | FPs | PoC Verified | Precision | Pooled Recall | False Disproof | FP Elim. | Tokens/Run | Tokens/TP | Time (s) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for s in summaries:
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "N/A"
            time_str = (
                f"{s.mean_wall_clock_seconds:.1f}s"
                if s.mean_wall_clock_seconds is not None
                else "—"
            )
            lines.append(
                f"| **{s.tier_name}** | {s.mean_open_findings:.1f} | {s.mean_unique_root_causes:.1f} "
                f"| {s.redundancy_ratio:.2f}x | {s.mean_true_positives:.1f} "
                f"| {s.mean_false_positives:.1f} | {s.mean_poc_verified:.1f} "
                f"| {s.precision_mean:.1%} | {s.pooled_recall_mean:.1%} "
                f"| {s.false_disproof_rate_mean:.1%} | {s.fp_elimination_rate_mean:.1%} "
                f"| {s.mean_tokens_per_run:,.0f} | {tok_tp_str} | {time_str} |"
            )

        primary_runs = [
            s for s in summaries if "@" not in s.ablation_tier and s.phase_funnel_summary
        ]
        if primary_runs:
            lines.extend(
                [
                    "",
                    "## 3. RQ2: Phase-Transition Verification Funnel, Redundancy Collapse & Severity Shifts",
                    "",
                    "| Run | Phase | Entering | Surviving Open | Closed | Duplicate | PoC Verified | Upgraded | Downgraded |",
                    "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
                ]
            )
            for s in primary_runs:
                for pid, counts in s.phase_funnel_summary.items():
                    lines.append(
                        f"| **{s.ablation_tier}** | `{pid}` | {counts['entering']:.1f} "
                        f"| {counts['surviving']:.1f} | {counts['closed']:.1f} "
                        f"| {counts['duplicate']:.1f} | {counts['poc_verified']:.1f} "
                        f"| {counts['upgraded']:.1f} | {counts['downgraded']:.1f} |"
                    )

        lines.extend(
            [
                "",
                "## 4. RQ3 & RQ4: Within-Model Consistency, Token Caching & Computational Overhead",
                "",
                "| Tier | Reps | Unique Open (Union) | Consistent Open (All Reps) | Unique TPs (Union) | Consistent TPs (All Reps) | Within-Model Jaccard | Uncached Input Tokens | Cached Input Tokens | Thinking Tokens | Output Tokens | Total Tokens | Tokens/TP | Wall Clock (s) |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            ]
        )
        for s in summaries:
            if "@" in s.ablation_tier:
                continue
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "N/A"
            jac_str = (
                f"{s.consistency_jaccard_mean:.1%} (\u00b1{s.consistency_jaccard_std or 0.0:.1%})"
                if s.consistency_jaccard_mean is not None
                else "N/A (1 rep)"
            )
            time_str = (
                f"{s.mean_wall_clock_seconds:.1f}s"
                if s.mean_wall_clock_seconds is not None
                else "—"
            )
            lines.append(
                f"| **{s.tier_name}** | {s.repetitions} | {s.unique_open_across_reps} "
                f"| {s.consistent_open_all_reps} | {s.unique_tps_across_reps} "
                f"| {s.consistent_tps_all_reps} | {jac_str} "
                f"| {s.mean_uncached_input_tokens_per_run:,.0f} "
                f"| {s.mean_cached_tokens_per_run:,.0f} | {s.mean_thoughts_tokens_per_run:,.0f} | {s.mean_pure_output_tokens_per_run:,.0f} "
                f"| {s.mean_tokens_per_run:,.0f} "
                f"| {tok_tp_str} | {time_str} |"
            )

        if cross_model:
            lines.extend(
                [
                    "",
                    "## 5. RQ3 Cross-Model Consistency & Multi-Provider Consensus",
                    "",
                    f"- **Evaluated Models ({len(cross_model.models)})**: `{', '.join(cross_model.models)}`",
                    f"- **Open Root-Cause Consensus**: `{cross_model.consensus_all_models_open}` all-models / "
                    f"`{cross_model.consensus_majority_models_open}` majority ($\\ge 2$ models) / "
                    f"`{cross_model.total_unique_open_across_models}` union "
                    f"(**Mean Pairwise Jaccard**: `{cross_model.mean_cross_model_open_jaccard:.1%}`)",
                    f"- **Confirmed TP Consensus**: `{cross_model.consensus_all_models_tp}` all-models / "
                    f"`{cross_model.consensus_majority_models_tp}` majority ($\\ge 2$ models) / "
                    f"`{cross_model.total_unique_tps_across_models}` union "
                    f"(**Mean Pairwise TP Jaccard**: `{cross_model.mean_cross_model_tp_jaccard:.1%}`)",
                ]
            )

        multi_rep_runs = [
            s
            for s in summaries
            if "@" not in s.ablation_tier and s.repetitions >= 2 and s.saturation_curve
        ]
        if multi_rep_runs:
            lines.extend(
                [
                    "",
                    "## 6. RQ3 Deep Within-Model Stability: Cumulative Saturation Curve (Unbiased Expected Discover@k)",
                    "",
                    "| Tier | k (Runs) | E[Unique Open(k)] | E[Unique PoC-Verified(k)] | E[Unique TP(k)] | E[Unique FP(k)] |",
                    "| :--- | :---: | :---: | :---: | :---: | :---: |",
                ]
            )
            for s in multi_rep_runs:
                for k, curve_vals in sorted(s.saturation_curve.items()):
                    lines.append(
                        f"| **{s.tier_name}** | {k} | {curve_vals['expected_open']:.2f} "
                        f"| {curve_vals['expected_poc_verified']:.2f} "
                        f"| {curve_vals['expected_tp']:.2f} | {curve_vals['expected_fp']:.2f} |"
                    )

        return "\n".join(lines) + "\n"

    def _render_latex_booktabs(
        self,
        summaries: list[TierEvaluationSummary],
        inter_rater: InterRaterStats,
        cross_model: CrossModelConsistencySummary | None = None,
    ) -> str:
        cm_note = (
            f", Cross-Model Open Jaccard={cross_model.mean_cross_model_open_jaccard:.3f}"
            if cross_model
            else ""
        )
        lines = [
            "% Auto-generated by Mjolnir ScorecardGenerator for USENIX Security",
            f"% Blind Review Pool: N={inter_rater.total_canonical_findings}, TP={inter_rater.confirmed_tp_count}, FP={inter_rater.confirmed_fp_count}, Cohen's kappa={inter_rater.cohens_kappa:.3f}{cm_note}",
            "\\begin{table*}[t]",
            "\\centering",
            "\\small",
            "\\begin{tabular}{lcccccccccc}",
            "\\toprule",
            "\\textbf{Configuration} & \\textbf{Open} & \\textbf{Unique RCAs} & \\textbf{Redundancy} & \\textbf{TP} & \\textbf{FP} & \\textbf{Precision} & \\textbf{Pooled Recall} & \\textbf{Tokens (M)} & \\textbf{Tokens/TP} & \\textbf{Time (min)} \\\\",
            "\\midrule",
        ]
        for s in summaries:
            safe_name = self._paper_tier_label(s)
            tok_m_str = f"{s.mean_tokens_per_run / 1_000_000:.2f}M"
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "---"
            time_str = (
                f"{s.mean_wall_clock_seconds / 60.0:.1f}m"
                if s.mean_wall_clock_seconds is not None
                else "\\textemdash{}"
            )
            lines.append(
                f"{safe_name} & {s.mean_open_findings:.1f} & {s.mean_unique_root_causes:.1f} & "
                f"{s.redundancy_ratio:.2f}$\\times$ & {s.mean_true_positives:.1f} & "
                f"{s.mean_false_positives:.1f} & {s.precision_mean * 100:.1f}\\% & "
                f"{s.pooled_recall_mean * 100:.1f}\\% & {tok_m_str} & "
                f"{tok_tp_str} & {time_str} \\\\"
            )
        lines.extend(
            [
                "\\bottomrule",
                "\\end{tabular}",
                "\\caption{Evaluation across pinned Root-of-Trust targets: quality (TP, precision, pooled recall), redundancy ratio, and token/time cost.}",
                "\\label{tab:mjolnir-evaluation}",
                "\\end{table*}",
            ]
        )
        return "\n".join(lines) + "\n"

    @classmethod
    def _get_model_pricing(cls, model: str = "gemini-3.8-flash") -> dict[str, float | str] | None:
        """Returns per-1M-token USD pricing schedule for a model from the pinned schedule."""
        norm_model = (model or "gemini-3.8-flash").strip().split("/")[-1].split("@")[0]
        return cls.MODEL_PRICING_SCHEDULES_USD_PER_1M.get(norm_model)

    @classmethod
    def _estimate_cost_usd(
        cls,
        uncached_in: float,
        cached_in: float,
        output_tok: float,
        model: str = "gemini-3.8-flash",
    ) -> float | None:
        """Computes list-price API dollar cost using the model's published schedule, or None if unavailable."""
        sched = cls._get_model_pricing(model)
        if sched is None:
            return None
        return (
            (uncached_in * float(sched["uncached_input"]) / 1_000_000.0)
            + (cached_in * float(sched["cached_input"]) / 1_000_000.0)
            + (output_tok * float(sched["output_and_thoughts"]) / 1_000_000.0)
        )

    @classmethod
    def _paper_tier_label(cls, s: TierEvaluationSummary) -> str:
        """Formats tier keys into concise USENIX paper configuration labels."""
        tk = s.ablation_tier
        ckpt_suffix = ""
        if "@" in tk:
            base, ckpt = tk.split("@", 1)
            ckpt_suffix = f" (\\texttt{{@{cls._latex_escape(ckpt)}}})"
        else:
            base = tk
        model_suffix = ""
        if "[" in base and base.endswith("]"):
            b_core, m_slug = base[:-1].split("[", 1)
            base = b_core
            pretty_models = {
                "gemini-3.8-flash": "Gemini 3.8 Flash",
                "gemini-4-argon": "Gemini 4 Argon",
                "claude-sonnet-5-5": "Claude Sonnet 5.5",
            }
            model_suffix = f" ({pretty_models.get(m_slug, cls._latex_escape(m_slug))})"
        mapping = {
            "full": "\\texttt{Full}",
            "no_tm": "\\texttt{w/o Threat Model}",
            "no_expert": "\\texttt{w/o Project Expert}",
            "base": "\\texttt{Base (w/o TM, w/o Expert)}",
            "per_file": "Single-Agent (Per-File)",
            "per_file_no_tm": "Single-Agent (Per-File, w/o TM)",
            "holistic": "Single-Agent (Whole-Dir)",
            "holistic_no_tm": "Single-Agent (Whole-Dir, w/o TM)",
        }
        label = mapping.get(base, cls._latex_escape(s.tier_name))
        return f"{label}{model_suffix}{ckpt_suffix}"

    @staticmethod
    def _fmt_tokens_m(tokens: float) -> str:
        """Formats token counts in millions (M) for compact USENIX tables."""
        m = tokens / 1_000_000.0
        if m >= 10.0:
            return f"{m:.1f}M"
        return f"{m:.2f}M"

    @staticmethod
    def _latex_escape(text: str) -> str:
        return (
            text.replace("&", "\\&")
            .replace("_", "\\_")
            .replace("@", "\\texttt{@}")
            .replace("%", "\\%")
        )

    def _export_modular_paper_tables(
        self,
        out_dir: Path,
        trials: list[TrialRunRecord],
        summaries: list[TierEvaluationSummary],
        inter_rater: InterRaterStats,
        cross_model: CrossModelConsistencySummary | None,
        manifest_path: Path,
        pool_path: Path,
    ) -> None:
        """Generates standalone USENIX LaTeX tables with provenance metadata headers and syncs to mjolnir-paper if present."""
        tables_dir = out_dir / "paper_tables"
        tables_dir.mkdir(parents=True, exist_ok=True)

        repo_name = trials[0].repo_name if trials else out_dir.parent.name
        project_name = trials[0].project_name if trials else repo_name
        pinned_rev = trials[0].pinned_rev if trials else "HEAD"
        target_dir = trials[0].target_dir if trials else "."
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        mjolnir_commit = self._get_mjolnir_commit()
        mjolnir_dirty = self._is_mjolnir_dirty()
        dirty_suffix = " (dirty)" if mjolnir_dirty else ""
        manifest_sha256 = (
            hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.exists() else ""
        )
        pool_sha256 = (
            hashlib.sha256(pool_path.read_bytes()).hexdigest() if pool_path.exists() else ""
        )

        meta_body_lines = [
            "=============================================================================",
            "AUTO-GENERATED BY MJOLNIR EVALUATION HARNESS — DO NOT EDIT MANUALLY",
            f"Target Repository : {project_name} ({repo_name}) @ {pinned_rev[:12]}",
            f"Target Scope      : {target_dir}",
            f"Mjolnir Commit    : {mjolnir_commit[:12]}{dirty_suffix}",
            f"Generated At (UTC): {generated_at}",
            f"Trials in Manifest: {len(trials)} (SHA-256: {manifest_sha256[:16]}...)",
            f"Blind Review Pool : N={inter_rater.total_canonical_findings} canonical RCAs (TP={inter_rater.confirmed_tp_count}, FP={inter_rater.confirmed_fp_count}, Unlabeled={inter_rater.unlabeled_count}, kappa={inter_rater.cohens_kappa:.3f})",
            "Token Pricing     : Per-model list-price schedule ($/1M tokens as of 2026-10-19)",
            "=============================================================================",
        ]
        meta_header = "\n".join(f"% {line}" for line in meta_body_lines)
        svg_meta_header = "<!--\n" + "\n".join(f"  {line}" for line in meta_body_lines) + "\n-->"

        by_key = {s.ablation_tier: s for s in summaries}

        is_adjudicated = (inter_rater.confirmed_tp_count + inter_rater.confirmed_fp_count) > 0

        for stale_f in tables_dir.glob("*.tex"):
            stale_f.unlink()

        exported_table_names: list[str] = []

        if is_adjudicated:
            # 1. Table: RQ1 Quality & Domain-Context Ablation vs. Controlled Single-Agent Baselines
            rq1_order = [
                "per_file_no_tm",
                "per_file",
                "holistic_no_tm",
                "holistic",
                "no_tm@discovery",
                "no_expert@discovery",
                "full@discovery",
                "no_tm",
                "no_expert",
                "full",
            ]
            rq1_tiers = [by_key[k] for k in rq1_order if k in by_key] or summaries
            rq1_lines = [
                meta_header,
                "\\begin{tabular}{@{}lrrrrrrrrr@{}}",
                "\\toprule",
                "\\textbf{Configuration} & \\textbf{Open} & \\textbf{Unique RCAs} & \\textbf{Redundancy} & \\textbf{PoC Ver.} & \\textbf{TP} & \\textbf{FP} & \\textbf{Precision} & \\textbf{Tokens} & \\textbf{Time (min)} \\\\",
                "\\midrule",
            ]
            for s in rq1_tiers:
                safe_name = self._paper_tier_label(s)
                tok_m = self._fmt_tokens_m(s.mean_tokens_per_run)
                time_str = (
                    f"{s.mean_wall_clock_seconds / 60.0:.1f}m"
                    if s.mean_wall_clock_seconds is not None
                    else "\\textemdash{}"
                )
                rq1_lines.append(
                    f"{safe_name} & {s.mean_open_findings:.1f} & {s.mean_unique_root_causes:.1f} & "
                    f"{s.redundancy_ratio:.2f}$\\times$ & {s.mean_poc_verified:.1f} & "
                    f"{s.mean_true_positives:.1f} & {s.mean_false_positives:.1f} & "
                    f"{s.precision_mean * 100:.1f}\\% & {tok_m} & {time_str} \\\\"
                )
            rq1_lines.extend(
                [
                    "\\bottomrule",
                    "\\end{tabular}",
                    "",
                ]
            )
            (tables_dir / "tab_rq1_ablation_baseline.tex").write_text(
                "\n".join(rq1_lines), encoding="utf-8"
            )
            exported_table_names.append("tab_rq1_ablation_baseline.tex")

            # 2. Table: RQ2 5-Stage Verification Funnel
            funnel_order = [
                f"{base}@{stage}"
                for base in ("no_tm", "no_expert", "full")
                for stage in (
                    "discovery",
                    "deduplication",
                    "initial_review",
                    "poc_creation",
                    "final_review",
                )
            ]
            rq2_tiers = [by_key[k] for k in funnel_order if k in by_key]
            rq2_lines = [
                meta_header,
                "\\begin{tabular}{@{}lrrrrrrrr@{}}",
                "\\toprule",
                "\\textbf{Pipeline Stage Checkpoint} & \\textbf{Open} & \\textbf{Unique RCAs} & \\textbf{Redundancy} & \\textbf{PoC Ver.} & \\textbf{TP} & \\textbf{FP} & \\textbf{FP Elim.} & \\textbf{False Disproof} \\\\",
                "\\midrule",
            ]
            for s in rq2_tiers:
                safe_name = self._paper_tier_label(s)
                rq2_lines.append(
                    f"{safe_name} & {s.mean_open_findings:.1f} & {s.mean_unique_root_causes:.1f} & "
                    f"{s.redundancy_ratio:.2f}$\\times$ & {s.mean_poc_verified:.1f} & "
                    f"{s.mean_true_positives:.1f} & {s.mean_false_positives:.1f} & "
                    f"{s.fp_elimination_rate_mean * 100:.1f}\\% & {s.false_disproof_rate_mean * 100:.1f}\\% \\\\"
                )
            rq2_lines.extend(
                [
                    "\\bottomrule",
                    "\\end{tabular}",
                    "",
                ]
            )
            (tables_dir / "tab_rq2_verification_funnel.tex").write_text(
                "\n".join(rq2_lines), encoding="utf-8"
            )
            exported_table_names.append("tab_rq2_verification_funnel.tex")

        # 3. Table: RQ3 Within-Model Consistency (requires >= 2 repetitions)
        rq3_tiers = [s for s in summaries if "@" not in s.ablation_tier]
        multi_rep_rq3 = [s for s in rq3_tiers if s.repetitions >= 2]
        if multi_rep_rq3:
            rq3_lines = [
                meta_header,
                "\\begin{tabular}{@{}lccccc@{}}",
                "\\toprule",
                "\\textbf{Configuration} & \\textbf{Reps} & \\textbf{Mean Open ($\\pm$ SD)} & \\textbf{Union RCAs} & \\textbf{All-Rep RCAs} & \\textbf{Pairwise Jaccard} \\\\",
                "\\midrule",
            ]
            for s in multi_rep_rq3:
                safe_name = self._paper_tier_label(s)
                jac_mean = (s.consistency_jaccard_mean or 0.0) * 100.0
                jac_std = (s.consistency_jaccard_std or 0.0) * 100.0
                rq3_lines.append(
                    f"{safe_name} & {s.repetitions} & {s.mean_open_findings:.1f} ($\\pm${s.std_open_findings:.1f}) & "
                    f"{s.unique_open_across_reps} & {s.consistent_open_all_reps} & "
                    f"{jac_mean:.1f}\\% ($\\pm${jac_std:.1f}\\%) \\\\"
                )
            rq3_lines.extend(
                [
                    "\\bottomrule",
                    "\\end{tabular}",
                    "",
                ]
            )
            (tables_dir / "tab_rq3_consistency_stability.tex").write_text(
                "\n".join(rq3_lines), encoding="utf-8"
            )
            exported_table_names.append("tab_rq3_consistency_stability.tex")

        # 4. Table: RQ4 Token, Caching, Thinking vs Output, Latency & API Dollar Cost Breakdown
        rq4_lines = [
            meta_header,
            "\\begin{tabular}{@{}lrrrrrrr@{}}",
            "\\toprule",
            "\\textbf{Configuration} & \\textbf{Uncached In} & \\textbf{Cached In} & \\textbf{Cache \\%} & \\textbf{Thinking} & \\textbf{Output} & \\textbf{API Cost (\\$)} & \\textbf{Time (min)} \\\\",
            "\\midrule",
        ]
        for s in rq3_tiers:
            safe_name = self._paper_tier_label(s)
            tot_in = s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run
            cache_pct = (s.mean_cached_tokens_per_run / tot_in * 100.0) if tot_in > 0 else 0.0
            cost_usd = self._estimate_cost_usd(
                s.mean_uncached_input_tokens_per_run,
                s.mean_cached_tokens_per_run,
                s.mean_output_tokens_per_run,
                model=s.model,
            )
            cost_str = f"\\${cost_usd:.2f}" if cost_usd is not None else "\\textemdash{}"
            time_str = (
                f"{s.mean_wall_clock_seconds / 60.0:.1f}m"
                if s.mean_wall_clock_seconds is not None
                else "\\textemdash{}"
            )
            rq4_lines.append(
                f"{safe_name} & {self._fmt_tokens_m(s.mean_uncached_input_tokens_per_run)} & "
                f"{self._fmt_tokens_m(s.mean_cached_tokens_per_run)} & {cache_pct:.1f}\\% & "
                f"{self._fmt_tokens_m(s.mean_thoughts_tokens_per_run)} & "
                f"{self._fmt_tokens_m(s.mean_pure_output_tokens_per_run)} & "
                f"{cost_str} & {time_str} \\\\"
            )
        rq4_lines.extend(
            [
                "\\bottomrule",
                "\\end{tabular}",
                "",
            ]
        )
        (tables_dir / "tab_rq4_token_cost_breakdown.tex").write_text(
            "\n".join(rq4_lines), encoding="utf-8"
        )
        exported_table_names.append("tab_rq4_token_cost_breakdown.tex")

        # 4b. Table: RQ3 Deep Stability Cumulative Saturation Curve (for stability study with >= 5 repetitions)
        deep_tiers = sorted(
            [s for s in rq3_tiers if s.repetitions >= 5 and s.saturation_curve],
            key=lambda x: (0 if x.ablation_tier == "full" else 1, -x.repetitions),
        )
        if deep_tiers:
            sat_tier = deep_tiers[0]
            sat_lines = [
                meta_header,
                "\\begin{tabular}{@{}cccc@{}}",
                "\\toprule",
                "\\textbf{$k$ (Runs)} & \\textbf{$E[\\text{Unique Open}(k)]$} & \\textbf{$E[\\text{Unique PoC-Ver.}(k)]$} & \\textbf{Marginal $\\Delta E(k)$} \\\\",
                "\\midrule",
            ]
            prev_open = 0.0
            for k, curve_vals in sorted(sat_tier.saturation_curve.items()):
                e_open = curve_vals["expected_open"]
                e_poc = curve_vals["expected_poc_verified"]
                delta = e_open - prev_open
                prev_open = e_open
                sat_lines.append(f"{k} & {e_open:.2f} & {e_poc:.2f} & +{delta:.2f} \\\\")
            sat_lines.extend(
                [
                    "\\bottomrule",
                    "\\end{tabular}",
                    "",
                ]
            )
            (tables_dir / "tab_rq3_saturation_curve.tex").write_text(
                "\n".join(sat_lines), encoding="utf-8"
            )
            exported_table_names.append("tab_rq3_saturation_curve.tex")

        used_models = {
            (s.model or "gemini-3.8-flash").strip().split("/")[-1].split("@")[0] for s in summaries
        }
        pricing_used = {
            m: sched
            for m, sched in self.MODEL_PRICING_SCHEDULES_USD_PER_1M.items()
            if m in used_models
        }
        phase_token_breakdown = self._collect_phase_token_stats(eval_dir=out_dir, by_key=by_key)

        # 5. JSON Metadata Companion
        metadata_payload = {
            "generated_at_utc": generated_at,
            "mjolnir_commit": mjolnir_commit,
            "mjolnir_dirty": mjolnir_dirty,
            "trial_mjolnir_commits": sorted({t.mjolnir_commit for t in trials if t.mjolnir_commit}),
            "trial_mjolnir_dirty": any(t.mjolnir_dirty for t in trials),
            "project_name": project_name,
            "repo_name": repo_name,
            "pinned_rev": pinned_rev,
            "target_dir": target_dir,
            "total_trial_records": len(trials),
            "manifest_sha256": manifest_sha256,
            "blind_review_pool_sha256": pool_sha256,
            "blind_review_pool_stats": inter_rater.model_dump(),
            "cross_model_consistency": cross_model.model_dump() if cross_model else None,
            "pricing_schedules_usd_per_1m_tokens": pricing_used,
            "exported_tables": exported_table_names,
            "phase_token_breakdown": phase_token_breakdown,
            "tiers_summary": [
                {
                    "ablation_tier": s.ablation_tier,
                    "tier_name": s.tier_name,
                    "model": s.model or "gemini-3.8-flash",
                    "repetitions": s.repetitions,
                    "mean_open_findings": s.mean_open_findings,
                    "std_open_findings": s.std_open_findings,
                    "mean_unique_root_causes": s.mean_unique_root_causes,
                    "redundancy_ratio": s.redundancy_ratio,
                    "unique_open_across_reps": s.unique_open_across_reps,
                    "consistent_open_all_reps": s.consistent_open_all_reps,
                    "saturation_curve": {str(k): v for k, v in sorted(s.saturation_curve.items())},
                    "mean_poc_verified": s.mean_poc_verified,
                    "mean_open_unverified": s.mean_open_unverified,
                    "mean_harness_limitation": s.mean_harness_limitation,
                    "mean_disproved_by_harness": s.mean_disproved_by_harness,
                    "mean_true_positives": s.mean_true_positives,
                    "mean_false_positives": s.mean_false_positives,
                    "precision_mean": s.precision_mean,
                    "precision_std": s.precision_std,
                    "pooled_recall_mean": s.pooled_recall_mean,
                    "pooled_recall_std": s.pooled_recall_std,
                    "consistency_jaccard_mean": s.consistency_jaccard_mean,
                    "consistency_jaccard_std": s.consistency_jaccard_std,
                    "phase_funnel_summary": s.phase_funnel_summary,
                    "mean_uncached_input_tokens": s.mean_uncached_input_tokens_per_run,
                    "mean_cached_tokens": s.mean_cached_tokens_per_run,
                    "mean_thoughts_tokens": s.mean_thoughts_tokens_per_run,
                    "mean_pure_output_tokens": s.mean_pure_output_tokens_per_run,
                    "mean_output_tokens": s.mean_output_tokens_per_run,
                    "out_to_in_ratio": round(
                        s.mean_output_tokens_per_run
                        / (s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run),
                        3,
                    )
                    if (s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run) > 0
                    else 0.0,
                    "mean_total_tokens": s.mean_tokens_per_run,
                    "mean_estimated_cost_usd": (
                        round(c_val, 4)
                        if (
                            c_val := self._estimate_cost_usd(
                                s.mean_uncached_input_tokens_per_run,
                                s.mean_cached_tokens_per_run,
                                s.mean_output_tokens_per_run,
                                model=s.model,
                            )
                        )
                        is not None
                        else None
                    ),
                    "mean_wall_clock_seconds": s.mean_wall_clock_seconds,
                }
                for s in summaries
            ],
        }
        (tables_dir / "tables_metadata.json").write_text(
            json.dumps(metadata_payload, indent=2), encoding="utf-8"
        )

        # Also mirror into out_dir / "tables" for clean tables/ + plots/ layout
        clean_tables_dir = out_dir / "tables"
        clean_tables_dir.mkdir(parents=True, exist_ok=True)
        for stale_f in clean_tables_dir.iterdir():
            if stale_f.is_file():
                stale_f.unlink()
        for f in tables_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, clean_tables_dir / f.name)

        # 6. Export standalone PGFPlots (.tex) and SVG (.svg) figures into out_dir / "plots"
        plots_dir = out_dir / "plots"
        plots_dir.mkdir(parents=True, exist_ok=True)
        for stale_f in plots_dir.iterdir():
            if stale_f.is_file():
                stale_f.unlink()
        self._export_modular_paper_plots(
            plots_dir=plots_dir,
            meta_header=meta_header,
            svg_meta_header=svg_meta_header,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            by_key=by_key,
            rq3_tiers=rq3_tiers,
            is_adjudicated=is_adjudicated,
        )

        # Auto-sync into sibling mjolnir-paper/27-usenix/{tables,plots}/<repo_name>/ if present
        # (Skip auto-sync when running inside temporary unit-test directories under /tmp)
        if not str(out_dir.resolve()).startswith("/tmp/"):
            is_stability_only = out_dir.name == "stability"
            repo_root = Path(__file__).resolve().parent.parent.parent
            candidate_roots = [
                *([Path(env_p)] if (env_p := os.environ.get("MJOLNIR_PAPER_DIR")) else []),
                repo_root.parent / "mjolnir-paper" / "27-usenix",
                Path.cwd().parent / "mjolnir-paper" / "27-usenix",
            ]
            for candidate_paper_root in candidate_roots:
                if candidate_paper_root.is_dir():
                    dest_paper_tables = candidate_paper_root / "tables" / repo_name
                    dest_paper_tables.mkdir(parents=True, exist_ok=True)
                    dest_paper_plots = candidate_paper_root / "plots" / repo_name
                    dest_paper_plots.mkdir(parents=True, exist_ok=True)
                    if is_stability_only:
                        sat_tab = tables_dir / "tab_rq3_saturation_curve.tex"
                        if sat_tab.is_file():
                            shutil.copy2(sat_tab, dest_paper_tables / sat_tab.name)
                        sat_meta = tables_dir / "tables_metadata.json"
                        if sat_meta.is_file():
                            shutil.copy2(sat_meta, dest_paper_tables / "stability_metadata.json")
                        for sat_plot_name in (
                            "fig_rq3_saturation_curve.tex",
                            "fig_rq3_saturation_curve.svg",
                        ):
                            sat_plot = plots_dir / sat_plot_name
                            if sat_plot.is_file():
                                shutil.copy2(sat_plot, dest_paper_plots / sat_plot.name)
                    else:
                        has_stability = (dest_paper_tables / "stability_metadata.json").is_file()
                        keep_tables = {"stability_metadata.json"}
                        keep_plots: set[str] = set()
                        if has_stability:
                            keep_tables.add("tab_rq3_saturation_curve.tex")
                            keep_plots.update(
                                {"fig_rq3_saturation_curve.tex", "fig_rq3_saturation_curve.svg"}
                            )
                        for stale_f in dest_paper_tables.iterdir():
                            if stale_f.is_file() and stale_f.name not in keep_tables:
                                stale_f.unlink()
                        for f in tables_dir.iterdir():
                            if f.is_file() and f.name not in keep_tables:
                                shutil.copy2(f, dest_paper_tables / f.name)
                        for stale_f in dest_paper_plots.iterdir():
                            if stale_f.is_file() and stale_f.name not in keep_plots:
                                stale_f.unlink()
                        for f in plots_dir.iterdir():
                            if f.is_file() and f.name not in keep_plots:
                                shutil.copy2(f, dest_paper_plots / f.name)
                    gen_eval_script = candidate_paper_root / "scripts" / "gen_eval_stats.py"
                    if gen_eval_script.is_file():
                        import sys as _sys

                        res = subprocess.run(
                            [_sys.executable, str(gen_eval_script)],
                            cwd=str(candidate_paper_root),
                            check=False,
                            capture_output=True,
                            text=True,
                            timeout=30,
                        )
                        if res.returncode != 0:
                            raise RuntimeError(
                                f"gen_eval_stats.py failed (exit {res.returncode}):\n{res.stderr or res.stdout}"
                            )
                    logger.info(
                        f"Synced generated paper tables and plots to {dest_paper_tables} and {dest_paper_plots}"
                    )
                    break

    def _export_modular_paper_plots(
        self,
        plots_dir: Path,
        meta_header: str,
        svg_meta_header: str,
        repo_name: str,
        pinned_rev: str,
        by_key: dict[str, TierEvaluationSummary],
        rq3_tiers: list[TierEvaluationSummary],
        is_adjudicated: bool = False,
    ) -> None:
        """Generates PGFPlots (.tex) and standalone vector (.svg) figures for paper-ready RQs."""
        # Plot 1: RQ2 5-Stage Verification Funnel (PGFPlots + SVG)
        stages = [
            ("discovery", "Discovery"),
            ("deduplication", "Dedup"),
            ("initial_review", "Init Review"),
            ("poc_creation", "PoC Creation"),
            ("final_review", "Final Review"),
        ]
        funnel_tex = [
            meta_header,
            "\\resizebox{\\columnwidth}{!}{%",
            "\\begin{tikzpicture}",
            "\\begin{axis}[",
            "    width=\\columnwidth,",
            "    height=5.2cm,",
            "    ylabel={Mean Open Findings},",
            "    symbolic x coords={Discovery,Dedup,Init Review,PoC Creation,Final Review},",
            "    xtick=data,",
            "    xticklabel style={rotate=20, anchor=east, font=\\footnotesize},",
            "    ymin=0,",
            "    ymajorgrids=true,",
            "    grid style=dashed,",
            "    legend pos=north east,",
            "    legend style={font=\\scriptsize},",
            "    mark size=2pt,",
            "    thick",
            "]",
        ]
        funnel_series = [
            ("no_tm", "\\texttt{w/o Threat Model}", "color=orange, mark=triangle*"),
            ("no_expert", "\\texttt{w/o Project Expert}", "color=teal, mark=square*"),
            ("full", "\\texttt{Full}", "color=blue, mark=*"),
        ]
        pretty_models = {
            "gemini-3.8-flash": "Gemini 3.8 Flash",
            "gemini-4-argon": "Gemini 4 Argon",
            "claude-sonnet-5-5": "Claude Sonnet 5.5",
        }
        alt_funnel_styles = [
            "color=violet, mark=diamond*, dashed",
            "color=magenta!80!black, mark=pentagon*, densely dotted",
            "color=brown!80!black, mark=star, dashdotted",
        ]
        alt_idx = 0
        for k in sorted(by_key.keys()):
            if k.startswith("full[") and "@" not in k:
                m_slug = k[len("full[") : -1]
                p_mod = pretty_models.get(m_slug, self._latex_escape(m_slug))
                style = alt_funnel_styles[alt_idx % len(alt_funnel_styles)]
                alt_idx += 1
                funnel_series.append((k, f"\\texttt{{Full}} ({p_mod})", style))
        for tier_prefix, label, style in funnel_series:
            coords = []
            for st_key, st_label in stages:
                rec = by_key.get(f"{tier_prefix}@{st_key}")
                if rec is not None:
                    coords.append(f"({st_label},{rec.mean_open_findings:.1f})")
            if coords:
                funnel_tex.append(f"\\addplot[{style}] coordinates {{ {' '.join(coords)} }};")
                funnel_tex.append(f"\\addlegendentry{{{label}}}")
        funnel_tex.extend(
            [
                "\\end{axis}",
                "\\end{tikzpicture}%",
                "}",
                "",
            ]
        )
        (plots_dir / "fig_rq2_verification_funnel.tex").write_text(
            "\n".join(funnel_tex), encoding="utf-8"
        )

        def _pgf_coord(tier_key: str) -> str:
            return tier_key.replace("_", "-").replace("[", "(").replace("]", ")")

        sym_coords = ",".join(_pgf_coord(s.ablation_tier) for s in rq3_tiers)

        # Plot 2 (Only when adjudicated): RQ1 Open vs. PoC-Verified vs. True Positives
        if is_adjudicated:
            open_coords = " ".join(
                f"({_pgf_coord(s.ablation_tier)},{s.mean_open_findings:.1f})" for s in rq3_tiers
            )
            poc_coords = " ".join(
                f"({_pgf_coord(s.ablation_tier)},{s.mean_poc_verified:.1f})" for s in rq3_tiers
            )
            tp_coords = " ".join(
                f"({_pgf_coord(s.ablation_tier)},{s.mean_true_positives:.1f})" for s in rq3_tiers
            )
            rq1_tex = [
                meta_header,
                "\\begin{tikzpicture}",
                "\\begin{axis}[",
                "    ybar,",
                "    bar width=5.5pt,",
                "    width=\\columnwidth,",
                "    height=5.4cm,",
                "    ylabel={Mean Findings / Run},",
                "    xtick=data,",
                f"    symbolic x coords={{{sym_coords}}},",
                "    xticklabel style={rotate=25, anchor=east, font=\\footnotesize},",
                "    ymin=0,",
                "    ymajorgrids=true,",
                "    grid style=dashed,",
                "    legend pos=north east,",
                "    legend style={font=\\scriptsize},",
                "    nodes near coords,",
                "    nodes near coords style={font=\\tiny}",
                "]",
                f"\\addplot[fill=blue!60!white, draw=black] coordinates {{ {open_coords} }};",
                "\\addlegendentry{Open Findings}",
                f"\\addplot[fill=green!55!black, draw=black] coordinates {{ {poc_coords} }};",
                "\\addlegendentry{PoC-Verified}",
                f"\\addplot[fill=orange!80!black, draw=black] coordinates {{ {tp_coords} }};",
                "\\addlegendentry{True Positives (TP)}",
                "\\end{axis}",
                "\\end{tikzpicture}",
                "",
            ]
            (plots_dir / "fig_rq1_ablation_comparison.tex").write_text(
                "\n".join(rq1_tex), encoding="utf-8"
            )
            self._render_rq1_comparison_svg(
                plots_dir / "fig_rq1_ablation_comparison.svg",
                rq3_tiers,
                repo_name=repo_name,
                svg_meta_header=svg_meta_header,
            )

        # Plot 3: RQ4 Token Cost Share Composition (100% Stacked PGFPlots .tex)
        priced_tiers = [s for s in rq3_tiers if self._get_model_pricing(s.model) is not None]
        if priced_tiers:
            priced_sym_coords = ",".join(_pgf_coord(s.ablation_tier) for s in priced_tiers)
            unc_coords, cac_coords, out_coords = [], [], []
            for s in priced_tiers:
                sched = self._get_model_pricing(s.model)
                assert sched is not None
                r_unc = float(sched["uncached_input"])
                r_cac = float(sched["cached_input"])
                r_out = float(sched["output_and_thoughts"])
                c_unc = s.mean_uncached_input_tokens_per_run * r_unc / 1_000_000.0
                c_cac = s.mean_cached_tokens_per_run * r_cac / 1_000_000.0
                c_out = s.mean_output_tokens_per_run * r_out / 1_000_000.0
                c_tot = max(1e-9, c_unc + c_cac + c_out)
                k = _pgf_coord(s.ablation_tier)
                unc_coords.append(f"({k},{c_unc / c_tot * 100.0:.1f})")
                cac_coords.append(f"({k},{c_cac / c_tot * 100.0:.1f})")
                out_coords.append(f"({k},{c_out / c_tot * 100.0:.1f})")

            rq4_tex = [
                meta_header,
                "\\begin{tikzpicture}",
                "\\begin{axis}[",
                "    ybar stacked,",
                "    bar width=11pt,",
                "    width=\\columnwidth,",
                "    height=5.2cm,",
                "    ylabel={Share of API Cost (\\%)},",
                "    xtick=data,",
                f"    symbolic x coords={{{priced_sym_coords}}},",
                "    xticklabel style={rotate=25, anchor=east, font=\\footnotesize},",
                "    ymin=0, ymax=100,",
                "    ymajorgrids=true,",
                "    grid style=dashed,",
                "    legend style={at={(0.5,1.05)}, anchor=south, legend columns=3, font=\\scriptsize}",
                "]",
                f"\\addplot[fill=blue!55!white, draw=black] coordinates {{ {' '.join(unc_coords)} }};",
                "\\addlegendentry{Uncached In}",
                f"\\addplot[fill=green!60!black, draw=black] coordinates {{ {' '.join(cac_coords)} }};",
                "\\addlegendentry{Cached In}",
                f"\\addplot[fill=red!70!black, draw=black] coordinates {{ {' '.join(out_coords)} }};",
                "\\addlegendentry{Thinking + Out}",
                "\\end{axis}",
                "\\end{tikzpicture}",
                "",
            ]
            (plots_dir / "fig_rq4_token_pathology.tex").write_text(
                "\n".join(rq4_tex), encoding="utf-8"
            )

        # Standalone SVG renders for instant preview
        self._render_funnel_svg(
            plots_dir / "fig_rq2_verification_funnel.svg",
            by_key,
            stages,
            repo_name=repo_name,
            svg_meta_header=svg_meta_header,
        )
        if priced_tiers:
            self._render_token_pathology_svg(
                plots_dir / "fig_rq4_token_pathology.svg",
                priced_tiers,
                repo_name=repo_name,
                svg_meta_header=svg_meta_header,
            )
        self._export_phase_token_breakdown_plot(
            plots_dir=plots_dir,
            eval_dir=plots_dir.parent,
            meta_header=meta_header,
            svg_meta_header=svg_meta_header,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            by_key=by_key,
        )

        deep_tiers = sorted(
            [s for s in rq3_tiers if s.repetitions >= 5 and s.saturation_curve],
            key=lambda x: (0 if x.ablation_tier == "full" else 1, -x.repetitions),
        )
        if deep_tiers:
            sat_tier = deep_tiers[0]
            open_sat = " ".join(
                f"({k},{vals['expected_open']:.2f})"
                for k, vals in sorted(sat_tier.saturation_curve.items())
            )
            poc_sat = " ".join(
                f"({k},{vals['expected_poc_verified']:.2f})"
                for k, vals in sorted(sat_tier.saturation_curve.items())
            )
            sat_tex = [
                meta_header,
                "\\begin{tikzpicture}",
                "\\begin{axis}[",
                "    width=\\columnwidth,",
                "    height=5.2cm,",
                "    xlabel={Cumulative Repetitions ($k$)},",
                "    ylabel={Expected Unique RCAs $E[\\text{Discover}(k)]$},",
                "    xtick=data,",
                "    ymin=0,",
                "    ymajorgrids=true,",
                "    grid style=dashed,",
                "    legend pos=south east,",
                "    legend style={font=\\scriptsize},",
                "    mark size=2pt,",
                "    thick",
                "]",
                f"\\addplot[color=blue, mark=*] coordinates {{ {open_sat} }};",
                "\\addlegendentry{$E[\\text{Unique Open}(k)]$}",
                f"\\addplot[color=green!55!black, mark=square*] coordinates {{ {poc_sat} }};",
                "\\addlegendentry{$E[\\text{Unique PoC-Verified}(k)]$}",
                "\\end{axis}",
                "\\end{tikzpicture}",
                "",
            ]
            (plots_dir / "fig_rq3_saturation_curve.tex").write_text(
                "\n".join(sat_tex), encoding="utf-8"
            )
            self._render_saturation_svg(
                plots_dir / "fig_rq3_saturation_curve.svg",
                sat_tier,
                repo_name=repo_name,
                svg_meta_header=svg_meta_header,
            )

    @staticmethod
    def _render_saturation_svg(
        svg_path: Path,
        sat_tier: TierEvaluationSummary,
        repo_name: str = "caliptra-sw",
        svg_meta_header: str = "",
    ) -> None:
        width, height = 680, 360
        pad_l, pad_r, pad_t, pad_b = 70, 45, 50, 60
        plot_w = width - pad_l - pad_r
        plot_h = height - pad_t - pad_b
        ks = sorted(sat_tier.saturation_curve.keys())
        peak = max((sat_tier.saturation_curve[k]["expected_open"] for k in ks), default=20.0)
        step = 5
        max_y = float(((int(peak) // step) + 1) * step)
        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">Cumulative Discovery Saturation Curve (N={sat_tier.repetitions}, {repo_name})</text>',
            f'<text x="18" y="{pad_t + plot_h / 2}" text-anchor="middle" font-size="12" fill="#333" transform="rotate(-90, 18, {pad_t + plot_h / 2})">Expected Unique RCAs E[Discover(k)]</text>',
        ]
        for y_val in range(0, int(max_y) + 1, step):
            y_px = pad_t + plot_h - (y_val / max_y) * plot_h
            svg.append(
                f'<line x1="{pad_l}" y1="{y_px:.1f}" x2="{width - pad_r}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{pad_l - 8}" y="{y_px + 4:.1f}" text-anchor="end" font-size="11" fill="#555">{y_val}</text>'
            )
        for idx, k in enumerate(ks):
            x_px = pad_l + (idx / max(1, len(ks) - 1)) * plot_w
            svg.append(
                f'<text x="{x_px:.1f}" y="{height - pad_b + 22}" text-anchor="middle" font-size="11" font-weight="bold" fill="#222">k={k}</text>'
            )
        for s_idx, (key_name, label, color, y_off) in enumerate(
            (
                ("expected_open", "E[Unique Open(k)]", "#2b5c8f", -10),
                ("expected_poc_verified", "E[Unique PoC-Verified(k)]", "#2b8a3e", 15),
            )
        ):
            pts = []
            for idx, k in enumerate(ks):
                val = sat_tier.saturation_curve[k][key_name]
                x_px = pad_l + (idx / max(1, len(ks) - 1)) * plot_w
                y_px = pad_t + plot_h - (min(val, max_y) / max_y) * plot_h
                pts.append((x_px, y_px, val))
            poly = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)
            svg.append(
                f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{poly}"/>'
            )
            for x, y, val in pts:
                svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}"/>')
                svg.append(
                    f'<text x="{x:.1f}" y="{y + y_off:.1f}" text-anchor="middle" font-size="10" font-weight="bold" fill="{color}">{val:.2f}</text>'
                )
            leg_x = width - pad_r - 190
            leg_y = pad_t + plot_h - 38 + s_idx * 20
            svg.append(
                f'<line x1="{leg_x}" y1="{leg_y}" x2="{leg_x + 20}" y2="{leg_y}" stroke="{color}" stroke-width="2.5"/>'
            )
            svg.append(f'<circle cx="{leg_x + 10}" cy="{leg_y}" r="3.5" fill="{color}"/>')
            svg.append(
                f'<text x="{leg_x + 26}" y="{leg_y + 4}" font-size="11" fill="#222">{label}</text>'
            )
        svg.append("</svg>\n")
        svg_path.write_text("\n".join(svg), encoding="utf-8")

    @staticmethod
    def _render_funnel_svg(
        svg_path: Path,
        by_key: dict[str, TierEvaluationSummary],
        stages: list[tuple[str, str]],
        repo_name: str = "caliptra-sw",
        svg_meta_header: str = "",
    ) -> None:
        width, height = 720, 380
        pad_l, pad_r, pad_t, pad_b = 70, 45, 50, 65
        plot_w = width - pad_l - pad_r
        plot_h = height - pad_t - pad_b
        series_defs = [
            ("no_tm", "Mjolnir (No TM)", "#d95f02", 14),
            ("no_expert", "Mjolnir (No Expert)", "#1b9e77", -10),
            ("full", "Mjolnir (Full)", "#2b5c8f", -10),
        ]
        alt_svg_colors = [("#7570b3", 14), ("#e7298a", -12), ("#a6761d", 14)]
        alt_svg_idx = 0
        for k in sorted(by_key.keys()):
            if k.startswith("full[") and "@" not in k:
                m_slug = k[len("full[") : -1]
                c_hex, y_off = alt_svg_colors[alt_svg_idx % len(alt_svg_colors)]
                alt_svg_idx += 1
                series_defs.append((k, f"Mjolnir ({m_slug})", c_hex, y_off))
        all_vals = [
            by_key[f"{prefix}@{st_key}"].mean_open_findings
            for prefix, _, _, _ in series_defs
            for st_key, _ in stages
            if f"{prefix}@{st_key}" in by_key
        ]
        peak = max(all_vals) if all_vals else 35.0
        step = 5 if peak <= 45 else (10 if peak <= 100 else 25)
        max_y = float(((int(peak) // step) + 1) * step)
        y_ticks = list(range(0, int(max_y) + 1, step))

        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">5-Stage Verification Funnel &amp; Adversarial Filtering ({repo_name})</text>',
            f'<text x="18" y="{pad_t + plot_h / 2}" text-anchor="middle" font-size="12" fill="#333" transform="rotate(-90, 18, {pad_t + plot_h / 2})">Mean Surviving Open Findings</text>',
        ]
        for y_val in y_ticks:
            y_px = pad_t + plot_h - (y_val / max_y) * plot_h
            svg.append(
                f'<line x1="{pad_l}" y1="{y_px:.1f}" x2="{width - pad_r}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{pad_l - 10}" y="{y_px + 4:.1f}" text-anchor="end" font-size="11" fill="#555">{y_val}</text>'
            )
        for idx, (_, st_label) in enumerate(stages):
            x_px = pad_l + (idx / max(1, len(stages) - 1)) * plot_w
            svg.append(
                f'<line x1="{x_px:.1f}" y1="{pad_t}" x2="{x_px:.1f}" y2="{pad_t + plot_h}" stroke="#f2f2f2"/>'
            )
            svg.append(
                f'<text x="{x_px:.1f}" y="{height - pad_b + 24}" text-anchor="middle" font-size="11" font-weight="bold" fill="#222">{st_label}</text>'
            )
        plotted_idx = 0
        for s_idx, (prefix, label, color, y_off) in enumerate(series_defs):
            pts = []
            for idx, (st_key, _) in enumerate(stages):
                rec = by_key.get(f"{prefix}@{st_key}")
                if rec is not None:
                    x_px = pad_l + (idx / max(1, len(stages) - 1)) * plot_w
                    y_px = pad_t + plot_h - (min(rec.mean_open_findings, max_y) / max_y) * plot_h
                    pts.append((x_px, y_px, rec.mean_open_findings))
            if pts:
                poly = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)
                svg.append(
                    f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{poly}"/>'
                )
                for x, y, val in pts:
                    svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}"/>')
                    svg.append(
                        f'<text x="{x + (s_idx - 1) * 14:.1f}" y="{y + y_off:.1f}" text-anchor="middle" font-size="10" fill="{color}" font-weight="bold">{val:.1f}</text>'
                    )
                leg_x = width - pad_r - 160
                leg_y = pad_t + 16 + plotted_idx * 20
                svg.append(
                    f'<line x1="{leg_x}" y1="{leg_y}" x2="{leg_x + 20}" y2="{leg_y}" stroke="{color}" stroke-width="2.5"/>'
                )
                svg.append(f'<circle cx="{leg_x + 10}" cy="{leg_y}" r="3.5" fill="{color}"/>')
                svg.append(
                    f'<text x="{leg_x + 26}" y="{leg_y + 4}" font-size="11" fill="#222">{label}</text>'
                )
                plotted_idx += 1
        svg.append("</svg>\n")
        svg_path.write_text("\n".join(svg), encoding="utf-8")

    def _render_token_pathology_svg(
        self,
        svg_path: Path,
        rq3_tiers: list[TierEvaluationSummary],
        repo_name: str = "caliptra-sw",
        svg_meta_header: str = "",
    ) -> None:
        """Renders a 2-panel SVG: (Left) 100% Stacked Dollar Cost Share (Uncached In vs Cached In vs Thinking+Out), (Right) Thinking+Output Tokens per Run."""
        priced_tiers = [s for s in rq3_tiers if self._get_model_pricing(s.model) is not None]
        if not priced_tiers:
            return
        width, height = 780, 390
        pad_t, pad_b = 58, 85
        plot_h = height - pad_t - pad_b
        left_x0, left_w = 65, 305
        right_x0, right_w = 445, 305

        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="24" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">Token Cost Composition &amp; Speculative Thinking Overhead ({repo_name})</text>',
            f'<text x="{left_x0 + left_w / 2}" y="44" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(a) Share of API Cost by Token Type (%)</text>',
            f'<text x="{right_x0 + right_w / 2}" y="44" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(b) Thinking + Output Tokens / Run (Millions)</text>',
        ]

        # Left Panel Y-axis (0% to 100%)
        for pct in (0, 25, 50, 75, 100):
            y_px = pad_t + plot_h - (pct / 100.0) * plot_h
            svg.append(
                f'<line x1="{left_x0}" y1="{y_px:.1f}" x2="{left_x0 + left_w}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{left_x0 - 8}" y="{y_px + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{pct}%</text>'
            )

        # Right Panel Y-axis (auto-scaled in Millions of output+thinking tokens)
        max_out_m = max(
            (s.mean_output_tokens_per_run / 1_000_000.0 for s in priced_tiers), default=1.0
        )
        max_y_m = float(int(max_out_m) + 1) if max_out_m >= 1.0 else 1.5
        for idx_tick in range(5):
            val_m = (idx_tick / 4.0) * max_y_m
            y_px = pad_t + plot_h - (val_m / max_y_m) * plot_h
            svg.append(
                f'<line x1="{right_x0}" y1="{y_px:.1f}" x2="{right_x0 + right_w}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{right_x0 - 8}" y="{y_px + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{val_m:.2f}M</text>'
            )

        n = max(1, len(priced_tiers))
        bar_w = min(40.0, left_w / n * 0.58)
        for idx, s in enumerate(priced_tiers):
            sched = self._get_model_pricing(s.model)
            assert sched is not None
            r_unc = float(sched["uncached_input"])
            r_cac = float(sched["cached_input"])
            r_out = float(sched["output_and_thoughts"])
            c_unc = s.mean_uncached_input_tokens_per_run * r_unc / 1_000_000.0
            c_cac = s.mean_cached_tokens_per_run * r_cac / 1_000_000.0
            c_out = s.mean_output_tokens_per_run * r_out / 1_000_000.0
            c_tot = max(1e-9, c_unc + c_cac + c_out)
            p_unc = c_unc / c_tot
            p_cac = c_cac / c_tot
            p_out = c_out / c_tot

            cx_l = left_x0 + (idx + 0.5) * (left_w / n)
            h_unc = p_unc * plot_h
            h_cac = p_cac * plot_h
            h_out = p_out * plot_h

            y_unc = pad_t + plot_h - h_unc
            y_cac = y_unc - h_cac
            y_out = y_cac - h_out

            svg.append(
                f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_unc:.1f}" width="{bar_w:.1f}" height="{h_unc:.1f}" fill="#3498db"/>'
            )
            svg.append(
                f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_cac:.1f}" width="{bar_w:.1f}" height="{h_cac:.1f}" fill="#2ecc71"/>'
            )
            svg.append(
                f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_out:.1f}" width="{bar_w:.1f}" height="{h_out:.1f}" fill="#e74c3c"/>'
            )
            svg.append(
                f'<text x="{cx_l:.1f}" y="{pad_t - 5}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#c0392b">{p_out * 100:.0f}% out</text>'
            )
            svg.append(
                f'<text x="{cx_l:.1f}" y="{height - pad_b + 16}" text-anchor="end" font-size="10" fill="#222" transform="rotate(-25, {cx_l:.1f}, {height - pad_b + 16})">{s.ablation_tier}</text>'
            )

            # Right panel bar: Thinking + Output Tokens (M)
            cx_r = right_x0 + (idx + 0.5) * (right_w / n)
            out_m = s.mean_output_tokens_per_run / 1_000_000.0
            bh_r = (min(out_m, max_y_m) / max_y_m) * plot_h
            by_r = pad_t + plot_h - bh_r
            tot_in = s.mean_uncached_input_tokens_per_run + s.mean_cached_tokens_per_run
            ratio = (s.mean_output_tokens_per_run / tot_in) if tot_in > 0 else 0.0
            r_color = "#e74c3c" if "per_file" in s.ablation_tier else "#2b5c8f"
            svg.append(
                f'<rect x="{cx_r - bar_w / 2:.1f}" y="{by_r:.1f}" width="{bar_w:.1f}" height="{bh_r:.1f}" fill="{r_color}" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx_r:.1f}" y="{by_r - 6:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="{r_color}">{out_m:.2f}M ({ratio:.2f}x)</text>'
            )
            svg.append(
                f'<text x="{cx_r:.1f}" y="{height - pad_b + 16}" text-anchor="end" font-size="10" fill="#222" transform="rotate(-25, {cx_r:.1f}, {height - pad_b + 16})">{s.ablation_tier}</text>'
            )

        # Legend at bottom
        leg_items = [
            ("#3498db", "Uncached In (Flash $0.75, Argon/Sonnet $2.00 / 1M)"),
            ("#2ecc71", "Cached In (Flash $0.075, Argon $0.10, Sonnet $0.20 / 1M)"),
            ("#e74c3c", "Thinking + Out (Flash $3.75, Argon/Sonnet $10.00 / 1M)"),
        ]
        for l_idx, (l_col, l_txt) in enumerate(leg_items):
            lx = 18 + l_idx * 254
            ly = height - 18
            svg.append(
                f'<rect x="{lx}" y="{ly - 10}" width="12" height="12" fill="{l_col}" rx="2"/>'
            )
            svg.append(f'<text x="{lx + 16}" y="{ly}" font-size="9.5" fill="#222">{l_txt}</text>')

        svg.append("</svg>\n")
        svg_path.write_text("\n".join(svg), encoding="utf-8")

    @staticmethod
    def _render_rq1_comparison_svg(
        svg_path: Path,
        rq3_tiers: list[TierEvaluationSummary],
        repo_name: str = "caliptra-sw",
        svg_meta_header: str = "",
    ) -> None:
        """Renders grouped bar chart of Open Findings, PoC-Verified Findings, and Confirmed True Positives across tiers."""
        width, height = 740, 390
        pad_l, pad_r, pad_t, pad_b = 70, 40, 50, 85
        plot_w = width - pad_l - pad_r
        plot_h = height - pad_t - pad_b
        peak = max((s.mean_open_findings for s in rq3_tiers), default=30.0)
        step = 5 if peak <= 45 else 10
        max_y = float(((int(peak) // step) + 1) * step)
        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="26" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">Open Findings vs. PoC-Verified vs. Confirmed True Positives ({repo_name})</text>',
        ]
        for y_val in range(0, int(max_y) + 1, step):
            y_px = pad_t + plot_h - (y_val / max_y) * plot_h
            svg.append(
                f'<line x1="{pad_l}" y1="{y_px:.1f}" x2="{width - pad_r}" y2="{y_px:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{pad_l - 8}" y="{y_px + 4:.1f}" text-anchor="end" font-size="11" fill="#555">{y_val}</text>'
            )
        n = max(1, len(rq3_tiers))
        group_w = plot_w / n
        bw = min(18.0, group_w * 0.25)
        for idx, s in enumerate(rq3_tiers):
            cx = pad_l + (idx + 0.5) * group_w
            h_open = (min(s.mean_open_findings, max_y) / max_y) * plot_h
            h_poc = (min(s.mean_poc_verified, max_y) / max_y) * plot_h
            h_tp = (min(s.mean_true_positives, max_y) / max_y) * plot_h
            y_open = pad_t + plot_h - h_open
            y_poc = pad_t + plot_h - h_poc
            y_tp = pad_t + plot_h - h_tp
            svg.append(
                f'<rect x="{cx - 1.5 * bw - 2:.1f}" y="{y_open:.1f}" width="{bw:.1f}" height="{h_open:.1f}" fill="#5c7cfa" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx - bw - 2:.1f}" y="{y_open - 4:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#364fc7">{s.mean_open_findings:.1f}</text>'
            )
            svg.append(
                f'<rect x="{cx - 0.5 * bw:.1f}" y="{y_poc:.1f}" width="{bw:.1f}" height="{h_poc:.1f}" fill="#2b8a3e" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx:.1f}" y="{y_poc - 4:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#2b8a3e">{s.mean_poc_verified:.1f}</text>'
            )
            svg.append(
                f'<rect x="{cx + 0.5 * bw + 2:.1f}" y="{y_tp:.1f}" width="{bw:.1f}" height="{h_tp:.1f}" fill="#d9480f" rx="2"/>'
            )
            svg.append(
                f'<text x="{cx + bw + 2:.1f}" y="{y_tp - 4:.1f}" text-anchor="middle" font-size="9.5" font-weight="bold" fill="#d9480f">{s.mean_true_positives:.1f}</text>'
            )
            svg.append(
                f'<text x="{cx:.1f}" y="{height - pad_b + 18}" text-anchor="end" font-size="10" fill="#222" transform="rotate(-25, {cx:.1f}, {height - pad_b + 18})">{s.ablation_tier}</text>'
            )
        svg.append('<rect x="135" y="366" width="12" height="12" fill="#5c7cfa" rx="2"/>')
        svg.append('<text x="152" y="376" font-size="11" fill="#222">Open Findings</text>')
        svg.append('<rect x="305" y="366" width="12" height="12" fill="#2b8a3e" rx="2"/>')
        svg.append('<text x="322" y="376" font-size="11" fill="#222">PoC-Verified Findings</text>')
        svg.append('<rect x="495" y="366" width="12" height="12" fill="#d9480f" rx="2"/>')
        svg.append(
            '<text x="512" y="376" font-size="11" fill="#222">Confirmed True Positives (TP)</text>'
        )
        svg.append("</svg>\n")
        svg_path.write_text("\n".join(svg), encoding="utf-8")

    def _collect_phase_token_stats(
        self,
        eval_dir: Path,
        by_key: dict[str, TierEvaluationSummary],
    ) -> list[dict]:
        """Collects per-phase mean and SD for uncached_input, cached_input, thoughts, and output tokens across full[<model>] tiers."""
        phases = [
            ("project_exploration", "Exploration"),
            ("discovery", "Discovery"),
            ("deduplication", "Dedup"),
            ("initial_review", "Init Review"),
            ("poc_creation", "PoC Synth."),
            ("final_review", "Final Review"),
        ]
        candidate_tiers = [
            k
            for k in (
                "full",
                *[k for k in sorted(by_key.keys()) if k.startswith("full[") and "@" not in k],
            )
            if k in by_key
        ]
        if not candidate_tiers:
            return []

        model_series: list[dict] = []
        for tier_key in candidate_tiers:
            summary = by_key[tier_key]
            model_label = summary.model or tier_key
            trials_dir = eval_dir / "trials" / tier_key
            phase_samples: dict[str, dict[str, list[float]]] = {
                pid: {
                    "uncached": [],
                    "cached": [],
                    "input_total": [],
                    "thoughts": [],
                    "output": [],
                    "output_total": [],
                }
                for pid, _ in phases
            }
            found_files = False
            if trials_dir.is_dir():
                for rep_dir in sorted(trials_dir.glob("rep_*")):
                    tu_files = sorted(rep_dir.glob("run_*/token_usage.json")) or sorted(
                        rep_dir.glob("token_usage.json")
                    )
                    if not tu_files:
                        continue
                    try:
                        tu_data = json.loads(tu_files[-1].read_text(encoding="utf-8"))
                        by_phase = tu_data.get("by_phase") or {}
                        if not isinstance(by_phase, dict) or not by_phase:
                            continue
                        found_files = True
                        for pid, _ in phases:
                            b = by_phase.get(pid) or {}
                            unc = float(b.get("uncached_tokens", 0) or 0)
                            cac = float(b.get("cache_tokens", 0) or 0)
                            inp = float(b.get("total_input_tokens", unc + cac) or (unc + cac))
                            tho = float(b.get("thoughts_tokens", 0) or 0)
                            out = float(b.get("output_tokens", 0) or 0)
                            tot_out = float(b.get("total_output_tokens", tho + out) or (tho + out))
                            if tho == 0.0 and out == 0.0 and tot_out > 0.0:
                                out = tot_out
                            phase_samples[pid]["uncached"].append(unc)
                            phase_samples[pid]["cached"].append(cac)
                            phase_samples[pid]["input_total"].append(inp)
                            phase_samples[pid]["thoughts"].append(tho)
                            phase_samples[pid]["output"].append(out)
                            phase_samples[pid]["output_total"].append(tot_out)
                    except Exception:
                        continue

            if not found_files:
                continue

            phase_stats: dict[str, dict[str, float | None]] = {}
            n_reps = 0
            for pid, _ in phases:
                s_map = phase_samples[pid]
                n_reps = max(n_reps, len(s_map["input_total"]))
                unc_mean = statistics.fmean(s_map["uncached"]) if s_map["uncached"] else 0.0
                cac_mean = statistics.fmean(s_map["cached"]) if s_map["cached"] else 0.0
                inp_mean = statistics.fmean(s_map["input_total"]) if s_map["input_total"] else 0.0
                tho_mean = statistics.fmean(s_map["thoughts"]) if s_map["thoughts"] else 0.0
                out_mean = statistics.fmean(s_map["output"]) if s_map["output"] else 0.0
                tot_out_mean = (
                    statistics.fmean(s_map["output_total"]) if s_map["output_total"] else 0.0
                )
                est_cost = self._estimate_cost_usd(
                    unc_mean, cac_mean, tot_out_mean, model=model_label
                )
                phase_stats[pid] = {
                    "uncached_mean": round(unc_mean, 1),
                    "uncached_std": round(
                        statistics.stdev(s_map["uncached"]) if len(s_map["uncached"]) >= 2 else 0.0,
                        1,
                    ),
                    "cached_mean": round(cac_mean, 1),
                    "cached_std": round(
                        statistics.stdev(s_map["cached"]) if len(s_map["cached"]) >= 2 else 0.0,
                        1,
                    ),
                    "input_mean": round(inp_mean, 1),
                    "input_std": round(
                        statistics.stdev(s_map["input_total"])
                        if len(s_map["input_total"]) >= 2
                        else 0.0,
                        1,
                    ),
                    "thoughts_mean": round(tho_mean, 1),
                    "thoughts_std": round(
                        statistics.stdev(s_map["thoughts"]) if len(s_map["thoughts"]) >= 2 else 0.0,
                        1,
                    ),
                    "output_mean": round(out_mean, 1),
                    "output_std": round(
                        statistics.stdev(s_map["output"]) if len(s_map["output"]) >= 2 else 0.0,
                        1,
                    ),
                    "output_total_mean": round(tot_out_mean, 1),
                    "output_total_std": round(
                        statistics.stdev(s_map["output_total"])
                        if len(s_map["output_total"]) >= 2
                        else 0.0,
                        1,
                    ),
                    "estimated_cost_usd": round(est_cost, 4) if est_cost is not None else None,
                }
            model_series.append(
                {
                    "tier_key": tier_key,
                    "model": model_label,
                    "repetitions": n_reps,
                    "phases": phase_stats,
                }
            )
        return model_series

    def _export_phase_token_breakdown_plot(
        self,
        plots_dir: Path,
        eval_dir: Path,
        meta_header: str,
        svg_meta_header: str,
        repo_name: str,
        pinned_rev: str,
        by_key: dict[str, TierEvaluationSummary],
    ) -> None:
        """Exports 2-panel grouped bar chart (Uncached vs Cached Input and Thinking vs Output per phase with +-1 SD error bars)."""
        model_series = self._collect_phase_token_stats(eval_dir=eval_dir, by_key=by_key)
        if not model_series:
            return

        phases = [
            ("project_exploration", "Exploration"),
            ("discovery", "Discovery"),
            ("deduplication", "Dedup"),
            ("initial_review", "Init Review"),
            ("poc_creation", "PoC Synth."),
            ("final_review", "Final Review"),
        ]
        sym_phases = ",".join(label for _, label in phases)

        # 1. Export PGFPlots (.tex) — disjoint grouped bars (no overlaid totals)
        n_mod = len(model_series)
        bw_pt = 2.3 if n_mod >= 3 else (3.2 if n_mod >= 2 else 5.5)
        pretty_models = {
            "gemini-3.8-flash": "Gemini 3.8 Flash",
            "gemini-4-argon": "Gemini 4 Argon",
            "claude-sonnet-5-5": "Claude Sonnet 5.5",
        }
        tex = [
            meta_header,
            "\\resizebox{\\textwidth}{!}{%",
            "\\begin{tikzpicture}",
            "\\begin{axis}[",
            "    name=leftplot,",
            "    ybar,",
            f"    bar width={bw_pt:.1f}pt,",
            "    width=0.48\\textwidth,",
            "    height=5.4cm,",
            "    ylabel={Input Tokens / Phase (Millions)},",
            f"    symbolic x coords={{{sym_phases}}},",
            "    xtick=data,",
            "    xticklabel style={rotate=22, anchor=east, font=\\footnotesize},",
            "    ymin=0,",
            "    ymajorgrids=true,",
            "    grid style=dashed,",
            "    title={\\footnotesize\\textbf{(a) Input Tokens per Phase (Uncached vs.\\ Cached)}},",
            "    legend style={at={(0.5,1.15)}, anchor=south, legend columns=2, font=\\scriptsize}",
            "]",
        ]
        palette_in = [
            ("blue!65!white", "green!60!black"),
            ("violet!65!white", "teal!70!black"),
            ("brown!75!black", "olive!75!black"),
        ]
        for idx, ms in enumerate(model_series):
            c_unc, c_cac = palette_in[idx % len(palette_in)]
            raw_m = str(ms["model"]).split("/")[-1].split("@")[0]
            m_name = pretty_models.get(raw_m, self._latex_escape(raw_m))
            if ms["repetitions"] >= 2:
                unc_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['uncached_mean'] or 0.0) / 1e6:.2f}) +- (0,{float(ms['phases'][pid]['uncached_std'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                cac_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['cached_mean'] or 0.0) / 1e6:.2f}) +- (0,{float(ms['phases'][pid]['cached_std'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                tex.append(
                    f"\\addplot[fill={c_unc}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {unc_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Uncached In}}")
                tex.append(
                    f"\\addplot[fill={c_cac}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {cac_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Cached In}}")
            else:
                unc_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['uncached_mean'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                cac_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['cached_mean'] or 0.0) / 1e6:.2f})"
                    for pid, label in phases
                )
                tex.append(f"\\addplot[fill={c_unc}, draw=black] coordinates {{ {unc_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Uncached In}}")
                tex.append(f"\\addplot[fill={c_cac}, draw=black] coordinates {{ {cac_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Cached In}}")
        tex.extend(
            [
                "\\end{axis}",
                "\\begin{axis}[",
                "    at={(leftplot.outer north east)},",
                "    anchor=outer north west,",
                "    xshift=0.8cm,",
                "    ybar,",
                f"    bar width={bw_pt:.1f}pt,",
                "    width=0.48\\textwidth,",
                "    height=5.4cm,",
                "    ylabel={Thinking / Output Tokens / Phase (Thousands)},",
                f"    symbolic x coords={{{sym_phases}}},",
                "    xtick=data,",
                "    xticklabel style={rotate=22, anchor=east, font=\\footnotesize},",
                "    ymin=0,",
                "    ymajorgrids=true,",
                "    grid style=dashed,",
                "    title={\\footnotesize\\textbf{(b) Thinking vs.\\ Output Tokens per Phase (K)}},",
                "    legend style={at={(0.5,1.15)}, anchor=south, legend columns=2, font=\\scriptsize}",
                "]",
            ]
        )
        palette_out = [
            ("red!70!black", "orange!85!white"),
            ("magenta!75!black", "cyan!75!black"),
            ("purple!80!black", "yellow!75!orange"),
        ]
        for idx, ms in enumerate(model_series):
            c_tho, c_out = palette_out[idx % len(palette_out)]
            raw_m = str(ms["model"]).split("/")[-1].split("@")[0]
            m_name = pretty_models.get(raw_m, self._latex_escape(raw_m))
            if ms["repetitions"] >= 2:
                tho_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['thoughts_mean'] or 0.0) / 1e3:.1f}) +- (0,{float(ms['phases'][pid]['thoughts_std'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                out_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['output_mean'] or 0.0) / 1e3:.1f}) +- (0,{float(ms['phases'][pid]['output_std'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                tex.append(
                    f"\\addplot[fill={c_tho}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {tho_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Thinking}}")
                tex.append(
                    f"\\addplot[fill={c_out}, draw=black, error bars/.cd, y dir=both, y explicit] coordinates {{ {out_pts} }};"
                )
                tex.append(f"\\addlegendentry{{{m_name} Output}}")
            else:
                tho_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['thoughts_mean'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                out_pts = " ".join(
                    f"({label},{float(ms['phases'][pid]['output_mean'] or 0.0) / 1e3:.1f})"
                    for pid, label in phases
                )
                tex.append(f"\\addplot[fill={c_tho}, draw=black] coordinates {{ {tho_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Thinking}}")
                tex.append(f"\\addplot[fill={c_out}, draw=black] coordinates {{ {out_pts} }};")
                tex.append(f"\\addlegendentry{{{m_name} Output}}")
        tex.extend(
            [
                "\\end{axis}",
                "\\end{tikzpicture}%",
                "}",
                "",
            ]
        )
        (plots_dir / "fig_rq4_phase_token_breakdown.tex").write_text(
            "\n".join(tex), encoding="utf-8"
        )

        # 2. Export standalone 2-panel SVG (.svg)
        width, height = 860, 440
        pad_t, pad_b = 64, 104
        plot_h = height - pad_t - pad_b
        left_x0, left_w = 68, 335
        right_x0, right_w = 485, 335

        max_in_m = max(
            (
                (
                    float(ms["phases"][pid]["input_mean"] or 0.0)
                    + float(ms["phases"][pid]["input_std"] or 0.0)
                )
                / 1e6
                for ms in model_series
                for pid, _ in phases
            ),
            default=10.0,
        )
        max_y_in = (
            float(((int(max_in_m) // 25) + 1) * 25)
            if max_in_m >= 25
            else max(5.0, math.ceil(max_in_m * 1.15))
        )

        max_out_k = max(
            (
                (
                    float(ms["phases"][pid]["output_total_mean"] or 0.0)
                    + float(ms["phases"][pid]["output_total_std"] or 0.0)
                )
                / 1e3
                for ms in model_series
                for pid, _ in phases
            ),
            default=100.0,
        )
        max_y_out = (
            float(((int(max_out_k) // 250) + 1) * 250)
            if max_out_k >= 250
            else max(50.0, math.ceil(max_out_k * 1.15))
        )

        svg = [
            *([svg_meta_header] if svg_meta_header else []),
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="sans-serif">',
            '<rect width="100%" height="100%" fill="#ffffff"/>',
            f'<text x="{width / 2}" y="24" text-anchor="middle" font-size="14" font-weight="bold" fill="#111">Per-Phase Token Breakdown Across Models ({repo_name})</text>',
            f'<text x="{left_x0 + left_w / 2}" y="46" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(a) Input Tokens per Phase (Millions, ±1 SD)</text>',
            f'<text x="{right_x0 + right_w / 2}" y="46" text-anchor="middle" font-size="12" font-weight="bold" fill="#333">(b) Thinking vs. Output Tokens per Phase (Thousands, ±1 SD)</text>',
        ]

        for idx_tick in range(5):
            val_in = (idx_tick / 4.0) * max_y_in
            y_in = pad_t + plot_h - (val_in / max_y_in) * plot_h
            svg.append(
                f'<line x1="{left_x0}" y1="{y_in:.1f}" x2="{left_x0 + left_w}" y2="{y_in:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{left_x0 - 8}" y="{y_in + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{val_in:.0f}M</text>'
            )

            val_out = (idx_tick / 4.0) * max_y_out
            y_out = pad_t + plot_h - (val_out / max_y_out) * plot_h
            svg.append(
                f'<line x1="{right_x0}" y1="{y_out:.1f}" x2="{right_x0 + right_w}" y2="{y_out:.1f}" stroke="#e0e0e0" stroke-dasharray="4,4"/>'
            )
            svg.append(
                f'<text x="{right_x0 - 8}" y="{y_out + 4:.1f}" text-anchor="end" font-size="10" fill="#555">{val_out:.0f}K</text>'
            )

        n_phases = len(phases)
        n_models = len(model_series)
        group_w_l = left_w / n_phases
        group_w_r = right_w / n_phases
        bar_w = min(22.0, (group_w_l * 0.76) / max(1, n_models))

        in_colors = [("#2b5c8f", "#2ecc71"), ("#7570b3", "#1b9e77"), ("#8c510a", "#66a61e")]
        out_colors = [("#c0392b", "#f39c12"), ("#8e44ad", "#16a085"), ("#6a3d9a", "#e6ab02")]

        for p_idx, (pid, p_label) in enumerate(phases):
            gx_l = left_x0 + (p_idx + 0.5) * group_w_l
            gx_r = right_x0 + (p_idx + 0.5) * group_w_r
            svg.append(
                f'<text x="{gx_l:.1f}" y="{height - pad_b + 18}" text-anchor="end" font-size="10" font-weight="bold" fill="#222" transform="rotate(-25, {gx_l:.1f}, {height - pad_b + 18})">{p_label}</text>'
            )
            svg.append(
                f'<text x="{gx_r:.1f}" y="{height - pad_b + 18}" text-anchor="end" font-size="10" font-weight="bold" fill="#222" transform="rotate(-25, {gx_r:.1f}, {height - pad_b + 18})">{p_label}</text>'
            )

            for m_idx, ms in enumerate(model_series):
                offset = (m_idx - (n_models - 1) / 2.0) * (bar_w + 3.0)
                st = ms["phases"][pid]

                # Panel (a): Input tokens (Uncached + Cached)
                cx_l = gx_l + offset
                unc_m = float(st["uncached_mean"] or 0.0) / 1e6
                cac_m = float(st["cached_mean"] or 0.0) / 1e6
                tot_in_m = float(st["input_mean"] or 0.0) / 1e6
                std_in_m = float(st["input_std"] or 0.0) / 1e6

                h_unc = (min(unc_m, max_y_in) / max_y_in) * plot_h
                h_cac = (min(cac_m, max(0.0, max_y_in - unc_m)) / max_y_in) * plot_h
                y_unc = pad_t + plot_h - h_unc
                y_cac = y_unc - h_cac
                col_unc, col_cac = in_colors[m_idx % len(in_colors)]

                svg.append(
                    f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_unc:.1f}" width="{bar_w:.1f}" height="{h_unc:.1f}" fill="{col_unc}"/>'
                )
                svg.append(
                    f'<rect x="{cx_l - bar_w / 2:.1f}" y="{y_cac:.1f}" width="{bar_w:.1f}" height="{h_cac:.1f}" fill="{col_cac}"/>'
                )
                if ms["repetitions"] >= 2 and std_in_m > 0:
                    err_top = (
                        pad_t + plot_h - (min(max_y_in, tot_in_m + std_in_m) / max_y_in) * plot_h
                    )
                    err_bot = pad_t + plot_h - (max(0.0, tot_in_m - std_in_m) / max_y_in) * plot_h
                    svg.append(
                        f'<line x1="{cx_l:.1f}" y1="{err_top:.1f}" x2="{cx_l:.1f}" y2="{err_bot:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_l - 3.5:.1f}" y1="{err_top:.1f}" x2="{cx_l + 3.5:.1f}" y2="{err_top:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_l - 3.5:.1f}" y1="{err_bot:.1f}" x2="{cx_l + 3.5:.1f}" y2="{err_bot:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )

                # Panel (b): Thinking + Output tokens (Thousands)
                cx_r = gx_r + offset
                tho_k = float(st["thoughts_mean"] or 0.0) / 1e3
                out_k = float(st["output_mean"] or 0.0) / 1e3
                tot_out_k = float(st["output_total_mean"] or 0.0) / 1e3
                std_out_k = float(st["output_total_std"] or 0.0) / 1e3

                h_tho = (min(tho_k, max_y_out) / max_y_out) * plot_h
                h_out = (min(out_k, max(0.0, max_y_out - tho_k)) / max_y_out) * plot_h
                y_tho = pad_t + plot_h - h_tho
                y_out = y_tho - h_out
                col_tho, col_out = out_colors[m_idx % len(out_colors)]

                svg.append(
                    f'<rect x="{cx_r - bar_w / 2:.1f}" y="{y_tho:.1f}" width="{bar_w:.1f}" height="{h_tho:.1f}" fill="{col_tho}"/>'
                )
                svg.append(
                    f'<rect x="{cx_r - bar_w / 2:.1f}" y="{y_out:.1f}" width="{bar_w:.1f}" height="{h_out:.1f}" fill="{col_out}"/>'
                )
                if ms["repetitions"] >= 2 and std_out_k > 0:
                    err_top_r = (
                        pad_t
                        + plot_h
                        - (min(max_y_out, tot_out_k + std_out_k) / max_y_out) * plot_h
                    )
                    err_bot_r = (
                        pad_t + plot_h - (max(0.0, tot_out_k - std_out_k) / max_y_out) * plot_h
                    )
                    svg.append(
                        f'<line x1="{cx_r:.1f}" y1="{err_top_r:.1f}" x2="{cx_r:.1f}" y2="{err_bot_r:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_r - 3.5:.1f}" y1="{err_top_r:.1f}" x2="{cx_r + 3.5:.1f}" y2="{err_top_r:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )
                    svg.append(
                        f'<line x1="{cx_r - 3.5:.1f}" y1="{err_bot_r:.1f}" x2="{cx_r + 3.5:.1f}" y2="{err_bot_r:.1f}" stroke="#111" stroke-width="1.4"/>'
                    )

        # Bottom legend
        leg_entries = []
        for m_idx, ms in enumerate(model_series):
            c_unc, c_cac = in_colors[m_idx % len(in_colors)]
            c_tho, c_out = out_colors[m_idx % len(out_colors)]
            m_short = str(ms["model"]).replace("gemini-", "")
            leg_entries.extend(
                [
                    (c_unc, f"{m_short} Uncached In"),
                    (c_cac, f"{m_short} Cached In"),
                    (c_tho, f"{m_short} Thinking"),
                    (c_out, f"{m_short} Output"),
                ]
            )
        cols_per_row = 4
        for idx_l, (col_hex, text_l) in enumerate(leg_entries):
            row = idx_l // cols_per_row
            col = idx_l % cols_per_row
            lx = 55 + col * 195
            ly = height - 40 + row * 15
            svg.append(
                f'<rect x="{lx}" y="{ly - 9}" width="11" height="11" fill="{col_hex}" rx="2"/>'
            )
            svg.append(f'<text x="{lx + 15}" y="{ly}" font-size="10" fill="#222">{text_l}</text>')

        svg.append("</svg>\n")
        (plots_dir / "fig_rq4_phase_token_breakdown.svg").write_text(
            "\n".join(svg), encoding="utf-8"
        )
