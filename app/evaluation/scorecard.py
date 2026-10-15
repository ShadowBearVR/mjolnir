# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Aggregates real-world pinned trials, blind review adjudications, and RQ1-RQ4 metrics into Markdown and USENIX LaTeX tables."""

from collections import defaultdict
import json
import math
from pathlib import Path
import re
import statistics

from evaluation.constants import ABLATION_TIERS
from evaluation.grader import FindingPooler, compute_inter_rater_stats
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

        logger.success(
            f"Generated scorecard artifacts in {out_dir} (scorecard.json, scorecard.md, scorecard_tables.tex)"
        )
        return summaries

    def _aggregate_tier(
        self,
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
        precisions: list[float] = []
        recalls: list[float] = []
        false_disproofs: list[float] = []
        fp_eliminations: list[float] = []
        poc_pass_rates: list[float] = []

        run_tokens: list[int] = []
        run_cached_tokens: list[int] = []
        run_uncached_tokens: list[int] = []
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
                if occ.status.lower() != "open":
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
            n_open = trial.open_findings_count
            n_unique_rca = len(open_cids)
            n_redundant_dup = max(0, n_open - n_unique_rca)
            n_poc = trial.poc_verified_count

            open_counts.append(float(n_open))
            unique_rca_counts.append(float(n_unique_rca))
            redundant_dup_counts.append(float(n_redundant_dup))
            tp_counts.append(float(n_tp))
            fp_counts.append(float(n_fp))
            unlabeled_counts.append(float(len(unlabeled_cids)))
            poc_counts.append(float(n_poc))
            poc_tp_counts.append(float(len(poc_tp_cids)))

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

            rep_open_sets.append(open_cids)
            rep_poc_sets.append(poc_cids)
            rep_tp_sets.append(tp_cids)
            rep_fp_sets.append(fp_cids)
            run_tokens.append(trial.total_tokens)
            run_cached_tokens.append(trial.cached_tokens)
            run_uncached_tokens.append(trial.uncached_input_tokens)
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
        for trial in tier_trials:
            for pt in trial.phase_transitions:
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
        phase_funnel_summary = {
            pid: {k: round(v / n_reps, 2) for k, v in counts.items()}
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
            consistency_jaccard_mean = round(statistics.fmean(jaccards), 4)
            consistency_jaccard_std = round(
                statistics.stdev(jaccards) if len(jaccards) > 1 else 0.0, 4
            )
        else:
            consistency_jaccard_mean = 1.0
            consistency_jaccard_std = 0.0

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
            mean_output_tokens_per_run=round(statistics.fmean(run_output_tokens), 1)
            if run_output_tokens
            else 0.0,
            tokens_per_tp=tokens_per_tp,
            mean_wall_clock_seconds=round(statistics.fmean(run_times), 2) if run_times else 0.0,
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
                    len(tp_by_model[m1] & tp_by_model[m2]) / u_tp if u_tp > 0 else 1.0, 4
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
            lines.append(
                f"| **{s.tier_name}** | {s.mean_open_findings:.1f} | {s.mean_unique_root_causes:.1f} "
                f"| {s.redundancy_ratio:.2f}x | {s.mean_true_positives:.1f} "
                f"| {s.mean_false_positives:.1f} | {s.mean_poc_verified:.1f} "
                f"| {s.precision_mean:.1%} | {s.pooled_recall_mean:.1%} "
                f"| {s.false_disproof_rate_mean:.1%} | {s.fp_elimination_rate_mean:.1%} "
                f"| {s.mean_tokens_per_run:,.0f} | {tok_tp_str} | {s.mean_wall_clock_seconds:.1f}s |"
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
                "| Tier | Reps | Unique Open (Union) | Consistent Open (All Reps) | Unique TPs (Union) | Consistent TPs (All Reps) | Within-Model Jaccard | Uncached Input Tokens | Cached Input Tokens | Output Tokens | Total Tokens | Tokens/TP | Wall Clock (s) |",
                "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            ]
        )
        for s in summaries:
            if "@" in s.ablation_tier:
                continue
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "N/A"
            lines.append(
                f"| **{s.tier_name}** | {s.repetitions} | {s.unique_open_across_reps} "
                f"| {s.consistent_open_all_reps} | {s.unique_tps_across_reps} "
                f"| {s.consistent_tps_all_reps} | {s.consistency_jaccard_mean:.1%} (\u00b1{s.consistency_jaccard_std:.1%}) "
                f"| {s.mean_uncached_input_tokens_per_run:,.0f} "
                f"| {s.mean_cached_tokens_per_run:,.0f} | {s.mean_output_tokens_per_run:,.0f} "
                f"| {s.mean_tokens_per_run:,.0f} "
                f"| {tok_tp_str} | {s.mean_wall_clock_seconds:.1f}s |"
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
            "\\textbf{Configuration} & \\textbf{Open} & \\textbf{Unique RCAs} & \\textbf{Redundancy} & \\textbf{TP} & \\textbf{FP} & \\textbf{Precision} & \\textbf{Pooled Recall} & \\textbf{Tokens (M)} & \\textbf{Tokens/TP} & \\textbf{Time (s)} \\\\",
            "\\midrule",
        ]
        for s in summaries:
            safe_name = (
                s.tier_name.replace("&", "\\&").replace("_", "\\_").replace("@", "\\texttt{@}")
            )
            tok_m_str = f"{s.mean_tokens_per_run / 1_000_000:.2f}M"
            tok_tp_str = f"{s.tokens_per_tp:,.0f}" if s.tokens_per_tp is not None else "---"
            lines.append(
                f"{safe_name} & {s.mean_open_findings:.1f} & {s.mean_unique_root_causes:.1f} & "
                f"{s.redundancy_ratio:.2f}$\\times$ & {s.mean_true_positives:.1f} & "
                f"{s.mean_false_positives:.1f} & {s.precision_mean * 100:.1f}\\% & "
                f"{s.pooled_recall_mean * 100:.1f}\\% & {tok_m_str} & "
                f"{tok_tp_str} & {s.mean_wall_clock_seconds:.1f} \\\\"
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
