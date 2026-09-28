# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Aggregates evaluation trial grades, phase-transition funnels, and severity shifts into Markdown and USENIX LaTeX tables."""

from collections import defaultdict
import json
from pathlib import Path
import statistics

from evaluation.constants import ABLATION_TIERS
from evaluation.models import InstanceGrade, TierAggregateMetrics
from utilities.logger import logger


class ScorecardGenerator:
    """Computes statistical aggregates across repetitions and exports Markdown + LaTeX tables."""

    def generate_scorecard(
        self, grades_path: Path, output_dir: Path | None = None
    ) -> list[TierAggregateMetrics]:
        raw_grades = json.loads(grades_path.read_text(encoding="utf-8"))
        grades = [InstanceGrade.model_validate(g) for g in raw_grades]
        out_dir = output_dir or grades_path.parent
        out_dir.mkdir(parents=True, exist_ok=True)

        by_tier: dict[str, list[InstanceGrade]] = defaultdict(list)
        for g in grades:
            by_tier[g.ablation_tier].append(g)

        summaries: list[TierAggregateMetrics] = []
        for tier_key, tier_grades in by_tier.items():
            summaries.append(self._aggregate_tier(tier_key, tier_grades))

        (out_dir / "scorecard.json").write_text(
            json.dumps([s.model_dump() for s in summaries], indent=2),
            encoding="utf-8",
        )
        md_text = self._render_markdown(summaries)
        (out_dir / "scorecard.md").write_text(md_text, encoding="utf-8")

        latex_text = self._render_latex_booktabs(summaries)
        (out_dir / "scorecard_tables.tex").write_text(latex_text, encoding="utf-8")

        logger.success(
            f"Generated scorecard artifacts in {out_dir} (scorecard.json, scorecard.md, scorecard_tables.tex)"
        )
        return summaries

    def _aggregate_tier(
        self, tier_key: str, tier_grades: list[InstanceGrade]
    ) -> TierAggregateMetrics:
        by_rep: dict[int, list[InstanceGrade]] = defaultdict(list)
        for g in tier_grades:
            by_rep[g.repetition].append(g)

        p2_recalls: list[float] = []
        final_recalls: list[float] = []
        precisions: list[float] = []
        false_disproofs: list[float] = []
        distractor_rejections: list[float] = []
        poc_rates: list[float] = []
        fdrs: list[float] = []
        open_counts: list[float] = []
        fp_counts: list[float] = []
        run_tokens: list[int] = []
        run_costs: list[float] = []
        run_times: list[float] = []

        for rep, rep_grades in sorted(by_rep.items()):
            vulns = [g for g in rep_grades if not g.is_distractor]
            distractors = [g for g in rep_grades if g.is_distractor]
            n_vulns = len(vulns)
            n_dist = len(distractors)

            p2_hits = sum(1 for g in vulns if g.detected_in_discovery)
            final_hits = sum(1 for g in vulns if g.survived_final_review)
            disproved = sum(1 for g in vulns if g.reviewer_falsely_disproved)
            poc_hits = sum(1 for g in vulns if g.poc_synthesized_and_verified)
            dist_rejected = sum(1 for g in distractors if g.distractor_truly_rejected)

            total_open = sum(g.total_reported_open_findings for g in rep_grades)
            total_fp = sum(g.false_positives_count for g in rep_grades)
            tp_open = max(0, total_open - total_fp)

            p2_recalls.append(p2_hits / n_vulns if n_vulns else 0.0)
            final_recalls.append(final_hits / n_vulns if n_vulns else 0.0)
            precisions.append(tp_open / total_open if total_open else 1.0)
            false_disproofs.append(disproved / p2_hits if p2_hits else 0.0)
            poc_rates.append(poc_hits / n_vulns if n_vulns else 0.0)
            distractor_rejections.append(dist_rejected / n_dist if n_dist else 1.0)
            fdrs.append(total_fp / total_open if total_open else 0.0)
            open_counts.append(float(total_open))
            fp_counts.append(float(total_fp))

            run_tokens.append(sum(g.total_tokens for g in rep_grades))
            run_costs.append(sum(g.estimated_cost_usd for g in rep_grades))
            run_times.append(sum(g.wall_clock_seconds for g in rep_grades))

        by_cell: dict[str, list[bool]] = defaultdict(list)
        for g in tier_grades:
            if not g.is_distractor:
                by_cell[g.ncm_cell].append(g.survived_final_review)

        cell_recall = {
            cell: round(sum(1 for hit in hits if hit) / len(hits), 4)
            for cell, hits in sorted(by_cell.items())
        }

        # Aggregate phase transition funnel & severity shifts across runs
        funnel_acc: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "entering": 0,
                "surviving": 0,
                "closed": 0,
                "duplicate": 0,
                "upgraded": 0,
                "downgraded": 0,
                "unchanged": 0,
            }
        )
        for g in tier_grades:
            for pt in g.phase_transitions:
                bucket = funnel_acc[pt.phase_id]
                bucket["entering"] += pt.entering_count
                bucket["surviving"] += pt.surviving_open_count
                bucket["closed"] += pt.closed_count
                bucket["duplicate"] += pt.duplicate_count
                bucket["upgraded"] += pt.severity_upgraded_count
                bucket["downgraded"] += pt.severity_downgraded_count
                bucket["unchanged"] += pt.severity_unchanged_count

        n_reps = max(1, len(by_rep))
        phase_funnel_summary = {
            pid: {k: round(v / n_reps, 2) for k, v in counts.items()}
            for pid, counts in funnel_acc.items()
        }

        base_tier = tier_key.split("@")[0]
        base_name = str(ABLATION_TIERS.get(base_tier, {}).get("name", tier_key))
        tier_name = f"{base_name} [{tier_key.split('@')[1]}]" if "@" in tier_key else base_name

        first_rep = next(iter(by_rep.values()), [])
        return TierAggregateMetrics(
            ablation_tier=tier_key,
            tier_name=tier_name,
            repetitions=len(by_rep),
            total_injections=sum(1 for g in first_rep if not g.is_distractor),
            total_distractors=sum(1 for g in first_rep if g.is_distractor),
            phase2_discovery_recall_mean=round(statistics.fmean(p2_recalls), 4),
            phase2_discovery_recall_std=round(
                statistics.stdev(p2_recalls) if len(p2_recalls) > 1 else 0.0, 4
            ),
            final_recall_mean=round(statistics.fmean(final_recalls), 4),
            final_recall_std=round(
                statistics.stdev(final_recalls) if len(final_recalls) > 1 else 0.0, 4
            ),
            precision_mean=round(statistics.fmean(precisions), 4),
            false_disproof_rate_mean=round(statistics.fmean(false_disproofs), 4),
            distractor_rejection_rate_mean=round(statistics.fmean(distractor_rejections), 4),
            poc_synthesis_rate_mean=round(statistics.fmean(poc_rates), 4),
            false_discovery_rate_mean=round(statistics.fmean(fdrs), 4),
            mean_open_findings_per_run=round(statistics.fmean(open_counts), 2),
            mean_false_positives_per_run=round(statistics.fmean(fp_counts), 2),
            mean_tokens_per_run=round(statistics.fmean(run_tokens), 1),
            mean_cost_usd_per_run=round(statistics.fmean(run_costs), 4),
            mean_wall_clock_seconds=round(statistics.fmean(run_times), 2),
            ncm_cell_recall=cell_recall,
            phase_funnel_summary=phase_funnel_summary,
        )

    def _render_markdown(self, summaries: list[TierAggregateMetrics]) -> str:
        lines = [
            "# Mjolnir Evaluation Scorecard",
            "",
            "## 1. Ablation Ladder & Baseline Comparison",
            "",
            "| Tier | P2 Recall | Final Recall | Precision | False Disproof | Distractor Rej. | PoC Verified | FDR | Mean Open | Mean FP | Mean Tokens | Mean Time (s) |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        ]
        for s in summaries:
            lines.append(
                f"| **{s.tier_name}** | {s.phase2_discovery_recall_mean:.1%} (±{s.phase2_discovery_recall_std:.1%}) "
                f"| {s.final_recall_mean:.1%} (±{s.final_recall_std:.1%}) | {s.precision_mean:.1%} "
                f"| {s.false_disproof_rate_mean:.1%} | {s.distractor_rejection_rate_mean:.1%} "
                f"| {s.poc_synthesis_rate_mean:.1%} | {s.false_discovery_rate_mean:.1%} "
                f"| {s.mean_open_findings_per_run:.1f} | {s.mean_false_positives_per_run:.1f} "
                f"| {s.mean_tokens_per_run:,.0f} | {s.mean_wall_clock_seconds:.1f}s |"
            )

        # Render Phase-Transition Funnel & Severity-Shift Table for primary Mjolnir runs
        primary_runs = [
            s for s in summaries if "@" not in s.ablation_tier and s.phase_funnel_summary
        ]
        if primary_runs:
            lines.extend(
                [
                    "",
                    "## 2. Phase-Transition Funnel & Severity Shifts",
                    "",
                    "| Run | Phase | Entering | Surviving Open | Closed | Duplicate | Upgraded | Downgraded |",
                    "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
                ]
            )
            for s in primary_runs:
                for pid, counts in s.phase_funnel_summary.items():
                    lines.append(
                        f"| **{s.ablation_tier}** | `{pid}` | {counts['entering']:.1f} "
                        f"| {counts['surviving']:.1f} | {counts['closed']:.1f} "
                        f"| {counts['duplicate']:.1f} | {counts['upgraded']:.1f} "
                        f"| {counts['downgraded']:.1f} |"
                    )

        lines.extend(["", "## 3. Cell Recall Breakdown", ""])
        all_cells = sorted({cell for s in summaries for cell in s.ncm_cell_recall})
        if all_cells:
            header = "| Tier | " + " | ".join(all_cells) + " |"
            sep = "| :--- | " + " | ".join(":---:" for _ in all_cells) + " |"
            lines.extend([header, sep])
            for s in summaries:
                row = [f"**{s.ablation_tier}**"] + [
                    f"{s.ncm_cell_recall.get(c, 0.0):.1%}" for c in all_cells
                ]
                lines.append("| " + " | ".join(row) + " |")
        return "\n".join(lines) + "\n"

    def _render_latex_booktabs(self, summaries: list[TierAggregateMetrics]) -> str:
        lines = [
            "% Auto-generated by Mjolnir ScorecardGenerator for USENIX Security",
            "\\begin{table*}[t]",
            "\\centering",
            "\\small",
            "\\begin{tabular}{lcccccccc}",
            "\\toprule",
            "\\textbf{Configuration} & \\textbf{P2 Recall} & \\textbf{Final Recall} & \\textbf{Precision} & \\textbf{False Disproof} & \\textbf{Decoy Rej.} & \\textbf{PoC Rate} & \\textbf{FDR} & \\textbf{Time (s)} \\\\",
            "\\midrule",
        ]
        for s in summaries:
            safe_name = (
                s.tier_name.replace("&", "\\&").replace("_", "\\_").replace("@", "\\texttt{@}")
            )
            lines.append(
                f"{safe_name} & {s.phase2_discovery_recall_mean * 100:.1f}\\% & "
                f"{s.final_recall_mean * 100:.1f}\\% & {s.precision_mean * 100:.1f}\\% & "
                f"{s.false_disproof_rate_mean * 100:.1f}\\% & "
                f"{s.distractor_rejection_rate_mean * 100:.1f}\\% & {s.poc_synthesis_rate_mean * 100:.1f}\\% & "
                f"{s.false_discovery_rate_mean * 100:.1f}\\% & {s.mean_wall_clock_seconds:.1f} \\\\"
            )
        lines.extend(
            [
                "\\bottomrule",
                "\\end{tabular}",
                "\\caption{Ablation ladder and baseline evaluation across RoT vulnerabilities.}",
                "\\label{tab:mjolnir-ablation}",
                "\\end{table*}",
            ]
        )
        return "\n".join(lines) + "\n"
