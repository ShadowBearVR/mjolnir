# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Pydantic data models for real-world pinned RoT evaluations, blind review pooling, and RQ1-RQ4 scorecards."""

from pydantic import BaseModel, Field


class RootCauseJudgeVerdict(BaseModel):
    """Structured verdict from the LLM-as-a-Judge semantic root-cause equivalence matcher."""

    is_match: bool = Field(
        description="True ONLY if both findings identify the same underlying security flaw / root-cause mechanism."
    )
    confidence: int = Field(
        default=10,
        ge=1,
        le=10,
        description="1-10 confidence score in the root-cause equivalence verdict.",
    )
    rationale: str = Field(
        default="",
        description="Concise explanation of why the two findings share or do not share the same root cause.",
    )


class PhaseTransitionStats(BaseModel):
    """Tracks how a pipeline phase changes finding counts, close rates, and severity ratings (RQ2)."""

    phase_id: str
    entering_count: int = 0
    surviving_open_count: int = 0
    closed_count: int = 0
    duplicate_count: int = 0
    poc_verified_count: int = 0
    severity_upgraded_count: int = 0
    severity_downgraded_count: int = 0
    severity_unchanged_count: int = 0
    severity_transitions: dict[str, int] = Field(
        default_factory=dict,
        description="Maps '<FromSeverity>-><ToSeverity|Closed|Duplicate>' to count.",
    )


class TrialRunRecord(BaseModel):
    """Execution and finding record for a single trial (or extracted phase checkpoint) on a pinned target."""

    project_name: str
    repo_name: str
    pinned_rev: str
    target_dir: str
    ablation_tier: str
    tier_name: str
    model: str = ""
    repetition: int = 1
    is_checkpoint: bool = False
    wall_clock_seconds: float = 0.0
    total_tokens: int = 0
    cached_tokens: int = 0
    uncached_input_tokens: int = 0
    output_tokens: int = 0
    total_reported_findings: int = 0
    open_findings_count: int = 0
    poc_verified_count: int = 0
    phase_transitions: list[PhaseTransitionStats] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)


class FindingOccurrence(BaseModel):
    """Maps a canonical pooled finding back to a specific tool trial or checkpoint occurrence."""

    ablation_tier: str
    repetition: int
    finding_id: str
    status: str = "Open"
    severity: str = "Medium"
    poc_verified: bool = False
    cwe: str | None = None
    raw_title: str = ""
    raw_location: str = ""


class CanonicalFinding(BaseModel):
    """Provenance-stripped canonical finding entry in blind_review_pool.json for dual-expert adjudication."""

    canonical_id: str
    project_name: str
    repo_name: str
    pinned_rev: str
    file: str
    location: str
    start_line: int | None = None
    end_line: int | None = None
    cwe: str = ""
    severity: str = "Medium"
    title: str
    description: str
    attack_vector: str = ""
    recommendation: str = ""
    reviewer_1_label: str | None = Field(
        default=None, description="Independent Reviewer 1 verdict: 'TP' or 'FP'"
    )
    reviewer_2_label: str | None = Field(
        default=None, description="Independent Reviewer 2 verdict: 'TP' or 'FP'"
    )
    adjudicated_label: str | None = Field(
        default=None, description="Consensus verdict after adjudication: 'TP' or 'FP'"
    )
    maintainer_status: str = Field(
        default="",
        description="Upstream disclosure tracking: '', 'reported', 'confirmed', or 'fixed'",
    )
    notes: str = ""

    @staticmethod
    def _normalize_label(raw: str | None) -> str | None:
        if not raw:
            return None
        s = raw.strip().upper()
        if s in ("TP", "TRUE_POSITIVE", "TRUE POSITIVE", "VALID"):
            return "TP"
        if s in ("FP", "FALSE_POSITIVE", "FALSE POSITIVE", "INVALID"):
            return "FP"
        return None

    @property
    def resolved_label(self) -> str | None:
        adj = self._normalize_label(self.adjudicated_label)
        if adj:
            return adj
        r1 = self._normalize_label(self.reviewer_1_label)
        r2 = self._normalize_label(self.reviewer_2_label)
        if r1 and r2:
            return r1 if r1 == r2 else None
        return r1 or r2


class FindingPoolMapping(BaseModel):
    """Links a canonical_id in blind_review_pool.json to all tool/tier occurrences (hidden during blind review)."""

    canonical_id: str
    occurrences: list[FindingOccurrence] = Field(default_factory=list)


class InterRaterStats(BaseModel):
    """Inter-rater reliability and adjudication summary across the blind review pool."""

    total_canonical_findings: int = 0
    double_reviewed_count: int = 0
    adjudicated_count: int = 0
    confirmed_tp_count: int = 0
    confirmed_fp_count: int = 0
    unlabeled_count: int = 0
    raw_agreement_rate: float = 0.0
    cohens_kappa: float = 0.0


class CrossModelConsistencySummary(BaseModel):
    """Cross-model / cross-provider root-cause overlap and consensus metrics (RQ3)."""

    models: list[str] = Field(default_factory=list)
    total_unique_open_across_models: int = 0
    consensus_all_models_open: int = 0
    consensus_majority_models_open: int = 0
    total_unique_tps_across_models: int = 0
    consensus_all_models_tp: int = 0
    consensus_majority_models_tp: int = 0
    pairwise_open_jaccard: dict[str, float] = Field(default_factory=dict)
    pairwise_tp_jaccard: dict[str, float] = Field(default_factory=dict)
    mean_cross_model_open_jaccard: float = 0.0
    mean_cross_model_tp_jaccard: float = 0.0


class TierEvaluationSummary(BaseModel):
    """Aggregated statistical metrics for an evaluation tier or phase checkpoint across repetitions (RQ1-RQ4)."""

    ablation_tier: str
    tier_name: str
    model: str = ""
    repetitions: int
    total_pooled_tps: int = 0
    mean_open_findings: float = 0.0
    std_open_findings: float = 0.0
    mean_unique_root_causes: float = 0.0
    mean_redundant_duplicates: float = 0.0
    redundancy_ratio: float = 1.0
    mean_true_positives: float = 0.0
    std_true_positives: float = 0.0
    unique_open_across_reps: int = 0
    consistent_open_all_reps: int = 0
    unique_tps_across_reps: int = 0
    consistent_tps_all_reps: int = 0
    consistency_jaccard_mean: float = 0.0
    consistency_jaccard_std: float = 0.0
    mean_false_positives: float = 0.0
    mean_unlabeled_open: float = 0.0
    mean_poc_verified: float = 0.0
    std_poc_verified: float = 0.0
    mean_poc_verified_tps: float = 0.0
    precision_mean: float = 0.0
    precision_std: float = 0.0
    pooled_recall_mean: float = 0.0
    pooled_recall_std: float = 0.0
    false_disproof_rate_mean: float = 0.0
    fp_elimination_rate_mean: float = 0.0
    poc_pass_rate_mean: float = 0.0
    mean_tokens_per_run: float = 0.0
    mean_cached_tokens_per_run: float = 0.0
    mean_uncached_input_tokens_per_run: float = 0.0
    mean_output_tokens_per_run: float = 0.0
    tokens_per_tp: float | None = None
    mean_wall_clock_seconds: float = 0.0
    phase_funnel_summary: dict[str, dict[str, float]] = Field(default_factory=dict)
    saturation_curve: dict[int, dict[str, float]] = Field(default_factory=dict)
    severity_distribution_mean: dict[str, float] = Field(default_factory=dict)
    module_distribution_mean: dict[str, float] = Field(default_factory=dict)
    finding_detection_frequencies: dict[str, float] = Field(default_factory=dict)
