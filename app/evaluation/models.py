# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Pydantic data models for real-world pinned RoT evaluations, blind per-finding review, and RQ1-RQ4 scorecards."""

from pydantic import BaseModel, Field


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
    mjolnir_commit: str = ""
    mjolnir_dirty: bool = False
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


class BlindReviewFinding(BaseModel):
    """Individual finding entry in blind_review_pool.json for dual-expert TP/FP adjudication."""

    review_id: str
    ablation_tier: str = ""
    repetition: int = 1
    finding_id: str = ""
    final_status: str = "Open"
    poc_verified: bool = False
    project_name: str
    repo_name: str
    pinned_rev: str
    file: str
    location: str
    start_line: int | None = None
    end_line: int | None = None
    source_url: str | None = None
    cwe: str = ""
    severity: str = "Medium"
    title: str
    description: str
    attack_vector: str = ""
    recommendation: str = ""
    in_blind_sample: bool = True
    sampling_weight: float = 1.0
    sampling_stratum: str = "census"
    reviewer_1_label: str | None = Field(
        default=None, description="Independent Reviewer 1 verdict: 'TP' or 'FP'"
    )
    reviewer_2_label: str | None = Field(
        default=None, description="Independent Reviewer 2 verdict: 'TP' or 'FP'"
    )
    reviewer_votes: dict[str, str] = Field(
        default_factory=dict,
        description="Maps normalized reviewer email/handle to normalized binary verdict ('TP' or 'FP').",
    )
    reviewer_severities: dict[str, str] = Field(
        default_factory=dict,
        description="Maps normalized reviewer email/handle to normalized optional severity ('High', 'Medium', 'Low', etc.).",
    )
    reviewer_notes: dict[str, str] = Field(
        default_factory=dict,
        description="Maps normalized reviewer email/handle (or '<email>#pass2') to optional free-text notes.",
    )
    adjudicated_label: str | None = Field(
        default=None,
        description="Consensus verdict after adjudication: 'TP', 'FP', or 'exclude'",
    )
    expert_severity: str | None = Field(
        default=None,
        description="Expert severity for confirmed TPs: 'Critical', 'High', 'Medium', 'Low', or 'Informational'",
    )
    poc_demonstrates: str | None = Field(
        default=None,
        description="Whether a verified PoC genuinely exercises the flaw: 'yes' or 'no'",
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
        if s in ("TP", "TRUE_POSITIVE", "TRUE POSITIVE", "VALID", "YES", "Y"):
            return "TP"
        if s in ("FP", "FALSE_POSITIVE", "FALSE POSITIVE", "INVALID", "NO", "N"):
            return "FP"
        return None

    @staticmethod
    def _normalize_severity(raw: str | None) -> str | None:
        if not raw:
            return None
        mapping = {
            "critical": "Critical",
            "crit": "Critical",
            "severe": "High",
            "high/critical": "High",
            "high / critical": "High",
            "high": "High",
            "medium": "Medium",
            "med": "Medium",
            "moderate": "Medium",
            "low": "Low",
            "benign": "Low",
            "benign/low": "Low",
            "benign / low": "Low",
            "informational": "Informational",
            "info": "Informational",
        }
        return mapping.get(raw.strip().lower())

    @staticmethod
    def _normalize_yes_no(raw: str | None) -> str | None:
        if raw is None:
            return None
        s = str(raw).strip().lower()
        if s in ("yes", "y", "true", "1"):
            return "yes"
        if s in ("no", "n", "false", "0"):
            return "no"
        return None

    @property
    def is_excluded(self) -> bool:
        return str(self.adjudicated_label or "").strip().lower() in ("exclude", "excluded")

    @property
    def resolved_label(self) -> str | None:
        if self.is_excluded:
            return None
        adj = self._normalize_label(self.adjudicated_label)
        if adj:
            return adj
        valid_votes = [
            norm
            for v in self.reviewer_votes.values()
            if (norm := self._normalize_label(v)) in ("TP", "FP")
        ]
        if len(valid_votes) == 1:
            return valid_votes[0]
        if len(valid_votes) >= 2:
            tp_votes = sum(1 for v in valid_votes if v == "TP")
            fp_votes = len(valid_votes) - tp_votes
            if tp_votes > fp_votes:
                return "TP"
            if fp_votes > tp_votes:
                return "FP"
            return None
        r1 = self._normalize_label(self.reviewer_1_label)
        r2 = self._normalize_label(self.reviewer_2_label)
        if r1 and r2:
            return r1 if r1 == r2 else None
        return None

    @property
    def normalized_expert_severity(self) -> str | None:
        return self._normalize_severity(self.expert_severity)

    @property
    def normalized_poc_demonstrates(self) -> str | None:
        return self._normalize_yes_no(self.poc_demonstrates)


class InterRaterStats(BaseModel):
    """Inter-rater reliability and adjudication summary across the blind review pool."""

    total_findings: int = 0
    in_sample_findings: int = 0
    double_reviewed_count: int = 0
    single_reviewed_count: int = 0
    adjudicated_count: int = 0
    confirmed_tp_count: int = 0
    confirmed_tp_medium_or_above_count: int = 0
    confirmed_fp_count: int = 0
    excluded_count: int = 0
    disputed_unadjudicated_count: int = 0
    unlabeled_count: int = 0
    raw_agreement_rate: float = 0.0
    cohens_kappa: float = 0.0
    krippendorffs_alpha: float = 0.0
    expert_severity_counts: dict[str, int] = Field(default_factory=dict)
    poc_demonstrates_counts: dict[str, int] = Field(default_factory=dict)


class TierEvaluationSummary(BaseModel):
    """Aggregated statistical metrics for an evaluation tier or phase checkpoint across repetitions (RQ1-RQ4)."""

    ablation_tier: str
    tier_name: str
    model: str = ""
    repetitions: int
    mean_open_findings: float = 0.0
    std_open_findings: float = 0.0
    min_open_findings: int = 0
    max_open_findings: int = 0
    mean_true_positives: float = 0.0
    std_true_positives: float = 0.0
    mean_false_positives: float = 0.0
    std_false_positives: float = 0.0
    mean_unlabeled_open: float = 0.0
    mean_poc_verified: float = 0.0
    std_poc_verified: float = 0.0
    min_poc_verified: int = 0
    max_poc_verified: int = 0
    mean_poc_verified_tps: float = 0.0
    mean_poc_verified_fps: float = 0.0
    mean_open_unverified: float = 0.0
    mean_open_unverified_tps: float = 0.0
    mean_open_unverified_fps: float = 0.0
    mean_harness_limitation: float = 0.0
    mean_disproved_by_harness: float = 0.0
    mean_true_positives_medium_plus: float = 0.0
    precision_mean: float | None = None
    precision_std: float | None = None
    poc_verified_precision_mean: float | None = None
    poc_verified_precision_std: float | None = None
    open_unverified_precision_mean: float | None = None
    open_unverified_precision_std: float | None = None
    precision_medium_plus_mean: float | None = None
    false_disproof_rate_mean: float | None = None
    fp_elimination_rate_mean: float | None = None
    poc_pass_rate_mean: float | None = None
    mean_tokens_per_run: float = 0.0
    mean_cached_tokens_per_run: float = 0.0
    mean_uncached_input_tokens_per_run: float = 0.0
    mean_thoughts_tokens_per_run: float = 0.0
    mean_pure_output_tokens_per_run: float = 0.0
    mean_output_tokens_per_run: float = 0.0
    tokens_per_tp: float | None = None
    mean_wall_clock_seconds: float | None = None
    mean_llm_calls_per_run: float = 0.0
    std_llm_calls_per_run: float = 0.0
    llm_calls_by_agent: dict[str, dict[str, float]] = Field(default_factory=dict)
    mean_tool_calls_per_run: float = 0.0
    std_tool_calls_per_run: float = 0.0
    mean_tool_errors_per_run: float = 0.0
    std_tool_errors_per_run: float = 0.0
    tool_calls_by_category: dict[str, dict[str, float]] = Field(default_factory=dict)
    tool_calls_by_agent: dict[str, dict[str, float]] = Field(default_factory=dict)
    tokens_by_agent: dict[str, dict[str, float | None]] = Field(default_factory=dict)
    mean_project_expert_questions: float = 0.0
    std_project_expert_questions: float = 0.0
    mean_project_expert_answered_from_history: float = 0.0
    std_project_expert_answered_from_history: float = 0.0
    mean_project_expert_cache_hits: float = 0.0
    mean_poc_attempts: float = 0.0
    std_poc_attempts: float = 0.0
    mean_poc_harness_commands: float = 0.0
    std_poc_harness_commands: float = 0.0
    mean_poc_harness_commands_per_finding: float | None = None
    std_poc_harness_commands_per_finding: float | None = None
    mean_poc_gate_failures: float = 0.0
    std_poc_gate_failures: float = 0.0
    refusals_summary: dict[str, int | dict[str, dict[str, int]]] = Field(default_factory=dict)
    phase_funnel_summary: dict[str, dict[str, float]] = Field(default_factory=dict)
    severity_distribution_mean: dict[str, float] = Field(default_factory=dict)
    module_distribution_mean: dict[str, float] = Field(default_factory=dict)
