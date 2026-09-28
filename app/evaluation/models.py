# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Pydantic data models for mjolnir-eval datasets, 2-step grading, and phase-transition metrics."""

from pydantic import BaseModel, Field

from evaluation.constants import BENCHMARK_CANARY_GUID


class NcmCoordinate(BaseModel):
    """Optional 3D complexity coordinate for synthetic or stratified benchmark instances."""

    spatial_scope: int = Field(default=1, ge=1, le=3)
    state_depth: int = Field(default=1, ge=1, le=3)
    domain_subtlety: int = Field(default=1, ge=1, le=3)
    is_distractor: bool = Field(default=False)

    @property
    def cell_id(self) -> str:
        prefix = "D" if self.is_distractor else "V"
        return f"{prefix}-S{self.spatial_scope}-T{self.state_depth}-D{self.domain_subtlety}"


class VulnerableSpan(BaseModel):
    """Ground-truth AST / line span for a benchmark vulnerability."""

    file_path: str = Field(description="Relative repository path to the vulnerable file")
    function_name: str = Field(default="", description="Target function or method identifier")
    start_line: int = Field(ge=1, description="1-indexed start line")
    end_line: int = Field(ge=1, description="1-indexed end line")


class VulnInstanceManifest(BaseModel):
    """Ground-truth manifest stored in <dataset_dir>/instances/<vuln_id>/ground_truth.json."""

    canary: str = Field(default=BENCHMARK_CANARY_GUID)
    vuln_id: str
    dataset_id: str
    project_name: str
    base_commit: str
    scope: str = "default"
    cwe_id: str
    title: str
    description: str
    ncm: NcmCoordinate = Field(default_factory=NcmCoordinate)
    vulnerable_spans: list[VulnerableSpan]
    oracle_test_file: str = ""
    oracle_test_command: str = ""
    realism_gate_passed: bool = True
    oracle_verified: bool = True
    stealth_score: int = 10
    generator_model: str = "historical"
    created_at: str = ""


class DatasetManifest(BaseModel):
    """Dataset-level manifest stored at <dataset_dir>/dataset_manifest.json."""

    canary: str = Field(default=BENCHMARK_CANARY_GUID)
    dataset_id: str
    project_name: str
    repo_url: str
    base_commit: str
    profile: str = "default"
    generator_model: str = "historical"
    instance_ids: list[str] = Field(default_factory=list)
    created_at: str = ""


class RootCauseJudgeVerdict(BaseModel):
    """Structured verdict from the Step-2 LLM-as-a-Judge semantic root-cause matcher."""

    is_match: bool = Field(
        description="True ONLY if the reported finding identifies the same underlying security flaw / root-cause mechanism as the ground-truth vulnerability."
    )
    confidence: int = Field(
        default=10,
        ge=1,
        le=10,
        description="1-10 confidence score in the root-cause equivalence verdict.",
    )
    rationale: str = Field(
        default="",
        description="Concise explanation of why the reported finding matches or does not match the ground-truth root cause.",
    )


class PhaseTransitionStats(BaseModel):
    """Tracks how a pipeline phase changes finding counts, close rates, and severity ratings."""

    phase_id: str
    entering_count: int = 0
    surviving_open_count: int = 0
    closed_count: int = 0
    duplicate_count: int = 0
    severity_upgraded_count: int = 0
    severity_downgraded_count: int = 0
    severity_unchanged_count: int = 0
    severity_transitions: dict[str, int] = Field(
        default_factory=dict,
        description="Maps '<FromSeverity>-><ToSeverity|Closed|Duplicate>' to count.",
    )


class InstanceGrade(BaseModel):
    """Per-instance grading diagnostics across pipeline phases and checkpoints."""

    vuln_id: str
    ncm_cell: str
    is_distractor: bool
    cwe_id: str
    ablation_tier: str
    repetition: int
    detected_in_discovery: bool = False
    survived_deduplication: bool = False
    survived_initial_review: bool = False
    poc_synthesized_and_verified: bool = False
    survived_final_review: bool = False
    reviewer_falsely_disproved: bool = False
    distractor_truly_rejected: bool = False
    matched_finding_id: str | None = None
    matched_cwe_id: str | None = None
    judge_rationale: str = ""
    total_reported_open_findings: int = 0
    false_positives_count: int = 0
    phase_transitions: list[PhaseTransitionStats] = Field(default_factory=list)
    wall_clock_seconds: float = 0.0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    tamper_detected: bool = False


class TierAggregateMetrics(BaseModel):
    """Aggregated statistical metrics for an evaluation tier or phase checkpoint across repetitions."""

    ablation_tier: str
    tier_name: str
    repetitions: int
    total_injections: int
    total_distractors: int
    phase2_discovery_recall_mean: float
    phase2_discovery_recall_std: float
    final_recall_mean: float
    final_recall_std: float
    precision_mean: float = 0.0
    false_disproof_rate_mean: float
    distractor_rejection_rate_mean: float
    poc_synthesis_rate_mean: float
    false_discovery_rate_mean: float
    mean_open_findings_per_run: float = 0.0
    mean_false_positives_per_run: float = 0.0
    mean_tokens_per_run: float
    mean_cost_usd_per_run: float
    mean_wall_clock_seconds: float
    ncm_cell_recall: dict[str, float] = Field(default_factory=dict)
    phase_funnel_summary: dict[str, dict[str, float]] = Field(default_factory=dict)
