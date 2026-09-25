# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Pydantic data models for Nidhogg synthetic vulnerability generation and benchmarking."""

from pydantic import BaseModel, Field

from nidhogg.constants import BENCHMARK_CANARY_GUID


class NcmCoordinate(BaseModel):
    """3D coordinate in the Nidhogg Complexity Matrix (NCM)."""

    spatial_scope: int = Field(
        ge=1,
        le=3,
        description="1=Intra-procedural, 2=Inter-procedural (single crate), 3=Cross-Component",
    )
    state_depth: int = Field(
        ge=1,
        le=3,
        description="1=Stateless, 2=Shallow State (1-2 transitions), 3=Deep State / Concurrency",
    )
    domain_subtlety: int = Field(
        ge=1,
        le=3,
        description="1=Standard Weakness, 2=Spec/Policy Mismatch, 3=Hardware Interface / MMIO",
    )
    is_distractor: bool = Field(
        default=False,
        description="True if this injection is a provably unexploitable benign anomaly (decoy) testing false-positive rejection.",
    )

    @property
    def cell_id(self) -> str:
        prefix = "D" if self.is_distractor else "V"
        return f"{prefix}-S{self.spatial_scope}-T{self.state_depth}-D{self.domain_subtlety}"


class VulnerableSpan(BaseModel):
    """Ground-truth AST / line span for an injected vulnerability."""

    file_path: str = Field(description="Relative repository path to the modified production file")
    function_name: str = Field(description="Target function or method identifier")
    start_line: int = Field(ge=1, description="1-indexed start line in the patched file")
    end_line: int = Field(ge=1, description="1-indexed end line in the patched file")


class InjectionPlan(BaseModel):
    """Structured output from the VulnerabilityPlanner agent."""

    target_file: str = Field(description="Relative path to production file to mutate")
    target_function: str = Field(
        description="Exact function name where the flaw will be introduced"
    )
    cwe_id: str = Field(description="Target CWE identifier (e.g. CWE-226)")
    ncm: NcmCoordinate
    title: str = Field(description="Concise technical title of the vulnerability")
    rationale: str = Field(
        description="Why this location naturally fits the CWE and NCM coordinate without looking artificial"
    )
    mutation_strategy: str = Field(
        description="Exact code change to apply using idiomatic project conventions and zero revealing comments/identifiers"
    )
    trigger_strategy: str = Field(
        description="How a unit/integration test in the project's test suite can deterministically trigger and assert this flaw"
    )


class AdversarialReviewVerdict(BaseModel):
    """Structured output from the AdversarialReviewer agent."""

    approved: bool = Field(
        description="True ONLY if the patch is realistic, stealthy, free of revealing names/comments/magic constants, and matches the NCM coordinate"
    )
    stealth_score: int = Field(
        ge=1,
        le=10,
        description="1-10 rating of how indistinguishable the patch is from organic developer error",
    )
    realism_issues: list[str] = Field(
        default_factory=list,
        description="Specific reasons the patch looks artificial, breaks invariants, or leaks intent",
    )
    feedback: str = Field(
        default="",
        description="Actionable instructions for the VulnerabilityCreator if rejected",
    )


class CreatorSubmission(BaseModel):
    """Structured output from the VulnerabilityCreator agent."""

    summary: str = Field(description="Summary of the production mutation and oracle test")
    vulnerable_spans: list[VulnerableSpan] = Field(
        description="Exact file and function spans where the vulnerability resides"
    )
    oracle_test_file: str = Field(
        description="Relative path to the test file containing the standalone PoC oracle test"
    )
    oracle_test_command: str = Field(
        description="Exact test command that fails on the vulnerable code and passes on baseline"
    )


class SyntheticVulnManifest(BaseModel):
    """Ground-truth manifest stored in benchmarks/corpus/<project>/<dataset_id>/instances/<vuln_id>/ground_truth.json."""

    canary: str = Field(default=BENCHMARK_CANARY_GUID)
    vuln_id: str
    dataset_id: str
    project_name: str
    base_commit: str
    scope: str
    cwe_id: str
    title: str
    description: str
    ncm: NcmCoordinate
    vulnerable_spans: list[VulnerableSpan]
    oracle_test_file: str
    oracle_test_command: str
    realism_gate_passed: bool = False
    oracle_verified: bool = False
    stealth_score: int = 0
    generator_model: str
    created_at: str


class DatasetManifest(BaseModel):
    """Dataset-level manifest stored at benchmarks/corpus/<project>/<dataset_id>/dataset_manifest.json."""

    canary: str = Field(default=BENCHMARK_CANARY_GUID)
    dataset_id: str
    project_name: str
    repo_url: str
    base_commit: str
    profile: str
    generator_model: str
    instance_ids: list[str] = Field(default_factory=list)
    created_at: str
