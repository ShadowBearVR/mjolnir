<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nidhogg: Synthetic Vulnerability Generation Suite

Nidhogg (`app/nidhogg`) is the synthetic vulnerability injection engine for Mjolnir (`nidhogg-run generate`).

## Architecture

1. **`generation/` (`nidhogg-run generate`)**:
   - Stratifies synthetic bugs across the 3D **Nidhogg Complexity Matrix (NCM)**: `Spatial Scope` (1–3) $\times$ `Temporal/State Depth` (1–3) $\times$ `Domain Subtlety` (1–3), plus benign `Distractor` injections, grounded in `data/rot_cwes.json`.
   - Multi-agent ADK pipeline (`VulnerabilityPlanner` $\rightarrow$ `VulnerabilityCreator` inside a live `WorktreeSandbox` $\rightarrow$ `AdversarialReviewer`).
   - **`WorktreeRealismGate`**: Enforces lexical stealth (zero added comments or revealing tokens), clean compilation/linting, and a **two-sided binary PoC oracle** (`oracle_poc.diff` must **fail** on `base + vuln_patch.diff` and **pass** on `base`).
2. **Corpus Output**:
   - Emits `dataset_manifest.json` and per-instance `ground_truth.json`, `vuln_patch.diff`, and `oracle_poc.diff` for consumption by `mjolnir-eval` (`app/evaluation`).
