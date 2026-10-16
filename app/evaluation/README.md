<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Mjolnir Evaluation Suite (`mjolnir-eval`)

`app/evaluation` (`mjolnir-eval`) is the empirical real-world evaluation, multi-checkpoint ablation, blind review pooling, and baseline comparison harness for Mjolnir.

## Architecture

1. **Multi-Checkpoint Ablation (`base`, `no_tm`, `no_expert`, `full`)**:
   - Evaluates pinned Root-of-Trust (RoT) source trees with `minPocSeverity = "Informational"` (so all findings surviving `Initial Review` undergo `PoC Creation` and `Final Review`).
   - Automatically reconstructs intermediate phase checkpoints (`@discovery`, `@deduplication`, `@initial_review` [`no_poc`/`fast`], `@poc_creation`, `@final_review`) directly from `Vulnerability.history`.
   - Computes phase-by-phase entering/surviving counts, close rates, deduplication rates, PoC verification counts, and severity shift matrices (upgrades vs. downgrades).

2. **Controlled Single-Agent ADK Baselines**:
   - Evaluates controlled single-agent ADK baselines (`holistic_no_tm`, `holistic`, `per_file_no_tm`, `per_file`) using the exact same model and temperature as Mjolnir.

3. **Blind Dual-Expert Review Pooler & Cohen's $\kappa$ (`grader.py`)**:
   - **Step 1 (Localization Filter)**: Clusters candidate findings across all tools, tiers, and repetitions by file path and line/function span (`±35` lines).
   - **Step 2 (Root-Cause Equivalence)**: Groups findings sharing equivalent CWEs (via MITRE CWE hierarchy) or semantic root cause (via optional LLM judge).
   - Exports a provenance-stripped, deterministically shuffled `blind_review_pool.json`, `blind_review_pool.md`, and Web-UI-compatible `blind_review/` bundle for independent dual-expert labeling (`TP`/`FP`), alongside `finding_pool_mapping.json` and Cohen's $\kappa$ inter-rater reliability.

4. **`sandbox/` (Clean Pinned Workspace & Namespace Isolation)**:
   - **`OrphanSnapshotBuilder`**: Materializes Nix-fetched source trees (`nixSourcePath`) into an ephemeral single-commit Git workspace (`git rev-list --count HEAD == 1`, zero remotes) with pre-built Ctags index.
   - **`IsolatedProcessRunner`**: Wraps evaluated tools inside `bwrap` mount namespaces with `--tmpfs` masking prior trial outputs and cache directories.
