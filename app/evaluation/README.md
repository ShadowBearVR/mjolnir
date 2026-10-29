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

3. **Blind Dual-Expert Review Deck Builder & Cohen's $\kappa$ (`grader.py`)**:
   - Collects verbatim individual findings `(ablation_tier, repetition, finding_id)` across trials, preferring final `Open` writeups and falling back to `@discovery` `Open` writeups when findings were later closed so verifier disproof text never leaks into blind review.
   - Attaches pinned GitHub source permalinks (`#Lstart-Lend`), groups items by file, and shuffles within each file via SHA-256 hash order so model/tier/checkpoint provenance is hidden.
   - Exports `blind_review_pool.json`, `blind_review_pool.md`, and a provenance-stripped Web-UI-compatible `blind_review/` bundle for independent dual-expert `TP`/`FP` labeling and Cohen's $\kappa$ inter-rater reliability.

4. **`sandbox/` (Clean Pinned Workspace & Namespace Isolation)**:
   - **`OrphanSnapshotBuilder`**: Materializes Nix-fetched source trees (`nixSourcePath`) into an ephemeral single-commit Git workspace (`git rev-list --count HEAD == 1`, zero remotes) with pre-built Ctags index.
   - **`IsolatedProcessRunner`**: Wraps evaluated tools inside `bwrap` mount namespaces with `--tmpfs` masking prior trial outputs and cache directories.
