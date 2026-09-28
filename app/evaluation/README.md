<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Mjolnir Evaluation Suite (`mjolnir-eval`)

`app/evaluation` (`mjolnir-eval`) is the empirical evaluation, 3-run ablation, and baseline comparison harness for Mjolnir.

## Architecture

1. **3-Run Multi-Checkpoint Ablation (`no_tm`, `no_expert`, `full`)**:
   - Executes only 3 Mjolnir conditioning runs and reconstructs all intermediate phase checkpoints (`@discovery`, `@deduplication`, `@initial_review` [`no_poc`/`fast`], `@poc_creation`, `@final_review`) directly from `Vulnerability.history`.
   - Computes phase-by-phase entering/surviving counts, close rates, deduplication rates, and severity shift matrices (upgrades vs. downgrades).

2. **Configurable Host/Nix CLI Templates & SAST Baselines**:
   - Invokes external CLIs (`gemini`, `antigravity`, `claude`, `codex`) via safe `shlex` command templates (`{prompt}`, `{output_json}`, `{target_dir}`, `{file}`, `{threat_model}`) in both directory and per-file modes, with and without `threat_model.md`.
   - Includes adapters for `openant`, `clippy`, and `semgrep`.

3. **2-Step Semantic Root-Cause Grader (`grader.py`)**:
   - **Step 1 (Localization Filter)**: Matches candidate findings by file path and line/function span.
   - **Step 2 (Root-Cause Equivalence Judge)**: Verifies via CWE hierarchy equivalence and an optional deterministic (`temperature=0`) LLM-as-a-Judge that the reported finding identifies the same underlying security flaw as `ground_truth.json` + `vuln_patch.diff`.

4. **`sandbox/` (3-Barrier Anti-Cheat Isolation)**:
   - **Barrier 1 (`OrphanSnapshotBuilder`)**: Materializes Nix-fetched source trees (`nixSourcePath`) + optional `vuln_patch.diff` into an ephemeral single-commit orphan Git repository (`git rev-list --count HEAD == 1`, zero remotes).
   - **Barrier 2 (`IsolatedProcessRunner`)**: Wraps evaluated tools inside `bwrap` mount namespaces with `--tmpfs` masking corpus and cache directories.
   - **Barrier 3 (Canary GUID Audit)**: Scans run outputs/transcripts post-run for `BENCHMARK_CANARY_GUID`.
