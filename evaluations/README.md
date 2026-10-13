<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Mjolnir Evaluation Suite (`evaluations/`)

This directory houses the declarative evaluation project specifications (`evaluations/projects/`) for the five pinned Root-of-Trust (RoT) repositories.

## Pinned Evaluation Targets

Each evaluation target is pinned to an immutable Nix-fetched source tree (`pkgs.fetchFromGitHub`), scoped to a security-critical directory (`targetDir`), and configured with `minPocSeverity = "Informational"` so every finding surviving initial review undergoes PoC synthesis and final verification:

| Project             | Nix Target                       | Pinned Commit (`pinnedRev`)                | Focused `targetDir` / `srcDirs`                                                                      |
| :------------------ | :------------------------------- | :----------------------------------------- | :--------------------------------------------------------------------------------------------------- |
| **Caliptra SW**     | `nix run .#eval-caliptra-sw`     | `262470b019905e8ea307be63860730d64c35d436` | `runtime/src`                                                                                        |
| **Caliptra MCU SW** | `nix run .#eval-caliptra-mcu-sw` | `21d2654c095048072bd07c9dbb2b3fa9528fa94d` | `rom/src`, `common/mcu-mbox/src`, `common/pldm/src`, `common/flash-image/src`, `common/mctp-vdm/src` |
| **Caliptra DPE**    | `nix run .#eval-caliptra-dpe`    | `7c210f1217479040c966ecadead837b0432fa83a` | `.` (Full repository: `dpe`, `crypto`, `platform`, `response-buffer`, `dice-asn1`, `verification`)   |
| **OpenTitan FW**    | `nix run .#eval-opentitan-fw`    | `c5a58fb8ad7b9e6c19164546a5e492975a77c464` | `sw/device/silicon_creator/rom_ext`                                                                  |
| **OpenTitan RTL**   | `nix run .#eval-opentitan-rtl`   | `c5a58fb8ad7b9e6c19164546a5e492975a77c464` | `hw/top_earlgrey` (Verilator-backed SystemVerilog RTL)                                               |
| **OpenPRoT**        | `nix run .#eval-openprot`        | `34d82b1f2360bcc43986f5a9846e5b85de94ba98` | `services`                                                                                           |

## Reproducible Suite Entrypoints

```bash
# Run Mjolnir multi-checkpoint ablations (no_tm, no_expert, full x 3 reps on fixed gemini-3.8-flash) across all 6 targets
nix run .#eval-ablation

# Run Antigravity CLI agent baselines (4 modes x 3 reps on fixed model) across all 6 targets
nix run .#eval-cli

# Run single-project multi-model / multi-provider variance comparison (full x 3 reps on flagship target caliptra-sw by default)
# Default models: gemini-4-argon,vertex_ai/claude-sonnet-4-6 (merged with gemini-3.8-flash from eval-ablation)
nix run .#eval-models
# Or override target / models:
MJOLNIR_EVAL_MODEL_TARGET="caliptra-sw" MJOLNIR_EVAL_MODELS="gemini-4-argon,vertex_ai/claude-sonnet-4-6" nix run .#eval-models

# Run deep stability & convergence suite (default: 20 reps of full on caliptra-sw with gemini-3.8-flash)
nix run .#eval-stability
# Or override reps / target / model:
MJOLNIR_EVAL_STABILITY_REPS=20 MJOLNIR_EVAL_STABILITY_TARGET="caliptra-sw" nix run .#eval-stability

# Run fast real-life smoke validation on a single file (--scope smoke)
nix run .#eval-caliptra-dpe -- run --scope smoke --tiers no_tm,full --repetitions 1 --run-label smoke-validation
```

## 3-Step Workflow (`run` $\to$ `pool` $\to$ `scorecard`)

```bash
# 1. Run Mjolnir ablation tiers (extracts all 5 phase checkpoints automatically) + Antigravity CLI/SAST baselines
nix run .#eval-caliptra-sw -- run \
  --run-label usenix_v1 \
  --tiers base,no_tm,no_expert,full,cli_antigravity,cli_antigravity_no_tm,cli_antigravity_per_file,cli_antigravity_per_file_no_tm,sast \
  --repetitions 3

# 2. (Optional) Re-cluster trials into blind_review_pool.json / blind_review_pool.md while preserving human labels
nix run .#eval-caliptra-sw -- pool \
  --eval-dir ./test-out/evaluations/caliptra-sw/usenix_v1

# 3. After labeling reviewer_1_label / reviewer_2_label / adjudicated_label in blind_review_pool.json,
#    regenerate RQ1-RQ4 Markdown & USENIX Security LaTeX booktabs scorecards (including Cohen's kappa)
nix run .#eval-caliptra-sw -- scorecard \
  --eval-dir ./test-out/evaluations/caliptra-sw/usenix_v1
```
