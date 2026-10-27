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

## Reproducible Suite Entrypoints (Zero Options Required)

```bash
# 1. Run Mjolnir multi-checkpoint ablations (no_tm, no_expert, full x 3 reps on gemini-3.8-flash) across all 6 targets
nix run .#eval-ablation

# 2. Run single-agent baselines (per_file_no_tm, per_file, holistic_no_tm, holistic x 3 reps) on caliptra-sw
nix run .#eval-cli

# 3. Run cross-language multi-model consistency suite (full x 3 models x 3 reps across Rust/C/RTL: caliptra-sw, opentitan-fw, opentitan-rtl)
# Default models: gemini-3.8-flash,gemini-4-argon,vertex_ai/claude-sonnet-5-5
nix run .#eval-models

# 4. Run deep within-model stability & convergence suite (5 reps of full on caliptra-sw with gemini-3.8-flash)
nix run .#eval-stability

# 5. Run a single project's default ablation suite (no_tm, no_expert, full x 3 reps)
nix run .#eval-caliptra-sw
```

## 3-Step Workflow (`run` $\to$ `pool` $\to$ `scorecard`)

```bash
# 1. Run evaluation suites (writes trials_manifest.json, blind_review_pool.json, and scorecard.md)
nix run .#eval-caliptra-sw

# 2. (Optional) Rebuild blind_review_pool.json / blind_review_pool.md / blind_review/ while preserving human labels
nix run .#eval-caliptra-sw -- pool \
  --eval-dir ./test-out/evaluations/caliptra-sw/pinned

# 3. After labeling reviewer_1_label / reviewer_2_label / adjudicated_label in blind_review_pool.json,
#    regenerate RQ1-RQ4 Markdown & LaTeX booktabs scorecards (including Cohen's kappa)
nix run .#eval-caliptra-sw -- scorecard \
  --eval-dir ./test-out/evaluations/caliptra-sw/pinned
```

## Historical Known-CVE Recall Experiment (`caliptra-sw @ fw-2.1.0`)

`evaluations/projects/caliptra-sw-v210/` pins `chipsalliance/caliptra-sw` at release tag `fw-2.1.0` (`7da3b01b8b1806af0ec491c5e3e3e7cac91a3561`, `2026-03-10`) across all 10 on-target Caliptra Core RISC-V firmware crates (`202` non-test `.rs` files) to measure pipeline recall against the 5 publicly disclosed 2026 CVEs (`CVE-2026-5818`, `CVE-2026-6458`, `CVE-2026-7328`, `CVE-2026-11835`, `CVE-2026-11836`):

```bash
# Run 1-repetition full scan on gemini-3.8-flash and emit cve_recall_{results.json,scorecard.md,table.tex}
nix run .#eval-caliptra-sw-v210

# Re-score CVE recall against trials_manifest.json at any time
nix run .#eval-caliptra-sw-v210 -- score-cve-recall \
  --eval-dir ./test-out/evaluations/caliptra-sw-v210/pinned
```
