<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Mjolnir & Nidhogg Benchmark Suite

This directory houses the declarative benchmark project specifications (`benchmarks/projects/`) and version-controlled synthetic vulnerability datasets (`benchmarks/corpus/`).

## Pinned Benchmark Targets

All benchmark targets are pinned to immutable Git commit SHAs (`pinnedRev`) so the underlying codebase never changes under the hood across ablation or baseline evaluations:

| Project             | Nix Target                          | Pinned Commit (`pinnedRev`)                |
| :------------------ | :---------------------------------- | :----------------------------------------- |
| **Caliptra SW**     | `nix run .#nidhogg-caliptra-sw`     | `262470b019905e8ea307be63860730d64c35d436` |
| **Caliptra MCU SW** | `nix run .#nidhogg-caliptra-mcu-sw` | `21d2654c095048072bd07c9dbb2b3fa9528fa94d` |
| **Caliptra DPE**    | `nix run .#nidhogg-caliptra-dpe`    | `7c210f1217479040c966ecadead837b0432fa83a` |
| **OpenPRoT**        | `nix run .#nidhogg-openprot`        | `ef0607aebb36b67c3b8876cb3b609af55c2012ce` |
| **OpenTitan**       | `nix run .#nidhogg-opentitan`       | `c5a58fb8ad7b9e6c19164546a5e492975a77c464` |

## Usage

```bash
# 1. Generate a synthetic vulnerability dataset stratified across the 3D NCM matrix
nix run .#nidhogg-caliptra-sw -- generate --dataset-id v1_ncm --profile balanced --count 10

# 2. Run the 4-step ablation ladder + external baselines across the dataset
nix run .#nidhogg-caliptra-sw -- benchmark --dataset-id v1_ncm --tiers raw,threat_model,fast,full,antigravity_cli,clippy --repetitions 3

# 3. Regenerate Markdown & USENIX Security LaTeX booktabs scorecards from grades.json
nix run .#nidhogg-caliptra-sw -- scorecard --grades ./test-out/benchmarks/caliptra-sw/v1_ncm/grades.json
```
