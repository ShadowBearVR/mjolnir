<!-- Licensed under the Apache-2.0 license -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Mjolnir Evaluation Suite (`evaluations/`)

This directory houses the declarative evaluation project specifications (`evaluations/projects/`) and version-controlled ground-truth vulnerability datasets (`evaluations/corpus/`).

## Pinned Evaluation Targets

Each evaluation target is pinned to an immutable Nix-fetched source tree (`pkgs.fetchFromGitHub`) and scoped to a single security-critical directory (`targetDir`):

| Project             | Nix Target                       | Pinned Commit (`pinnedRev`)                | Focused `targetDir`                 |
| :------------------ | :------------------------------- | :----------------------------------------- | :---------------------------------- |
| **Caliptra SW**     | `nix run .#eval-caliptra-sw`     | `262470b019905e8ea307be63860730d64c35d436` | `rom/dev/src`                       |
| **Caliptra MCU SW** | `nix run .#eval-caliptra-mcu-sw` | `21d2654c095048072bd07c9dbb2b3fa9528fa94d` | `rom/src`                           |
| **Caliptra DPE**    | `nix run .#eval-caliptra-dpe`    | `7c210f1217479040c966ecadead837b0432fa83a` | `dpe/src`                           |
| **OpenTitan**       | `nix run .#eval-opentitan`       | `c5a58fb8ad7b9e6c19164546a5e492975a77c464` | `sw/device/silicon_creator/rom_ext` |

## Usage

```bash
# 1. Run the 3-run Mjolnir ablation matrix (yields all 15 phase checkpoints) + external CLI/SAST baselines
nix run .#eval-opentitan -- benchmark \
  --dataset-id v1 \
  --tiers no_tm,no_expert,full,cli_gemini,cli_claude,cli_codex,semgrep \
  --repetitions 3

# 2. Override a host CLI template on the fly
nix run .#eval-caliptra-sw -- benchmark \
  --dataset-id v1 \
  --tiers full,cli_gemini \
  --cli-template "gemini=gemini -p {prompt} --yolo"

# 3. Regenerate Markdown & USENIX Security LaTeX booktabs scorecards from grades.json
nix run .#eval-opentitan -- scorecard \
  --grades ./test-out/evaluations/opentitan/v1/grades.json
```
