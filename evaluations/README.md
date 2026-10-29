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

## Stratified Security Baseline & Historical CVE Recall (`caliptra-sw @ fw-2.1.0`)

`evaluations/projects/caliptra-sw-v210/` pins `chipsalliance/caliptra-sw` at release tag `fw-2.1.0` (`7da3b01b8b1806af0ec491c5e3e3e7cac91a3561`, `2026-03-10`) across all 10 on-target Caliptra Core RISC-V firmware crates (`202` non-test `.rs` files) and evaluates pipeline recall against a complete 36-item post-`fw-2.1.0` Stratified Security Baseline (`SECURITY_BASELINE.md` and `cve_ground_truth.json`, covering all `295` upstream commits merged through `2026-10-27`):

- **Tier A (`5` Published CVEs / GHSAs)**: `CVE-2026-5818`, `CVE-2026-6458`, `CVE-2026-7328`, `CVE-2026-11835`, `CVE-2026-11836`
- **Tier B (`22` Maintainer Security Bugs, `SB-01`..`SB-22`)**: Auth/access-control bypasses, mailbox privilege checks, integer overflows, and PQC/protocol verification bugs patched upstream without separate CVE IDs (`Core Security Bugs = Tier A + B = 27 items`)
- **Tier C (`9` Zeroization, Attestation & Side-Channel Hardening Fixes, `SH-01`..`SH-09`)**: Secret zeroization, attestation completeness, and fault/timing hardening PRs (`Complete Baseline = Tier A–C = 36 items`)

```bash
# Run 1-repetition full scan on gemini-3.8-flash and emit stratified cve_recall_{results.json,scorecard.md,table.tex}
nix run .#eval-caliptra-sw-v210

# Re-score stratified Tier A–C recall against trials_manifest.json at any time
nix run .#eval-caliptra-sw-v210 -- score-cve-recall \
  --eval-dir ./test-out/evaluations/caliptra-sw-v210/pinned
```

## Double-Blind Expert Review Portal (Deck Build, Signed Links & Label Sync)

`web/blind_review/` and `scripts/deploy_gcs_eval.py` provide a serverless static review SPA where domain experts review provenance-stripped findings without seeing configuration names, pipeline phases, or model identities. Public `config.json` files contain **zero** upload credentials; write capabilities are carried strictly inside the private URL `#auth=<policy_b64url>.<sig_b64url>` fragment signed via keyless IAM `signBlob` (`GOOG4-RSA-SHA256`, $\le 7$-day TTL) against a private GCS dropbox bucket (`--public-access-prevention` enforced, Service Account restricted to `roles/storage.objectCreator` under `v2/`).

### 1. Environment Variables (Coordinator Shell)

```bash
export MJOLNIR_EVAL_BUCKET="<public-static-web-bucket>"
export MJOLNIR_SUBMISSIONS_BUCKET="<private-submissions-dropbox-bucket>"
export MJOLNIR_UPLOADER_SA="<uploader-sa>@<gcp-project-id>.iam.gserviceaccount.com"
export MJOLNIR_STUDY_KEY="caliptra-v2"
```

### 2. Generate Provenance-Stripped Review Decks

```bash
# Main 9-configuration double-blind study (hybrid stratified sample across 10 intact-file chunks; PoC withheld)
mjolnir-eval sample-blind-deck \
  --eval-dir ./test-out/evaluations/caliptra-sw/pinned \
  --seed mjolnir-usenix27-v2 \
  --unverified-per-tier 10 \
  --num-batches 10

# Single-batch open-finding review decks for one-off targets (with PoC tabs included)
for d in caliptra-mcu-sw/pinned openprot/pinned opentitan-fw/pinned opentitan-rtl/pinned; do
  mjolnir-eval sample-blind-deck \
    --eval-dir "./test-out/evaluations/${d}" \
    --seed mjolnir-usenix27-v2 \
    --unverified-per-tier 999 \
    --num-batches 1 \
    --include-poc
done
```

### 3. Deploy Static SPA & Mint Private `#auth=...` Invite URLs

Every non-dry-run deploy (or `--sign-only` refresh) writes freshly signed per-target invite links locally to `/live-urls.md` (`0600`, gitignored; never uploaded to GCS):

```bash
# Deploy static SPA + decks to MJOLNIR_EVAL_BUCKET and write signed invite URLs to ./live-urls.md
python3 scripts/deploy_gcs_eval.py \
  --only blind \
  --bucket "${MJOLNIR_EVAL_BUCKET}" \
  --submissions-bucket "${MJOLNIR_SUBMISSIONS_BUCKET}" \
  --signer-service-account "${MJOLNIR_UPLOADER_SA}" \
  --study-key "${MJOLNIR_STUDY_KEY}"

# Mint fresh 7-day signed invite URLs into ./live-urls.md without re-uploading static assets
python3 scripts/deploy_gcs_eval.py \
  --sign-only \
  --bucket "${MJOLNIR_EVAL_BUCKET}" \
  --submissions-bucket "${MJOLNIR_SUBMISSIONS_BUCKET}" \
  --signer-service-account "${MJOLNIR_UPLOADER_SA}" \
  --study-key "${MJOLNIR_STUDY_KEY}"
```

### 4. Pull Reviewer Snapshots, Check Coverage & Generate Scorecards

`sync-gcs-labels` pulls append-only JSON snapshots directly from `gs://${MJOLNIR_SUBMISSIONS_BUCKET}/v2/<study_key>/`, deduplicates multi-session edits per `(reviewer_email, review_id)` by latest timestamp, prints per-chunk review coverage (`B1=..., B10=...`), computes Krippendorff's $\alpha$ and Cohen's $\kappa$ on multi-reviewed cards, emits `blind_review/adjudication_template.json` for any tied items, and updates `scorecard.{json,md}` and `paper_tables/*.tex`:

```bash
# Main caliptra-sw ablation study
mjolnir-eval sync-gcs-labels \
  --eval-dir ./test-out/evaluations/caliptra-sw/pinned \
  --source "gs://${MJOLNIR_SUBMISSIONS_BUCKET}/v2" \
  --study-key "${MJOLNIR_STUDY_KEY}"

# Targeted one-off review studies
mjolnir-eval sync-gcs-labels --eval-dir ./test-out/evaluations/caliptra-mcu-sw/pinned --source "gs://${MJOLNIR_SUBMISSIONS_BUCKET}/v2" --study-key caliptra-mcu-sw
mjolnir-eval sync-gcs-labels --eval-dir ./test-out/evaluations/openprot/pinned        --source "gs://${MJOLNIR_SUBMISSIONS_BUCKET}/v2" --study-key openprot
mjolnir-eval sync-gcs-labels --eval-dir ./test-out/evaluations/opentitan-fw/pinned    --source "gs://${MJOLNIR_SUBMISSIONS_BUCKET}/v2" --study-key opentitan-fw
mjolnir-eval sync-gcs-labels --eval-dir ./test-out/evaluations/opentitan-rtl/pinned   --source "gs://${MJOLNIR_SUBMISSIONS_BUCKET}/v2" --study-key opentitan-rtl-v2

# Optional: steer newly arriving reviewers on the same invite URL to uncovered chunks (e.g., 4 and 9) first
python3 scripts/deploy_gcs_eval.py \
  --only blind \
  --bucket "${MJOLNIR_EVAL_BUCKET}" \
  --submissions-bucket "${MJOLNIR_SUBMISSIONS_BUCKET}" \
  --signer-service-account "${MJOLNIR_UPLOADER_SA}" \
  --study-key "${MJOLNIR_STUDY_KEY}" \
  --priority-batches 4,9

# Optional: apply third-reviewer tie-breakers and regenerate final scorecards
mjolnir-eval sync-gcs-labels \
  --eval-dir ./test-out/evaluations/caliptra-sw/pinned \
  --source "gs://${MJOLNIR_SUBMISSIONS_BUCKET}/v2" \
  --study-key "${MJOLNIR_STUDY_KEY}" \
  --adjudication-json ./test-out/evaluations/caliptra-sw/pinned/blind_review/adjudication_template.json
```

### 5. Post-Study Lockout

To close submissions immediately while preserving all collected snapshots for offline scoring, revoke the uploader Service Account's `objectCreator` binding on the submissions bucket:

```bash
gcloud storage buckets remove-iam-policy-binding "gs://${MJOLNIR_SUBMISSIONS_BUCKET}" \
  --member="serviceAccount:${MJOLNIR_UPLOADER_SA}" \
  --role="roles/storage.objectCreator" \
  --condition="expression=resource.name.startsWith('projects/_/buckets/${MJOLNIR_SUBMISSIONS_BUCKET}/objects/v2/'),title=v2-prefix-only"
```
