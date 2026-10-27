# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for Stratified Security Baseline & Known-CVE recall evaluation (caliptra-sw fw-2.1.0)."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

from pydantic import ValidationError

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "app"))
sys.path.insert(0, str(ROOT_DIR / "app" / "mjolnir"))

from evaluation.cve_recall import (  # noqa: E402
    CveGroundTruthManifest,
    CveRecallEvaluator,
    KnownCveSpec,
)
from evaluation.models import TrialRunRecord  # noqa: E402


class TestCveRecallEvaluator(unittest.TestCase):
    def setUp(self) -> None:
        self.gt_path = (
            ROOT_DIR / "evaluations" / "projects" / "caliptra-sw-v210" / "cve_ground_truth.json"
        )
        self.gt = CveGroundTruthManifest.model_validate(
            json.loads(self.gt_path.read_text(encoding="utf-8"))
        )

    def test_ground_truth_manifest_has_stratified_tiers_a_through_c(self) -> None:
        self.assertEqual(self.gt.pinned_tag, "fw-2.1.0")
        self.assertEqual(
            self.gt.pinned_rev,
            "7da3b01b8b1806af0ec491c5e3e3e7cac91a3561",
        )
        self.assertEqual(len(self.gt.cves), 36)

        tier_a = [c for c in self.gt.cves if c.tier == "A"]
        tier_b = [c for c in self.gt.cves if c.tier == "B"]
        tier_c = [c for c in self.gt.cves if c.tier == "C"]

        self.assertEqual(
            [c.cve_id for c in tier_a],
            [
                "CVE-2026-5818",
                "CVE-2026-6458",
                "CVE-2026-7328",
                "CVE-2026-11835",
                "CVE-2026-11836",
            ],
        )
        self.assertEqual(len(tier_b), 22)
        self.assertEqual(tier_b[0].cve_id, "SB-01")
        self.assertEqual(tier_b[-1].cve_id, "SB-22")
        self.assertEqual(len(tier_c), 9)
        self.assertEqual(tier_c[0].cve_id, "SH-01")
        self.assertEqual(tier_c[-1].cve_id, "SH-09")

        for item in self.gt.cves:
            self.assertTrue(item.fix_pr_url.startswith("https://github.com/chipsalliance/"))
            self.assertTrue(item.fix_commit_url.startswith("https://github.com/chipsalliance/"))
            if item.tier == "A":
                self.assertTrue(item.advisory_url.startswith("https://github.com/chipsalliance/"))

    def test_url_allowlist_rejects_untrusted_links(self) -> None:
        with self.assertRaises(ValidationError):
            KnownCveSpec(
                cve_id="SB-99",
                tier="B",
                severity="High",
                advisory_url="javascript:alert(1)",
                title="Invalid URL Test",
                summary="Must reject non-GitHub/NVD URLs.",
                sites=[],
            )

    def test_positive_negative_and_stratified_checkpoint_recall(self) -> None:
        discovery_findings = [
            {
                "id": "f-5818",
                "file": "runtime/src/activate_firmware.rs",
                "location": "activate_fw (Line 225)",
                "status": "Open",
                "poc_verified": False,
                "severity": "High",
                "title": "Ignored AuthorizeAndStash Return Value Bypasses MCU Auth",
                "description": "activate_fw calls authorize_and_stash and maps ImageAuthorizationStatus to ().",
            },
            {
                "id": "f-6458",
                "file": "drivers/src/aes.rs",
                "location": "aes_256_gcm_update (Line 369)",
                "status": "Open",
                "poc_verified": False,
                "severity": "Medium",
                "title": "GHASH State Reset to Default on Streaming Update with Empty AAD",
                "description": "When context.aad_len == 0 && context.buffer_len == 0, ghash_state is discarded.",
            },
            {
                "id": "f-7328-a",
                "file": "runtime/src/invoke_dpe.rs",
                "location": "execute_mldsa87 (Line 159)",
                "status": "Open",
                "poc_verified": False,
                "severity": "High",
                "title": "Arbitrary AXI DMA Write Without PL0 Check in execute_mldsa87",
                "description": "Unvalidated axi_response address passed to drivers.dma.write_buffer.",
            },
            {
                "id": "f-7328-b",
                "file": "runtime/src/cryptographic_mailbox.rs",
                "location": "aes_gcm_decrypt_dma (Line 2790)",
                "status": "Open",
                "poc_verified": False,
                "severity": "High",
                "title": "Unverified AXI Source and Destination DMA Addresses",
                "description": "aes_gcm_decrypt_dma performs DMA without PAUSER PL0 check or range bounds.",
            },
            {
                "id": "f-sb18-mldsa-pad",
                "file": "runtime/src/cryptographic_mailbox.rs",
                "location": "mldsa_verify (Line 2240)",
                "status": "Open",
                "poc_verified": False,
                "severity": "Low",
                "title": "Missing Signature Trailing Padding Byte Validation",
                "description": "ML-DSA signature buffer trailing byte is not checked against zero.",
            },
            {
                "id": "f-sh07-cmk-zeroize",
                "file": "common/src/crypto.rs",
                "location": "decrypt_cmk (Line 200)",
                "status": "Open",
                "poc_verified": False,
                "severity": "Low",
                "title": "Plaintext Key Material Not Zeroized in decrypt_cmk",
                "description": "Unencrypted key material remains on stack without zeroize.",
            },
            {
                "id": "f-11836",
                "file": "common/src/debug_unlock.rs",
                "location": "validate_debug_unlock_token (Line 184)",
                "status": "Open",
                "poc_verified": False,
                "severity": "Medium",
                "title": "Debug Unlock Token Signature Missing Device UDI Binding",
                "description": "token.unique_device_identifier is hashed without comparing against challenge UDI.",
            },
        ]

        # Simulate final full trial where f-6458 and f-sh07 were closed in triage and f-5818 got PoC-verified
        final_findings = []
        for item in discovery_findings:
            copy_item = dict(item)
            if copy_item["id"] == "f-5818":
                copy_item["poc_verified"] = True
            elif copy_item["id"] in {"f-6458", "f-sh07-cmk-zeroize"}:
                copy_item["status"] = "Closed"
            final_findings.append(copy_item)

        trials = [
            TrialRunRecord(
                project_name="Caliptra SW (fw-2.1.0)",
                repo_name="caliptra-sw-v210",
                pinned_rev=self.gt.pinned_rev,
                target_dir=".",
                ablation_tier="full@discovery",
                tier_name="Mjolnir Full [discovery]",
                model="gemini-3.8-flash",
                repetition=1,
                is_checkpoint=True,
                findings=discovery_findings,
            ),
            TrialRunRecord(
                project_name="Caliptra SW (fw-2.1.0)",
                repo_name="caliptra-sw-v210",
                pinned_rev=self.gt.pinned_rev,
                target_dir=".",
                ablation_tier="full",
                tier_name="Mjolnir Full",
                model="gemini-3.8-flash",
                repetition=1,
                is_checkpoint=False,
                findings=final_findings,
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            eval_dir = Path(tmp)
            (eval_dir / "trials_manifest.json").write_text(
                json.dumps([t.model_dump(mode="json") for t in trials], indent=2),
                encoding="utf-8",
            )
            report = CveRecallEvaluator().evaluate_and_write(
                eval_dir=eval_dir,
                ground_truth_path=self.gt_path,
            )

            # Discovery checkpoint: 4/5 Tier A + 1/22 Tier B (SB-18) + 1/9 Tier C (SH-07) = 6/36
            t_disc = report.trials[0]
            self.assertEqual(t_disc.by_tier["A"].recalled_open, 4)
            self.assertEqual(t_disc.by_tier["B"].recalled_open, 1)
            self.assertEqual(t_disc.by_tier["A+B"].recalled_open, 5)
            self.assertEqual(t_disc.by_tier["C"].recalled_open, 1)
            self.assertEqual(t_disc.recalled_open, 6)

            # Final trial: 3/5 Tier A Open (1 PoC) + 1/22 Tier B Open + 0/9 Tier C Open = 4/36 Open (6/36 Any)
            t_final = report.trials[1]
            self.assertEqual(t_final.by_tier["A"].recalled_open, 3)
            self.assertEqual(t_final.by_tier["A"].recalled_poc_verified, 1)
            self.assertEqual(t_final.by_tier["B"].recalled_open, 1)
            self.assertEqual(t_final.by_tier["A+B"].recalled_open, 4)
            self.assertEqual(t_final.by_tier["C"].recalled_open, 0)
            self.assertEqual(t_final.by_tier["C"].recalled_any_status, 1)
            self.assertEqual(t_final.recalled_open, 4)
            self.assertEqual(t_final.recalled_any_status, 6)
            self.assertEqual(t_final.recalled_poc_verified, 1)

            by_cve_final = {r.cve_id: r for r in t_final.per_cve}
            self.assertEqual(
                by_cve_final["CVE-2026-7328"].matched_site_ids_open,
                ["cm_aes_gcm_decrypt_dma", "invoke_dpe_mldsa87"],
            )
            # SB-18 lives in cryptographic_mailbox.rs but must not false-match CVE-2026-7328
            self.assertEqual(
                len(by_cve_final["CVE-2026-7328"].same_file_unmatched),
                1,
            )
            self.assertTrue(by_cve_final["SB-18"].detected_open)
            self.assertFalse(by_cve_final["CVE-2026-11835"].detected_any_status)

            self.assertTrue((eval_dir / "cve_recall_results.json").exists())
            self.assertTrue((eval_dir / "cve_recall_scorecard.md").exists())
            self.assertTrue((eval_dir / "cve_recall_table.tex").exists())


if __name__ == "__main__":
    unittest.main()
