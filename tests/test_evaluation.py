# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for mjolnir-eval: phase-checkpoint extraction, transition counting, blind review pooling, Cohen's kappa, and RQ1-RQ4 scorecards."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "app"))
sys.path.insert(0, str(ROOT_DIR / "app" / "mjolnir"))

from evaluation.grader import (
    FindingPooler,
    build_github_permalink,
    compute_inter_rater_stats,
    compute_phase_transitions,
    extract_phase_checkpoint_findings,
    parse_line_range,
)
from evaluation.models import BlindReviewFinding, TrialRunRecord
from evaluation.runner import (
    format_model_slug,
    parse_usage_metrics,
)
from evaluation.scorecard import ScorecardGenerator


class TestEvaluationHarness(unittest.TestCase):
    def _sample_vulnerabilities(self) -> list[dict]:
        return [
            {
                "id": "v-true-bug",
                "file": "sw/device/silicon_creator/rom_ext/rom_ext.c",
                "location": "rom_ext_verify (Line 128)",
                "cwe": "CWE-252",
                "severity": "Critical",
                "status": "Open",
                "title": "Unchecked signature verification status",
                "description": "Return status of sigverify is ignored on error path.",
                "poc_verified": True,
                "history": [
                    {
                        "phase_id": "discovery",
                        "status": "Open",
                        "severity": "High",
                        "cwe": "CWE-252",
                        "title": "Unchecked signature verification status",
                        "description": "Return status of sigverify is ignored.",
                        "location": "rom_ext_verify (Line 128)",
                    },
                    {
                        "phase_id": "deduplication",
                        "status": "Open",
                        "severity": "High",
                        "cwe": "CWE-252",
                        "is_duplicate": False,
                    },
                    {
                        "phase_id": "initial_review",
                        "status": "Open",
                        "verdict": "confirmed",
                        "severity": "High",
                        "cwe": "CWE-252",
                    },
                    {
                        "phase_id": "poc_creation",
                        "status": "Open",
                        "severity": "High",
                        "poc_verified": True,
                    },
                    {
                        "phase_id": "final_review",
                        "status": "Open",
                        "severity": "Critical",
                        "cwe": "CWE-252",
                    },
                ],
            },
            {
                "id": "v-false-alarm-closed-in-ir",
                "file": "sw/device/silicon_creator/rom_ext/rom_ext.c",
                "location": "rom_ext_init (Line 40)",
                "cwe": "CWE-190",
                "severity": "Medium",
                "status": "Closed",
                "title": "Spurious overflow claim",
                "description": "Counter is bounded by constant.",
                "history": [
                    {
                        "phase_id": "discovery",
                        "status": "Open",
                        "severity": "High",
                        "cwe": "CWE-190",
                    },
                    {
                        "phase_id": "deduplication",
                        "status": "Open",
                        "severity": "High",
                        "is_duplicate": False,
                    },
                    {
                        "phase_id": "initial_review",
                        "status": "Closed",
                        "verdict": "disproven",
                        "severity": "Medium",
                    },
                ],
            },
            {
                "id": "v-duplicate",
                "file": "sw/device/silicon_creator/rom_ext/sigverify_helper.c",
                "location": "sigverify_helper (Line 310)",
                "cwe": "CWE-252",
                "severity": "High",
                "status": "Duplicate",
                "duplicate_of": "v-true-bug",
                "title": "Duplicate sigverify finding in helper",
                "description": "Duplicate of v-true-bug across file boundary.",
                "history": [
                    {
                        "phase_id": "discovery",
                        "status": "Open",
                        "severity": "High",
                        "cwe": "CWE-252",
                    },
                    {
                        "phase_id": "deduplication",
                        "status": "Duplicate",
                        "duplicate_of": "v-true-bug",
                        "severity": "High",
                        "is_duplicate": True,
                    },
                ],
            },
        ]

    def test_extract_phase_checkpoint_findings(self) -> None:
        vulns = self._sample_vulnerabilities()

        at_disc = extract_phase_checkpoint_findings(vulns, "discovery")
        open_disc = [v for v in at_disc if v["status"].lower() == "open"]
        self.assertEqual(len(open_disc), 3)
        self.assertEqual(at_disc[0]["severity"], "High")
        self.assertFalse(at_disc[0].get("poc_verified"))

        at_dedup = extract_phase_checkpoint_findings(vulns, "deduplication")
        open_dedup = [v for v in at_dedup if v["status"].lower() == "open"]
        self.assertEqual(len(open_dedup), 2)

        at_ir = extract_phase_checkpoint_findings(vulns, "initial_review")
        open_ir = [v for v in at_ir if v["status"].lower() == "open"]
        self.assertEqual(len(open_ir), 1)
        self.assertEqual(open_ir[0]["id"], "v-true-bug")
        self.assertEqual(open_ir[0]["severity"], "High")
        self.assertFalse(open_ir[0].get("poc_verified"))

        at_final = extract_phase_checkpoint_findings(vulns, "final_review")
        open_final = [v for v in at_final if v["status"].lower() == "open"]
        self.assertEqual(len(open_final), 1)
        self.assertEqual(open_final[0]["severity"], "Critical")
        self.assertTrue(open_final[0].get("poc_verified"))

    def test_compute_phase_transitions(self) -> None:
        vulns = self._sample_vulnerabilities()
        transitions = {pt.phase_id: pt for pt in compute_phase_transitions(vulns)}

        self.assertEqual(transitions["discovery"].entering_count, 3)
        self.assertEqual(transitions["deduplication"].entering_count, 3)
        self.assertEqual(transitions["deduplication"].duplicate_count, 1)
        self.assertEqual(transitions["deduplication"].surviving_open_count, 2)

        self.assertEqual(transitions["initial_review"].entering_count, 2)
        self.assertEqual(transitions["initial_review"].closed_count, 1)
        self.assertEqual(transitions["initial_review"].surviving_open_count, 1)

        self.assertEqual(transitions["poc_creation"].poc_verified_count, 1)
        self.assertEqual(transitions["final_review"].entering_count, 1)
        self.assertEqual(transitions["final_review"].severity_upgraded_count, 1)
        self.assertEqual(transitions["final_review"].severity_transitions.get("High->Critical"), 1)

    def test_finding_pooler_per_finding_deck_and_intra_run_funnel(self) -> None:
        vulns = self._sample_vulnerabilities()
        disc_vulns = extract_phase_checkpoint_findings(vulns, "discovery")

        claude_vulns = [
            {
                "id": "cli-1",
                "file": "sw/device/silicon_creator/rom_ext/rom_ext.c",
                "location": "rom_ext_verify (Line 125)",
                "cwe": "CWE-252",
                "severity": "High",
                "status": "Open",
                "title": "[Claude] Unchecked signature verification return status",
                "description": "The return status of sigverify is ignored on error path.",
                "history": [],
            },
            {
                "id": "cli-2",
                "file": "sw/device/silicon_creator/rom_ext/rom_ext.c",
                "location": "rom_ext_verify (Line 129)",
                "cwe": "CWE-476",
                "severity": "Medium",
                "status": "Open",
                "title": "Null pointer dereference on manifest pointer",
                "description": "Manifest pointer may be dereferenced when null.",
                "history": [],
            },
        ]

        trials = [
            TrialRunRecord(
                project_name="OpenTitan",
                repo_name="opentitan",
                pinned_rev="c5a58fb8ad7b9e6c19164546a5e492975a77c464",
                target_dir="sw/device/silicon_creator/rom_ext",
                ablation_tier="full",
                tier_name="Mjolnir Full (TM + Expert + PoC)",
                repetition=1,
                wall_clock_seconds=45.0,
                total_tokens=120000,
                cached_tokens=90000,
                uncached_input_tokens=20000,
                output_tokens=10000,
                total_reported_findings=len(vulns),
                open_findings_count=1,
                poc_verified_count=1,
                phase_transitions=compute_phase_transitions(vulns),
                findings=vulns,
            ),
            TrialRunRecord(
                project_name="OpenTitan",
                repo_name="opentitan",
                pinned_rev="c5a58fb8ad7b9e6c19164546a5e492975a77c464",
                target_dir="sw/device/silicon_creator/rom_ext",
                ablation_tier="full@discovery",
                tier_name="Mjolnir Full (TM + Expert + PoC) [discovery]",
                repetition=1,
                is_checkpoint=True,
                wall_clock_seconds=45.0,
                total_tokens=120000,
                cached_tokens=90000,
                uncached_input_tokens=20000,
                output_tokens=10000,
                total_reported_findings=len(disc_vulns),
                open_findings_count=3,
                poc_verified_count=0,
                findings=disc_vulns,
            ),
            TrialRunRecord(
                project_name="OpenTitan",
                repo_name="opentitan",
                pinned_rev="c5a58fb8ad7b9e6c19164546a5e492975a77c464",
                target_dir="sw/device/silicon_creator/rom_ext",
                ablation_tier="holistic",
                tier_name="Single-Agent Baseline (Whole-Directory, +TM)",
                repetition=1,
                wall_clock_seconds=30.0,
                total_reported_findings=2,
                open_findings_count=2,
                findings=claude_vulns,
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "trials_manifest.json").write_text(
                json.dumps([t.model_dump() for t in trials], indent=2),
                encoding="utf-8",
            )
            pooler = FindingPooler()
            pool = pooler.build_pool(trials=trials, output_dir=out_dir)

            # Verbatim per-finding pool: 3 findings from full + 2 findings from holistic = 5 items (no cross-tool clustering)
            self.assertEqual(len(pool), 5)
            by_fid = {(bf.ablation_tier, bf.finding_id): bf for bf in pool}
            # Closed finding must preserve its original @discovery Open writeup severity ("High"), not disproven ("Medium")
            self.assertEqual(by_fid[("full", "v-false-alarm-closed-in-ir")].severity, "High")
            self.assertEqual(
                by_fid[("full", "v-true-bug")].source_url,
                "https://github.com/lowRISC/opentitan/blob/c5a58fb8ad7b9e6c19164546a5e492975a77c464/sw/device/silicon_creator/rom_ext/rom_ext.c#L128",
            )

            # Label all CWE-252 findings as TP (including v-duplicate) and CWE-190 / CWE-476 as FP
            for bf in pool:
                if bf.cwe == "CWE-252":
                    bf.reviewer_1_label = "TP"
                    bf.reviewer_2_label = "TP"
                    bf.adjudicated_label = "TP"
                else:
                    bf.reviewer_1_label = "FP"
                    bf.reviewer_2_label = "FP"
                    bf.adjudicated_label = "FP"

            (out_dir / "blind_review_pool.json").write_text(
                json.dumps([c.model_dump() for c in pool], indent=2),
                encoding="utf-8",
            )

            # Re-pooling must preserve existing human labels by (ablation_tier, repetition, finding_id)
            repool = pooler.build_pool(trials=trials, output_dir=out_dir)
            tp_items = [c for c in repool if c.resolved_label == "TP"]
            self.assertEqual(len(tp_items), 3)
            self.assertTrue((out_dir / "blind_review" / "metadata.json").exists())
            self.assertTrue((out_dir / "blind_review" / "vulnerabilities.json").exists())

            ir_stats = compute_inter_rater_stats(repool)
            self.assertEqual(ir_stats.double_reviewed_count, 5)
            self.assertEqual(ir_stats.raw_agreement_rate, 1.0)
            self.assertEqual(ir_stats.cohens_kappa, 1.0)

            summaries = ScorecardGenerator().generate_scorecard(out_dir)
            by_tier = {s.ablation_tier: s for s in summaries}

            # Full Mjolnir kept v-true-bug (TP), closed v-false-alarm-closed-in-ir (FP),
            # and deduplicated v-duplicate (TP -> duplicate_of v-true-bug, so NOT a false disproof!)
            self.assertEqual(by_tier["full"].precision_mean, 1.0)
            self.assertEqual(by_tier["full"].mean_true_positives, 1.0)
            self.assertEqual(by_tier["full"].mean_false_positives, 0.0)
            self.assertEqual(by_tier["full"].fp_elimination_rate_mean, 1.0)
            self.assertEqual(by_tier["full"].false_disproof_rate_mean, 0.0)
            self.assertEqual(by_tier["full"].min_open_findings, 1)
            self.assertEqual(by_tier["full"].max_open_findings, 1)
            # At discovery, 3 open findings (2 TP, 1 FP) -> 66.7% precision
            self.assertEqual(by_tier["full@discovery"].mean_open_findings, 3.0)
            self.assertAlmostEqual(
                by_tier["full@discovery"].precision_mean or 0.0, 2.0 / 3.0, places=4
            )
            # Phase checkpoints do not report per-run wall-clock time
            self.assertIsNone(by_tier["full@discovery"].mean_wall_clock_seconds)
            self.assertEqual(by_tier["full"].mean_wall_clock_seconds, 45.0)
            self.assertAlmostEqual(
                ScorecardGenerator._estimate_cost_usd(
                    1_000_000, 1_000_000, 1_000_000, model="gemini-3.8-flash"
                )
                or 0.0,
                0.75 + 0.075 + 3.75,
                places=6,
            )
            self.assertAlmostEqual(
                ScorecardGenerator._estimate_cost_usd(
                    1_000_000, 1_000_000, 1_000_000, model="gemini-4-argon"
                )
                or 0.0,
                2.00 + 0.10 + 10.00,
                places=6,
            )
            self.assertIsNone(
                ScorecardGenerator._estimate_cost_usd(
                    1000, 1000, 1000, model="nonexistent-model-xyz"
                )
            )
            self.assertEqual(by_tier["full"].severity_distribution_mean.get("Critical"), 1.0)
            self.assertEqual(by_tier["full"].mean_open_unverified, 0.0)

            # Holistic baseline had 1 TP and 1 FP -> 50% precision
            self.assertEqual(by_tier["holistic"].precision_mean, 0.5)

    def test_usage_parsing(self) -> None:
        usage_with_phases = {
            "total": {
                "prompt_tokens": 110000,
                "cache_tokens": 90000,
                "uncached_tokens": 20000,
                "total_output_tokens": 10000,
                "total_tokens": 120000,
            },
            "by_phase": {
                "project_exploration": {
                    "prompt_tokens": 20000,
                    "cache_tokens": 10000,
                    "uncached_tokens": 10000,
                    "total_output_tokens": 2000,
                    "total_tokens": 22000,
                },
                "discovery": {
                    "prompt_tokens": 30000,
                    "cache_tokens": 25000,
                    "uncached_tokens": 5000,
                    "total_output_tokens": 3000,
                    "total_tokens": 33000,
                },
                "deduplication": {
                    "prompt_tokens": 10000,
                    "cache_tokens": 8000,
                    "uncached_tokens": 2000,
                    "total_output_tokens": 1000,
                    "total_tokens": 11000,
                },
                "initial_review": {
                    "prompt_tokens": 20000,
                    "cache_tokens": 18000,
                    "uncached_tokens": 2000,
                    "total_output_tokens": 2000,
                    "total_tokens": 22000,
                },
                "poc_creation": {
                    "prompt_tokens": 20000,
                    "cache_tokens": 19000,
                    "uncached_tokens": 1000,
                    "total_output_tokens": 1000,
                    "total_tokens": 21000,
                },
                "final_review": {
                    "prompt_tokens": 10000,
                    "cache_tokens": 10000,
                    "uncached_tokens": 0,
                    "total_output_tokens": 1000,
                    "total_tokens": 11000,
                },
            },
        }
        tot, cached, uncached, out = parse_usage_metrics(usage_with_phases)
        self.assertEqual(tot, 120000)
        self.assertEqual(cached, 90000)
        self.assertEqual(uncached, 20000)
        self.assertEqual(out, 10000)

        # Checkpoint at discovery should equal project_exploration + discovery = 55000
        tot_d, cac_d, unc_d, out_d = parse_usage_metrics(
            usage_with_phases, checkpoint_phase="discovery"
        )
        self.assertEqual(tot_d, 55000)
        self.assertEqual(cac_d, 35000)
        self.assertEqual(unc_d, 15000)
        self.assertEqual(out_d, 5000)

        # Checkpoint at initial_review (Fast pipeline) should equal exploration + discovery + dedup + initial_review = 88000
        tot_ir, _, _, _ = parse_usage_metrics(usage_with_phases, checkpoint_phase="initial_review")
        self.assertEqual(tot_ir, 88000)

    def test_orphan_snapshot_builder_single_commit_integrity(self) -> None:
        from evaluation.sandbox.orphan_snapshot import OrphanSnapshotBuilder

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src_dir = tmp_path / "src_repo"
            src_dir.mkdir()
            (src_dir / "lib.rs").write_text("pub fn verify() -> bool { true }\n", encoding="utf-8")

            builder = OrphanSnapshotBuilder(cache_root=tmp_path / "cache")
            snap_dir = builder.materialize_orphan_snapshot(
                baseline_dir=src_dir,
                dest_dir=tmp_path / "snapshot",
            )
            self.assertTrue((snap_dir / ".git").exists())
            self.assertTrue((snap_dir / "lib.rs").exists())

    def test_sast_scoping_and_trial_artifacts(self) -> None:
        from evaluation.runner import EvaluationRunner

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            snap_dir = tmp_path / "workspace"
            (snap_dir / "rom" / "src").mkdir(parents=True)
            (snap_dir / "rom" / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            (snap_dir / "rom" / "src" / "main_test.rs").write_text(
                "fn test() {}\n", encoding="utf-8"
            )
            (snap_dir / "other" / "src").mkdir(parents=True)
            (snap_dir / "other" / "src" / "lib.rs").write_text("pub fn x() {}\n", encoding="utf-8")

            spec = {
                "project": {
                    "name": "TestProj",
                    "repoName": "test-proj",
                    "repoUrl": "https://example.com/test.git",
                    "pinnedRev": "abcdef1234567890",
                    "targetDir": "rom/src",
                    "extensions": ["rs"],
                    "excludeDirs": ["tests"],
                    "excludePatterns": ["*_test.rs"],
                },
                "config": {},
            }
            runner = EvaluationRunner(
                spec=spec,
                output_root=tmp_path / "out",
                cache_root=tmp_path / "cache",
            )
            in_scope = runner._get_in_scope_files(snap_dir)
            self.assertEqual(in_scope, {"rom/src/main.rs"})

            trial_out = tmp_path / "trial_out"
            trial_out.mkdir()
            runner._write_trial_artifacts(
                trial_out_dir=trial_out,
                tier_key="per_file_no_tm",
                tier_cfg={"name": "Single-Agent (Per-File, No TM)"},
                vulns_data=[
                    {
                        "id": "VULN-001",
                        "file": "rom/src/main.rs",
                        "location": "Line 1",
                        "cwe": "CWE-190",
                        "title": "Integer overflow test",
                        "description": "Test finding",
                        "severity": "Medium",
                        "status": "Open",
                        "history": [],
                    }
                ],
            )
            self.assertTrue((trial_out / "metadata.json").exists())
            self.assertTrue((trial_out / "vulnerabilities.json").exists())
            self.assertTrue((trial_out / "vulnerabilities_minimal.json").exists())

            # Verify multi-model parsing and slug formatting
            multi_runner = EvaluationRunner(
                spec=spec,
                output_root=tmp_path / "out",
                cache_root=tmp_path / "cache",
                evaluator_model="gemini-3.8-flash,gemini-4-argon,vertex_ai/claude-sonnet-5-5@20260514",
            )
            self.assertEqual(
                multi_runner.evaluator_models,
                ["gemini-3.8-flash", "gemini-4-argon", "vertex_ai/claude-sonnet-5-5@20260514"],
            )
            self.assertEqual(
                format_model_slug("vertex_ai/claude-sonnet-5-5@20260514"), "claude-sonnet-5-5"
            )

    def test_cross_model_consistency_and_litellm_token_tracking(self) -> None:
        from types import SimpleNamespace
        from providers.adk.utilities.usage_tracker import UsageTracker

        tracker = UsageTracker()
        # 1. Gemini event where candidates_token_count (200) and thoughts_token_count (300) sum to 500 output
        gemini_ev = SimpleNamespace(
            author="AuditorAgent",
            branch="AuditorAgent@file1.rs",
            node_name="discovery_phase",
            model_version="gemini-3.8-flash",
            usage_metadata=SimpleNamespace(
                prompt_token_count=1000,
                candidates_token_count=200,
                cached_content_token_count=600,
                thoughts_token_count=300,
                total_token_count=1500,
            ),
        )
        tracker.track_event(gemini_ev)
        self.assertEqual(tracker.total_usage["total_tokens"], 1500)
        self.assertEqual(tracker.total_usage["total_output_tokens"], 500)
        self.assertEqual(tracker.usage_by_phase["discovery"]["total_tokens"], 1500)

        # 2. LiteLLM (Claude/OpenAI) event where candidates_token_count (500) already includes reasoning_tokens (300)
        litellm_ev = SimpleNamespace(
            author="AdversarialReviewerAgent",
            branch="AdversarialReviewerAgent@initial_review_v1",
            node_name="initial_review_phase",
            model_version="vertex_ai/claude-sonnet-5-5",
            usage_metadata=SimpleNamespace(
                prompt_token_count=1000,
                candidates_token_count=500,
                cached_content_token_count=400,
                thoughts_token_count=300,
                total_token_count=1500,
            ),
        )
        tracker.track_event(litellm_ev)
        # Total should be 1500 + 1500 = 3000 (not 3300!)
        self.assertEqual(tracker.total_usage["total_tokens"], 3000)
        self.assertEqual(tracker.usage_by_phase["initial_review"]["total_tokens"], 1500)

        # 3. Cross-model consistency across 3 models on same target
        f_shared = {
            "id": "v1",
            "file": "runtime/src/verify.rs",
            "location": "Line 42",
            "cwe": "CWE-252",
            "severity": "Critical",
            "status": "Open",
            "title": "Unchecked verify status",
            "description": "Signature status unchecked.",
            "history": [],
        }
        f_extra = {
            "id": "v2",
            "file": "runtime/src/stash.rs",
            "location": "Line 88",
            "cwe": "CWE-787",
            "severity": "High",
            "status": "Open",
            "title": "Out of bounds write in stash",
            "description": "Index unchecked.",
            "history": [],
        }
        trials = [
            TrialRunRecord(
                project_name="Caliptra",
                repo_name="caliptra-sw",
                pinned_rev="262470b",
                target_dir="runtime/src",
                ablation_tier="full[gemini-3.8-flash]",
                tier_name="Mjolnir Full (gemini-3.8-flash)",
                model="gemini-3.8-flash",
                repetition=1,
                open_findings_count=1,
                total_reported_findings=1,
                findings=[f_shared],
            ),
            TrialRunRecord(
                project_name="Caliptra",
                repo_name="caliptra-sw",
                pinned_rev="262470b",
                target_dir="runtime/src",
                ablation_tier="full[gemini-4-argon]",
                tier_name="Mjolnir Full (gemini-4-argon)",
                model="gemini-4-argon",
                repetition=1,
                open_findings_count=2,
                total_reported_findings=2,
                findings=[f_shared, f_extra],
            ),
            TrialRunRecord(
                project_name="Caliptra",
                repo_name="caliptra-sw",
                pinned_rev="262470b",
                target_dir="runtime/src",
                ablation_tier="full[claude-sonnet-5-5]",
                tier_name="Mjolnir Full (claude-sonnet-5-5)",
                model="vertex_ai/claude-sonnet-5-5",
                repetition=1,
                open_findings_count=2,
                total_reported_findings=2,
                findings=[f_shared, f_extra],
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            (out_dir / "trials_manifest.json").write_text(
                json.dumps([t.model_dump() for t in trials], indent=2), encoding="utf-8"
            )
            summaries = ScorecardGenerator().generate_scorecard(out_dir)
            by_tier = {s.ablation_tier: s for s in summaries}
            self.assertEqual(by_tier["full[gemini-3.8-flash]"].mean_open_findings, 1.0)
            self.assertEqual(by_tier["full[gemini-4-argon]"].mean_open_findings, 2.0)
            self.assertEqual(by_tier["full[claude-sonnet-5-5]"].mean_open_findings, 2.0)
            sc_json = json.loads((out_dir / "scorecard.json").read_text(encoding="utf-8"))
            self.assertNotIn("cross_model_consistency", sc_json)

    def test_vanilla_baseline_instruction_and_in_scope_resolution(self) -> None:
        from evaluation.constants import ABLATION_TIERS
        from evaluation.runner import (
            EvaluationRunner,
            VANILLA_HOLISTIC_TOOLS,
            build_vanilla_baseline_instruction,
        )

        # Verify all 4 controlled single-agent baseline tiers are registered
        for tk in ("holistic_no_tm", "holistic", "per_file_no_tm", "per_file"):
            self.assertIn(tk, ABLATION_TIERS)
            self.assertEqual(ABLATION_TIERS[tk]["runner"], "vanilla_agent")

        # Verify tool names are standard coding-agent primitives without custom Mjolnir tools
        tool_names = [t.__name__ for t in VANILLA_HOLISTIC_TOOLS]
        self.assertEqual(tool_names, ["glob", "read_file", "grep_search"])
        for t in VANILLA_HOLISTIC_TOOLS:
            self.assertNotIn("ctags_search", t.__doc__ or "")
            self.assertNotIn("ast_search", t.__doc__ or "")

        inst_no_tm = build_vanilla_baseline_instruction(threat_model_context="", has_tools=False)
        self.assertIn("Audit Guidelines:", inst_no_tm)
        self.assertNotIn("Available File-Browsing Tools:", inst_no_tm)
        self.assertNotIn("Project Threat Model Context", inst_no_tm)

        inst_dir_tm = build_vanilla_baseline_instruction(
            threat_model_context="DPE commands are untrusted.", has_tools=True
        )
        self.assertIn("Available File-Browsing Tools:", inst_dir_tm)
        self.assertIn("DPE commands are untrusted.", inst_dir_tm)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runner = EvaluationRunner(
                spec={
                    "project": {
                        "name": "Caliptra",
                        "repoName": "caliptra-sw",
                        "repoUrl": "https://example.com/caliptra.git",
                        "targetDir": "runtime/src",
                    },
                    "config": {},
                },
                output_root=tmp_path / "out",
                cache_root=tmp_path / "cache",
            )
            in_scope = {"runtime/src/invoke_dpe.rs", "runtime/src/stash_measurement.rs"}
            self.assertEqual(
                runner._resolve_in_scope_file(
                    "invoke_dpe.rs:142", tmp_path, in_scope, fallback_file="runtime/src"
                ),
                "runtime/src/invoke_dpe.rs",
            )
            self.assertIsNone(
                runner._resolve_in_scope_file(
                    "runtime/tests/integration_test.rs",
                    tmp_path,
                    in_scope,
                    fallback_file="runtime/src",
                )
            )

    def test_verbatim_pool_file_grouping_horvitz_thompson_and_stability_label_sync(self) -> None:
        self.assertEqual(
            parse_line_range("AddSubjectAltNameCmd::execute (L28-50); dispatch (~L422)"),
            (28, 50),
        )
        self.assertEqual(parse_line_range("SyntheticModule::handle_request"), (None, None))
        self.assertEqual(
            build_github_permalink(
                repo_name="caliptra-sw",
                pinned_rev="262470b01990",
                file_path="runtime/src/alpha.rs",
                start_line=10,
                end_line=25,
            ),
            "https://github.com/chipsalliance/caliptra-sw/blob/262470b01990/runtime/src/alpha.rs#L10-L25",
        )

        rep1 = TrialRunRecord(
            project_name="Caliptra SW",
            repo_name="caliptra-sw",
            pinned_rev="262470b",
            target_dir="runtime/src",
            ablation_tier="full",
            tier_name="Mjolnir Full",
            model="gemini-3.8-flash",
            repetition=1,
            wall_clock_seconds=10.0,
            open_findings_count=2,
            findings=[
                {
                    "id": "f1",
                    "file": "runtime/src/beta.rs",
                    "location": "runtime/src/beta.rs:40",
                    "cwe": "CWE-787",
                    "status": "Open",
                    "title": "Synthetic beta index check",
                    "description": "Synthetic test finding one.",
                    "history": [],
                },
                {
                    "id": "f2",
                    "file": "runtime/src/alpha.rs",
                    "location": "handle_alpha",
                    "cwe": "CWE-20",
                    "status": "Open",
                    "title": "Synthetic alpha length check",
                    "description": "Synthetic test finding two.",
                    "history": [],
                },
            ],
        )
        rep2 = TrialRunRecord(
            project_name="Caliptra SW",
            repo_name="caliptra-sw",
            pinned_rev="262470b",
            target_dir="runtime/src",
            ablation_tier="full",
            tier_name="Mjolnir Full",
            model="gemini-3.8-flash",
            repetition=2,
            wall_clock_seconds=10.0,
            open_findings_count=2,
            findings=[
                {
                    "id": "f3",
                    "file": "runtime/src/alpha.rs",
                    "location": "runtime/src/alpha.rs:10-25",
                    "cwe": "CWE-770",
                    "status": "Open",
                    "title": "Synthetic alpha counter check",
                    "description": "Synthetic test finding three.",
                    "history": [],
                },
                {
                    "id": "f4",
                    "file": "runtime/src/beta.rs",
                    "location": "runtime/src/beta.rs:55",
                    "cwe": "CWE-20",
                    "status": "Open",
                    "title": "Synthetic beta bounds check",
                    "description": "Synthetic test finding four.",
                    "history": [],
                },
            ],
        )
        rep4_stab = TrialRunRecord(
            project_name="Caliptra SW",
            repo_name="caliptra-sw",
            pinned_rev="262470b",
            target_dir="runtime/src",
            ablation_tier="full",
            tier_name="Mjolnir Full",
            model="gemini-3.8-flash",
            repetition=4,
            wall_clock_seconds=10.0,
            open_findings_count=1,
            findings=[
                {
                    "id": "f5",
                    "file": "runtime/src/alpha.rs",
                    "location": "SyntheticCmd::execute (L30-45)",
                    "cwe": "CWE-284",
                    "status": "Open",
                    "title": "Synthetic stability finding",
                    "description": "Extra stability run synthetic finding.",
                    "history": [],
                }
            ],
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pinned_dir = root / "pinned"
            stab_dir = root / "stability"
            pinned_dir.mkdir()
            stab_dir.mkdir()
            (pinned_dir / "trials_manifest.json").write_text(
                json.dumps([rep1.model_dump(), rep2.model_dump()], indent=2),
                encoding="utf-8",
            )
            (stab_dir / "trials_manifest.json").write_text(
                json.dumps(
                    [rep1.model_dump(), rep2.model_dump(), rep4_stab.model_dump()], indent=2
                ),
                encoding="utf-8",
            )

            pool = FindingPooler().build_pool(trials=[rep1, rep2], output_dir=pinned_dir)
            self.assertEqual(len(pool), 4)
            # Blind deck must be grouped deterministically by source file (alpha.rs before beta.rs)
            files_in_order = [bf.file for bf in pool]
            self.assertEqual(
                files_in_order,
                [
                    "runtime/src/alpha.rs",
                    "runtime/src/alpha.rs",
                    "runtime/src/beta.rs",
                    "runtime/src/beta.rs",
                ],
            )
            # Provenance-stripped web bundle must not leak ablation_tier or repetition
            web_vulns = json.loads(
                (pinned_dir / "blind_review" / "vulnerabilities.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(web_vulns), 4)
            self.assertNotIn("ablation_tier", web_vulns[0])
            self.assertNotIn("repetition", web_vulns[0])
            self.assertTrue(web_vulns[0]["source_url"].startswith("https://github.com/"))

            # Verify Horvitz-Thompson sampling_weight (sample 1 item per rep with w=2.0) + sibling stability sync
            for bf in pool:
                if bf.finding_id in ("f1", "f3"):
                    bf.in_blind_sample = True
                    bf.sampling_weight = 2.0
                    bf.adjudicated_label = "TP" if bf.finding_id == "f3" else "FP"
                else:
                    bf.in_blind_sample = False
                    bf.sampling_weight = 0.0
            (pinned_dir / "blind_review_pool.json").write_text(
                json.dumps([c.model_dump() for c in pool], indent=2),
                encoding="utf-8",
            )
            pinned_summaries = ScorecardGenerator().generate_scorecard(pinned_dir)
            # rep1 had weighted FP=2.0, rep2 had weighted TP=2.0 -> mean TP=1.0, mean FP=1.0, micro precision=0.5
            self.assertEqual(pinned_summaries[0].mean_true_positives, 1.0)
            self.assertEqual(pinned_summaries[0].mean_false_positives, 1.0)
            self.assertEqual(pinned_summaries[0].precision_mean, 0.5)

            # Stability scorecard inherits labels for shared rep1 & rep2 from ../pinned/blind_review_pool.json
            stab_summaries = ScorecardGenerator().generate_scorecard(stab_dir)
            self.assertEqual(stab_summaries[0].repetitions, 3)
            self.assertEqual(stab_summaries[0].min_open_findings, 1)
            self.assertEqual(stab_summaries[0].max_open_findings, 2)

    def test_harness_fixes_h1_to_h8_and_refusal_tracking(self) -> None:
        from types import SimpleNamespace
        from providers.adk.utilities.async_runner import is_safety_refusal_text
        from providers.adk.utilities.usage_tracker import UsageTracker
        from utilities.worktree_sandbox import REPRODUCE_SCRIPT_TEMPLATE

        # H8: Neutral reproducer exit message
        self.assertNotIn("VULNERABILITY REPRODUCED", REPRODUCE_SCRIPT_TEMPLATE)
        self.assertIn("COMMAND FAILED (exit code", REPRODUCE_SCRIPT_TEMPLATE)

        # H4 & H5: Dual-expert resolution + expert_severity / poc_demonstrates / exclude
        base_bf_kwargs = {
            "project_name": "Caliptra",
            "repo_name": "caliptra-sw",
            "pinned_rev": "262470b",
            "ablation_tier": "full",
            "repetition": 1,
            "location": "Line 10",
            "title": "Test finding",
            "description": "Test description",
        }
        single_labeled = BlindReviewFinding(
            review_id="BF-0001",
            finding_id="f1",
            file="a.rs",
            reviewer_1_label="TP",
            reviewer_2_label="",
            **base_bf_kwargs,
        )
        self.assertIsNone(single_labeled.resolved_label)

        disputed = BlindReviewFinding(
            review_id="BF-0002",
            finding_id="f2",
            file="b.rs",
            reviewer_1_label="TP",
            reviewer_2_label="FP",
            **base_bf_kwargs,
        )
        self.assertIsNone(disputed.resolved_label)

        agreed_med_tp = BlindReviewFinding(
            review_id="BF-0003",
            finding_id="f3",
            file="c.rs",
            reviewer_1_label="TP",
            reviewer_2_label="TP",
            expert_severity="high",
            poc_demonstrates="yes",
            **base_bf_kwargs,
        )
        agreed_low_tp = BlindReviewFinding(
            review_id="BF-0004",
            finding_id="f4",
            file="d.rs",
            adjudicated_label="TP",
            expert_severity="Low",
            poc_demonstrates="no",
            **base_bf_kwargs,
        )
        excluded_item = BlindReviewFinding(
            review_id="BF-0005",
            finding_id="f5",
            file="e.rs",
            reviewer_1_label="TP",
            reviewer_2_label="FP",
            adjudicated_label="exclude",
            **base_bf_kwargs,
        )
        self.assertEqual(agreed_med_tp.resolved_label, "TP")
        self.assertEqual(agreed_med_tp.normalized_expert_severity, "High")
        self.assertTrue(excluded_item.is_excluded)
        self.assertIsNone(excluded_item.resolved_label)
        ir = compute_inter_rater_stats(
            [single_labeled, disputed, agreed_med_tp, agreed_low_tp, excluded_item]
        )
        self.assertEqual(ir.total_findings, 5)
        self.assertEqual(ir.excluded_count, 1)
        self.assertEqual(ir.single_reviewed_count, 1)
        self.assertEqual(ir.disputed_unadjudicated_count, 1)
        self.assertEqual(ir.confirmed_tp_count, 2)
        self.assertEqual(ir.confirmed_tp_medium_or_above_count, 1)
        self.assertEqual(ir.expert_severity_counts["High"], 1)
        self.assertEqual(ir.expert_severity_counts["Low"], 1)
        self.assertEqual(ir.poc_demonstrates_counts, {"yes": 1, "no": 1})

        # H1 + Refusal tracking in UsageTracker & safety refusal classifier
        self.assertTrue(
            is_safety_refusal_text(
                "I cannot fulfill this request. I am unable to generate functional exploit payloads."
            )
        )
        self.assertFalse(
            is_safety_refusal_text(
                "After reviewing rom/src/i3c.rs, all bounds checks hold and no vulnerabilities were found."
            )
        )

        tracker = UsageTracker()
        tracker.track_event(
            SimpleNamespace(
                author="ExploitCreationAgent",
                branch="ExploitCreationAgent@poc_creation_v1",
                node_name="poc_creation_phase",
                model_version="gemini-3.8-flash",
                usage_metadata=SimpleNamespace(
                    prompt_token_count=500,
                    candidates_token_count=100,
                    cached_content_token_count=200,
                    thoughts_token_count=50,
                    total_token_count=650,
                ),
            )
        )
        tracker.track_tool_call(
            "run_harness_command",
            True,
            agent_name="ExploitCreationAgent",
            phase_id="poc_creation",
        )
        tracker.track_refusal(
            "hard_safety_refusals", agent_name="ExploitCreationAgent", phase_id="poc_creation"
        )
        tracker.track_refusal(
            "schema_validation_drops", agent_name="AuditorAgent", phase_id="discovery"
        )
        tracker.track_error(
            RuntimeError("SAFETY: The prompt is blocked due to safety"),
            agent_name="AdversarialReviewerAgent",
        )
        self.assertEqual(tracker.total_usage["llm_calls"], 1)
        self.assertEqual(tracker.usage_by_agent["ExploitCreationAgent"]["llm_calls"], 1)
        self.assertEqual(
            tracker.tool_usage_by_phase["poc_creation"]["run_harness_command"]["calls"], 1
        )
        self.assertEqual(tracker.refusal_counts["total_safety_refusals"], 2)
        self.assertEqual(tracker.refusal_counts["hard_safety_refusals"], 1)
        self.assertEqual(tracker.refusal_counts["api_safety_blocks"], 1)
        self.assertEqual(tracker.refusal_counts["schema_validation_drops"], 1)

        # H1 + H3 + H6 retroactive telemetry, None zero-denominator precision, and saturation labels
        with tempfile.TemporaryDirectory() as tmp:
            eval_dir = Path(tmp) / "caliptra-dpe" / "pinned"
            rep_dirs = [eval_dir / "trials" / "full" / f"rep_{r}" for r in range(1, 6)]
            trials_list = []
            for r_idx, r_dir in enumerate(rep_dirs, start=1):
                run_sub = r_dir / "run_001"
                run_sub.mkdir(parents=True)
                (run_sub / "token_usage.json").write_text(
                    json.dumps(
                        {
                            "total": {
                                "total_tokens": 1000,
                                "uncached_tokens": 600,
                                "cache_tokens": 200,
                                "total_output_tokens": 200,
                            },
                            "by_phase": {
                                "discovery": {
                                    "uncached_tokens": 600,
                                    "cache_tokens": 200,
                                    "total_output_tokens": 200,
                                }
                            },
                            "errors_grouped": ({"SAFETY: blocked": 1} if r_idx == 1 else {}),
                        }
                    ),
                    encoding="utf-8",
                )
                (run_sub / "tool_usage.json").write_text(
                    json.dumps(
                        {
                            "by_tool": {
                                "read_file": {"calls": 10, "failures": 0},
                                "ask_project_expert": {"calls": 3, "failures": 0},
                                "run_harness_command": {"calls": 4, "failures": 1},
                                "set_model_response": {"calls": 2, "failures": 0},
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                (run_sub / "reasoning_log.json").write_text(
                    json.dumps(
                        {
                            "expert_query_1": [
                                {
                                    "type": "thought",
                                    "agent": "ProjectExpertAgent",
                                    "content": "Recall",
                                },
                                {
                                    "type": "tool_call",
                                    "agent": "ProjectExpertAgent",
                                    "tool": "set_model_response",
                                    "args": {"answer": "ok"},
                                },
                            ],
                            "poc_creation_v1": (
                                [
                                    {
                                        "type": "output",
                                        "agent": "ExploitCreationAgent",
                                        "content": "I cannot fulfill this request. I am unable to generate functional exploit payloads.",
                                    }
                                ]
                                if r_idx == 1
                                else [
                                    {
                                        "type": "tool_call",
                                        "agent": "ExploitCreationAgent",
                                        "tool": "set_model_response",
                                        "args": {"poc_verified": True},
                                    }
                                ]
                            ),
                        }
                    ),
                    encoding="utf-8",
                )
                f_item = {
                    "id": "v1",
                    "file": "dpe/src/cmd.rs",
                    "location": "Line 10",
                    "cwe": "CWE-20",
                    "severity": "High",
                    "status": "Open",
                    "title": "Unchecked input",
                    "description": "Unchecked input.",
                    "poc_verified": False,
                    "history": [
                        {"phase_id": "poc_creation", "status": "Open", "poc_verified": False}
                    ],
                }
                (run_sub / "vulnerabilities.json").write_text(
                    json.dumps([f_item]), encoding="utf-8"
                )
                trials_list.append(
                    TrialRunRecord(
                        project_name="DPE",
                        repo_name="caliptra-dpe",
                        pinned_rev="7c210f1",
                        target_dir="dpe/src",
                        ablation_tier="full",
                        tier_name="Mjolnir Full",
                        model="gemini-3.8-flash",
                        repetition=r_idx,
                        wall_clock_seconds=12.0,
                        total_tokens=1000,
                        cached_tokens=200,
                        uncached_input_tokens=600,
                        output_tokens=200,
                        open_findings_count=1,
                        poc_verified_count=0,
                        findings=[f_item],
                    )
                )
            (eval_dir / "trials_manifest.json").write_text(
                json.dumps([t.model_dump() for t in trials_list], indent=2), encoding="utf-8"
            )
            summaries = ScorecardGenerator().generate_scorecard(eval_dir)
            s_full = summaries[0]
            # H3: Pool has 0 human labels -> precision_mean must be None (not 0.0)
            self.assertIsNone(s_full.precision_mean)
            self.assertIsNone(s_full.precision_std)
            # H1: Tool calls exclude set_model_response (10 + 3 + 4 = 17), 1 tool error, expert 2 cache + 1 zero-tool = 3 from history
            self.assertEqual(s_full.mean_tool_calls_per_run, 17.0)
            self.assertEqual(s_full.mean_tool_errors_per_run, 1.0)
            self.assertEqual(s_full.mean_project_expert_questions, 3.0)
            self.assertEqual(s_full.mean_project_expert_answered_from_history, 3.0)
            # Gate rejected poc_verified=True in reps 2..5 (4/5 = 0.8 mean gate failures)
            self.assertEqual(s_full.mean_poc_gate_failures, 0.8)
            # Refusal summary: 1 hard refusal + 1 API safety block = 2 total safety refusals
            sc_json = json.loads((eval_dir / "scorecard.json").read_text(encoding="utf-8"))
            self.assertEqual(sc_json["refusal_summary"]["total_safety_refusals"], 2)
            self.assertEqual(sc_json["refusal_summary"]["hard_safety_refusals"], 1)
            self.assertEqual(sc_json["refusal_summary"]["api_safety_blocks"], 1)
            # RQ3 table reports Min--Max Open without saturation curve files
            self.assertFalse((eval_dir / "plots" / "fig_rq3_saturation_curve.tex").exists())
            rq3_tex = (eval_dir / "tables" / "tab_rq3_consistency_stability.tex").read_text(
                encoding="utf-8"
            )
            self.assertIn("Min--Max Open", rq3_tex)
            self.assertIn("1--1", rq3_tex)

    def test_h11_poc_vs_unverified_precision_and_module_bazel_lock_ignore(self) -> None:
        from utilities.worktree_sandbox import WorktreeSandbox

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # 1. Verify WorktreeSandbox ignores MODULE.bazel.lock churn in get_diff, get_modified_files, and gate checks
            repo_dir = tmp_path / "repo"
            repo_dir.mkdir()
            (repo_dir / "MODULE.bazel.lock").write_text('{"CARGO_BAZEL_ISOLATED": "0"}\n')
            (repo_dir / "src").mkdir()
            (repo_dir / "src" / "lib.rs").write_text(
                "pub fn add(a: u32, b: u32) -> u32 { a + b }\n"
            )
            (repo_dir / "tests").mkdir()
            (repo_dir / "tests" / "poc_test.rs").write_text("#[test]\nfn smoke() {}\n")

            ws_dir = tmp_path / "ws"
            sb = WorktreeSandbox(repo_dir, ws_dir, "VULN-LOCK")
            sb.setup()
            try:
                # Simulate Bazel modifying MODULE.bazel.lock alongside a test file edit
                sb.write_file("MODULE.bazel.lock", '{"CARGO_BAZEL_ISOLATED": null}\n')
                sb.write_file("tests/poc_test.rs", "#[test]\nfn smoke() { assert_eq!(1, 1); }\n")
                self.assertEqual(sb.get_modified_files(), ["tests/poc_test.rs"])
                self.assertNotIn("MODULE.bazel.lock", sb.get_diff())
                self.assertEqual(sb.count_removed_baseline_lines(), 0)
                self.assertFalse(sb.has_production_code_modifications())
            finally:
                sb.cleanup()

            # 2. Verify H11: PoC-verified vs unverified open finding TP/FP and precision
            eval_dir = tmp_path / "eval_h11"
            eval_dir.mkdir()
            findings = [
                {
                    "id": "v_poc_tp",
                    "file": "src/a.rs",
                    "location": "Line 10",
                    "cwe": "CWE-20",
                    "severity": "High",
                    "status": "Open",
                    "title": "PoC TP",
                    "description": "PoC TP",
                    "poc_verified": True,
                    "history": [
                        {"phase_id": "poc_creation", "status": "Open", "poc_verified": True}
                    ],
                },
                {
                    "id": "v_poc_fp",
                    "file": "src/b.rs",
                    "location": "Line 20",
                    "cwe": "CWE-20",
                    "severity": "Medium",
                    "status": "Open",
                    "title": "PoC FP",
                    "description": "PoC FP",
                    "poc_verified": True,
                    "history": [
                        {"phase_id": "poc_creation", "status": "Open", "poc_verified": True}
                    ],
                },
                {
                    "id": "v_unver_fp",
                    "file": "src/c.rs",
                    "location": "Line 30",
                    "cwe": "CWE-20",
                    "severity": "Medium",
                    "status": "Open",
                    "title": "Unver FP",
                    "description": "Unver FP",
                    "poc_verified": False,
                    "history": [
                        {"phase_id": "poc_creation", "status": "Open", "poc_verified": False}
                    ],
                },
            ]
            t_rec = TrialRunRecord(
                project_name="OpenPRoT",
                repo_name="openprot",
                pinned_rev="abc1234",
                target_dir="services",
                ablation_tier="full",
                tier_name="Mjolnir Full",
                model="gemini-3.8-flash",
                repetition=1,
                wall_clock_seconds=10.0,
                total_tokens=1000,
                open_findings_count=3,
                poc_verified_count=2,
                findings=findings,
            )
            (eval_dir / "trials_manifest.json").write_text(
                json.dumps([t_rec.model_dump()], indent=2), encoding="utf-8"
            )
            pool = FindingPooler().build_pool([t_rec], eval_dir)
            for cf in pool:
                lbl = "TP" if cf.file == "src/a.rs" else "FP"
                cf.reviewer_1_label = lbl
                cf.reviewer_2_label = lbl
            (eval_dir / "blind_review_pool.json").write_text(
                json.dumps([c.model_dump() for c in pool], indent=2), encoding="utf-8"
            )
            summaries = ScorecardGenerator().generate_scorecard(eval_dir)
            s = summaries[0]
            self.assertEqual(s.mean_poc_verified_tps, 1.0)
            self.assertEqual(s.mean_poc_verified_fps, 1.0)
            self.assertEqual(s.poc_verified_precision_mean, 0.5)
            self.assertEqual(s.mean_open_unverified_tps, 0.0)
            self.assertEqual(s.mean_open_unverified_fps, 1.0)
            self.assertEqual(s.open_unverified_precision_mean, 0.0)
            meta = json.loads(
                (eval_dir / "tables" / "tables_metadata.json").read_text(encoding="utf-8")
            )
            ts = meta["tiers_summary"][0]
            self.assertEqual(ts["mean_poc_verified_tps"], 1.0)
            self.assertEqual(ts["mean_poc_verified_fps"], 1.0)
            self.assertEqual(ts["poc_verified_precision_mean"], 0.5)
            self.assertEqual(ts["mean_open_unverified_tps"], 0.0)
            self.assertEqual(ts["mean_open_unverified_fps"], 1.0)
            self.assertEqual(ts["open_unverified_precision_mean"], 0.0)

    def test_usage_tracker_expert_subquery_phase_attribution(self):
        from providers.adk.utilities.usage_tracker import UsageTracker

        tracker = UsageTracker()
        # Phase 1 exploration stays in project_exploration
        self.assertEqual(
            tracker._resolve_phase_id(object(), "ProjectExpertAgent", "project_exploration"),
            "project_exploration",
        )
        # Even before ev.node_name updates _current_phase, Discovery ask_project_expert sub-branches
        # (<file_path>.ProjectExpertAgent@expert_query_<id>) must resolve to discovery
        self.assertEqual(
            tracker._resolve_phase_id(
                object(),
                "ProjectExpertAgent",
                "runtime/src/manifest.rs.ProjectExpertAgent@expert_query_89c513e4",
            ),
            "discovery",
        )
        # Review and PoC sub-branches resolve to their caller phases
        self.assertEqual(
            tracker._resolve_phase_id(
                object(),
                "ProjectExpertAgent",
                "initial_review_v1.ProjectExpertAgent@expert_query_11111111",
            ),
            "initial_review",
        )
        self.assertEqual(
            tracker._resolve_phase_id(
                object(),
                "ProjectExpertAgent",
                "poc_creation_v1.ProjectExpertAgent@expert_query_22222222",
            ),
            "poc_creation",
        )
        self.assertEqual(
            tracker._resolve_phase_id(
                object(),
                "ProjectExpertAgent",
                "final_review_v1.ProjectExpertAgent@expert_query_33333333",
            ),
            "final_review",
        )
        # Explicit set_phase updates _current_phase immediately on phase entry
        tracker.set_phase("discovery")
        self.assertEqual(
            tracker._resolve_phase_id(object(), "ProjectExpertAgent", "expert_query_standalone"),
            "discovery",
        )

    def test_import_reviewer_labels_adjudication_template_and_pass2_deck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            eval_dir = Path(tmp) / "caliptra-sw" / "pinned"
            eval_dir.mkdir(parents=True)
            src_dir = Path(tmp) / "fake_src" / "runtime" / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "stash.rs").write_text(
                "\n".join(f"fn line_{i}() {{}}" for i in range(1, 40)), encoding="utf-8"
            )

            trial = TrialRunRecord(
                project_name="Caliptra",
                repo_name="caliptra-sw",
                pinned_rev="262470b019905e8ea307be63860730d64c35d436",
                target_dir="runtime",
                ablation_tier="full",
                tier_name="Mjolnir Full",
                model="gemini-3.8-flash",
                repetition=1,
                wall_clock_seconds=5.0,
                open_findings_count=2,
                poc_verified_count=1,
                findings=[
                    {
                        "id": "v1",
                        "file": "runtime/src/stash.rs",
                        "location": "Lines 5-10",
                        "cwe": "CWE-20",
                        "severity": "High",
                        "status": "Open",
                        "poc_verified": True,
                        "poc": "cargo test stash_overflow",
                        "title": "Stash bounds overflow",
                        "description": "Missing bounds check.",
                    },
                    {
                        "id": "v2",
                        "file": "runtime/src/stash.rs",
                        "location": "Lines 15-20",
                        "cwe": "CWE-284",
                        "severity": "Medium",
                        "status": "Open",
                        "poc_verified": False,
                        "title": "Disputed access check",
                        "description": "Disputed finding.",
                    },
                ],
            )
            (eval_dir / "trials_manifest.json").write_text(
                json.dumps([trial.model_dump()], indent=2), encoding="utf-8"
            )
            FindingPooler().build_pool([trial], eval_dir)
            pool = FindingPooler().sample_blind_pool(
                eval_dir=eval_dir,
                seed="unit-test-seed",
                source_root=Path(tmp) / "fake_src",
            )
            by_title = {bf.title: bf.review_id for bf in pool}
            rid_tp = by_title["Stash bounds overflow"]
            rid_disp = by_title["Disputed access check"]

            r1_file = Path(tmp) / "r1.json"
            r2_file = Path(tmp) / "r2.json"
            r1_file.write_text(
                json.dumps(
                    {
                        "reviewer_ldap": "alice",
                        "reviews": {
                            rid_tp: {"verdict": "TP", "expert_severity": "High"},
                            rid_disp: {
                                "verdict": "TP",
                                "expert_severity": "Medium",
                                "notes": "looks reachable",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            r2_file.write_text(
                json.dumps(
                    {
                        "reviewer_ldap": "bob",
                        "reviews": {
                            rid_tp: {"verdict": "TP", "expert_severity": "High"},
                            rid_disp: {"verdict": "FP", "notes": "guarded by caller"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            stats1 = FindingPooler.import_reviewer_labels(
                eval_dir, r1_path=r1_file, r2_path=r2_file
            )
            self.assertEqual(stats1.disputed_unadjudicated_count, 1)
            adj_tpl = json.loads(
                (eval_dir / "blind_review" / "adjudication_template.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(adj_tpl["disputed_count"], 1)
            self.assertIn(rid_disp, adj_tpl["reviews"])

            # Referee resolves dispute -> disputed_unadjudicated drops to 0
            adj_tpl["reviews"][rid_disp]["verdict"] = "FP"
            adj_filled = Path(tmp) / "adj_filled.json"
            adj_filled.write_text(json.dumps(adj_tpl), encoding="utf-8")
            stats2 = FindingPooler.import_reviewer_labels(eval_dir, adjudication_path=adj_filled)
            self.assertEqual(stats2.disputed_unadjudicated_count, 0)
            self.assertEqual(stats2.confirmed_tp_count, 1)
            self.assertEqual(stats2.confirmed_fp_count, 1)

            # Build Pass-2 PoC deck -> only the 1 confirmed TP with poc_verified=True appears
            p2_deck = FindingPooler.write_pass2_poc_spa_deck(
                eval_dir=eval_dir,
                out_path=eval_dir / "blind_review" / "pass2_poc_deck.json",
                source_root=Path(tmp) / "fake_src",
            )
            self.assertEqual(p2_deck["pass"], "pass2")
            self.assertEqual(p2_deck["card_count"], 1)
            self.assertEqual(p2_deck["cards"][0]["review_id"], rid_tp)


if __name__ == "__main__":
    unittest.main()
