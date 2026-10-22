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
    compute_inter_rater_stats,
    compute_phase_transitions,
    extract_phase_checkpoint_findings,
    parse_line_range,
)
from evaluation.models import CanonicalFinding, RootCauseJudgeVerdict, TrialRunRecord
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

    def test_finding_pooler_clusters_cross_tool_and_separates_distinct_cwe(self) -> None:
        vulns = self._sample_vulnerabilities()
        disc_vulns = extract_phase_checkpoint_findings(vulns, "discovery")

        # Claude reports the same CWE-252 bug at Line 125 plus an unrelated CWE-476 null pointer bug at Line 129
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
            pooler = FindingPooler(judge_model="heuristic")
            pool, mappings = pooler.build_pool(trials=trials, output_dir=out_dir)

            # Should have 3 canonical findings:
            # 1) CWE-252 in rom_ext_verify (clustered across v-true-bug, v-duplicate, and cli-1)
            # 2) CWE-190 in rom_ext_init (v-false-alarm-closed-in-ir)
            # 3) CWE-476 in rom_ext_verify (cli-2, kept separate from CWE-252 despite same function/line)
            self.assertEqual(len(pool), 3)
            cwe_set = {c.cwe for c in pool}
            self.assertEqual(cwe_set, {"CWE-252", "CWE-190", "CWE-476"})

            # Verify blind review labels & scorecard generation
            for cf in pool:
                if cf.cwe == "CWE-252":
                    cf.reviewer_1_label = "TP"
                    cf.reviewer_2_label = "TP"
                    cf.adjudicated_label = "TP"
                else:
                    cf.reviewer_1_label = "FP"
                    cf.reviewer_2_label = "FP"
                    cf.adjudicated_label = "FP"

            (out_dir / "blind_review_pool.json").write_text(
                json.dumps([c.model_dump() for c in pool], indent=2),
                encoding="utf-8",
            )

            # Re-pooling must preserve existing human labels and emit Web-UI blind_review bundle
            repool, _ = pooler.build_pool(trials=trials, output_dir=out_dir)
            tp_items = [c for c in repool if c.resolved_label == "TP"]
            self.assertEqual(len(tp_items), 1)
            self.assertTrue((out_dir / "blind_review" / "metadata.json").exists())
            self.assertTrue((out_dir / "blind_review" / "vulnerabilities.json").exists())

            ir_stats = compute_inter_rater_stats(repool)
            self.assertEqual(ir_stats.double_reviewed_count, 3)
            self.assertEqual(ir_stats.raw_agreement_rate, 1.0)
            self.assertEqual(ir_stats.cohens_kappa, 1.0)

            summaries = ScorecardGenerator().generate_scorecard(out_dir)
            by_tier = {s.ablation_tier: s for s in summaries}

            # Full Mjolnir kept the 1 TP and eliminated the 1 FP and 1 Duplicate from discovery
            self.assertEqual(by_tier["full"].precision_mean, 1.0)
            self.assertEqual(by_tier["full"].pooled_recall_mean, 1.0)
            self.assertEqual(by_tier["full"].fp_elimination_rate_mean, 1.0)
            self.assertEqual(by_tier["full"].false_disproof_rate_mean, 0.0)
            self.assertEqual(by_tier["full"].mean_unique_root_causes, 1.0)
            self.assertEqual(by_tier["full"].mean_redundant_duplicates, 0.0)
            self.assertEqual(by_tier["full"].redundancy_ratio, 1.0)
            # At discovery, 3 open findings mapped to 2 unique root causes (1 redundant duplicate) -> 1.5x redundancy
            self.assertEqual(by_tier["full@discovery"].mean_open_findings, 3.0)
            self.assertEqual(by_tier["full@discovery"].mean_unique_root_causes, 2.0)
            self.assertEqual(by_tier["full@discovery"].mean_redundant_duplicates, 1.0)
            self.assertEqual(by_tier["full@discovery"].redundancy_ratio, 1.5)
            # Phase checkpoints do not report per-run wall-clock time, and 1-rep tiers have None Jaccard
            self.assertIsNone(by_tier["full@discovery"].mean_wall_clock_seconds)
            self.assertEqual(by_tier["full"].mean_wall_clock_seconds, 45.0)
            self.assertIsNone(by_tier["full"].consistency_jaccard_mean)
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
            self.assertEqual(by_tier["full"].unique_open_across_reps, 1)
            self.assertEqual(by_tier["full"].consistent_open_all_reps, 1)
            self.assertEqual(by_tier["full"].unique_tps_across_reps, 1)
            self.assertEqual(by_tier["full"].consistent_tps_all_reps, 1)
            self.assertEqual(by_tier["full"].saturation_curve[1]["expected_open"], 1.0)
            self.assertEqual(by_tier["full"].saturation_curve[1]["expected_tp"], 1.0)
            self.assertEqual(by_tier["full"].severity_distribution_mean.get("Critical"), 1.0)
            self.assertEqual(by_tier["full"].mean_open_unverified, 0.0)

            # Holistic baseline had 1 TP and 1 FP -> 50% precision, 100% recall
            self.assertEqual(by_tier["holistic"].precision_mean, 0.5)
            self.assertEqual(by_tier["holistic"].pooled_recall_mean, 1.0)

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
            ScorecardGenerator().generate_scorecard(out_dir)
            sc_json = json.loads((out_dir / "scorecard.json").read_text(encoding="utf-8"))
            cm = sc_json["cross_model_consistency"]
            self.assertIsNotNone(cm)
            self.assertEqual(cm["total_unique_open_across_models"], 2)
            self.assertEqual(cm["consensus_all_models_open"], 1)
            self.assertEqual(cm["consensus_majority_models_open"], 2)

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

    def test_pure_llm_judge_and_unified_stability_pool(self) -> None:
        self.assertEqual(
            parse_line_range("AddSubjectAltNameCmd::execute (L28-50); dispatch (~L422)"),
            (28, 50),
        )
        self.assertEqual(parse_line_range("InvokeDpeCmd::execute_mldsa87"), (None, None))

        judge_pairs: list[tuple[str, str]] = []

        class StubArgonPooler(FindingPooler):
            def _run_llm_equivalence_judge(
                self, canon, file_path, loc_str, cwe_str, title_str, desc_str
            ):
                judge_pairs.append((canon.title, title_str))
                is_same = "Quota" in canon.title and "Quota" in title_str
                return RootCauseJudgeVerdict(is_match=is_same, rationale="stub verdict")

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
                    "file": "runtime/src/invoke_dpe.rs",
                    "location": "runtime/src/invoke_dpe.rs:InvokeDpeCmd::execute",
                    "cwe": "CWE-770",
                    "status": "Open",
                    "title": "PL1 DPE Quota Bypass",
                    "description": "PL1 caller exhausts PL0 quota via CALIPTRA_LOCALITY.",
                    "history": [],
                },
                {
                    "id": "f2",
                    "file": "runtime/src/invoke_dpe.rs",
                    "location": "execute_ecc384",
                    "cwe": "CWE-20",
                    "status": "Open",
                    "title": "ECC384 size check missing",
                    "description": "Missing mailbox size check.",
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
                    "file": "runtime/src/invoke_dpe.rs",
                    "location": "runtime/src/invoke_dpe.rs:188-220",
                    "cwe": "CWE-770",
                    "status": "Open",
                    "title": "PL1 DPE Quota Exhaustion",
                    "description": "PL1 caller exhausts PL0 quota via CALIPTRA_LOCALITY.",
                    "history": [],
                },
                {
                    "id": "f4",
                    "file": "runtime/src/invoke_dpe.rs",
                    "location": "execute_mldsa87",
                    "cwe": "CWE-20",
                    "status": "Open",
                    "title": "MLDSA87 size check missing",
                    "description": "Missing mailbox size check.",
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
                    "file": "runtime/src/invoke_dpe.rs",
                    "location": "InvokeDpeCmd::execute (L190-215)",
                    "cwe": "CWE-284",
                    "status": "Open",
                    "title": "Quota Exhaustion in DeriveContext",
                    "description": "Different CWE but same root cause.",
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

            pooler = StubArgonPooler(judge_model="gemini-4-argon")
            pool, _ = pooler.build_pool(
                trials=[rep1, rep2],
                output_dir=pinned_dir,
                extra_eval_dirs=[stab_dir],
                rebuild=True,
            )

            # Even though f1 and f3 share CWE-770 and high lexical overlap, pure LLM judge must be invoked
            self.assertGreaterEqual(len(judge_pairs), 2)
            # execute_ecc384 vs execute_mldsa87 are distinct functions -> rejected by location gate without LLM call
            self.assertFalse(any("ECC384" in a and "MLDSA87" in b for a, b in judge_pairs))
            # Quota bug merged across rep1, rep2, and stability rep4; ECC384 and MLDSA87 kept separate -> 3 clusters
            self.assertEqual(len(pool), 3)

            # Label only pinned/blind_review_pool.json and verify stability scorecard inherits TP labels
            for cf in pool:
                cf.adjudicated_label = "TP" if "Quota" in cf.title else "FP"
            (pinned_dir / "blind_review_pool.json").write_text(
                json.dumps([c.model_dump() for c in pool], indent=2),
                encoding="utf-8",
            )
            stab_summaries = ScorecardGenerator().generate_scorecard(stab_dir)
            self.assertEqual(stab_summaries[0].repetitions, 3)
            self.assertEqual(stab_summaries[0].consistent_tps_all_reps, 1)

    def test_harness_fixes_h1_to_h8_and_refusal_tracking(self) -> None:
        from types import SimpleNamespace
        from providers.adk.utilities.async_runner import is_safety_refusal_text
        from providers.adk.utilities.usage_tracker import UsageTracker
        from utilities.worktree_sandbox import REPRODUCE_SCRIPT_TEMPLATE

        # H8: Neutral reproducer exit message
        self.assertNotIn("VULNERABILITY REPRODUCED", REPRODUCE_SCRIPT_TEMPLATE)
        self.assertIn("COMMAND FAILED (exit code", REPRODUCE_SCRIPT_TEMPLATE)

        # H4 & H5: Dual-expert resolution + expert_severity / poc_demonstrates / cluster_error
        base_cf_kwargs = {
            "project_name": "Caliptra",
            "repo_name": "caliptra-sw",
            "pinned_rev": "262470b",
            "location": "Line 10",
            "title": "Test finding",
            "description": "Test description",
        }
        single_labeled = CanonicalFinding(
            canonical_id="CANON-001",
            file="a.rs",
            reviewer_1_label="TP",
            reviewer_2_label="",
            **base_cf_kwargs,
        )
        self.assertIsNone(single_labeled.resolved_label)

        disputed = CanonicalFinding(
            canonical_id="CANON-002",
            file="b.rs",
            reviewer_1_label="TP",
            reviewer_2_label="FP",
            **base_cf_kwargs,
        )
        self.assertIsNone(disputed.resolved_label)

        agreed_med_tp = CanonicalFinding(
            canonical_id="CANON-003",
            file="c.rs",
            reviewer_1_label="TP",
            reviewer_2_label="TP",
            expert_severity="high",
            poc_demonstrates="yes",
            cluster_error="none",
            **base_cf_kwargs,
        )
        agreed_low_tp = CanonicalFinding(
            canonical_id="CANON-004",
            file="d.rs",
            adjudicated_label="TP",
            expert_severity="Low",
            poc_demonstrates="no",
            cluster_error="split",
            **base_cf_kwargs,
        )
        self.assertEqual(agreed_med_tp.resolved_label, "TP")
        self.assertEqual(agreed_med_tp.normalized_expert_severity, "High")
        ir = compute_inter_rater_stats([single_labeled, disputed, agreed_med_tp, agreed_low_tp])
        self.assertEqual(ir.single_reviewed_count, 1)
        self.assertEqual(ir.disputed_unadjudicated_count, 1)
        self.assertEqual(ir.confirmed_tp_count, 2)
        self.assertEqual(ir.confirmed_tp_medium_or_above_count, 1)
        self.assertEqual(ir.expert_severity_counts["High"], 1)
        self.assertEqual(ir.expert_severity_counts["Low"], 1)
        self.assertEqual(ir.poc_demonstrates_counts, {"yes": 1, "no": 1})
        self.assertEqual(ir.cluster_error_counts, {"none": 1, "split": 1, "merge": 0})

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
            # H6: Saturation plot uses "Expected unique root causes" without "Discover"
            sat_tex = (eval_dir / "plots" / "fig_rq3_saturation_curve.tex").read_text(
                encoding="utf-8"
            )
            sat_svg = (eval_dir / "plots" / "fig_rq3_saturation_curve.svg").read_text(
                encoding="utf-8"
            )
            self.assertIn("Expected unique root causes", sat_tex)
            self.assertNotIn("Discover", sat_tex)
            self.assertIn("Expected unique root causes", sat_svg)
            self.assertNotIn("Discover", sat_svg)


if __name__ == "__main__":
    unittest.main()
