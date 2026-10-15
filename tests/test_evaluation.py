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
)
from evaluation.models import CanonicalFinding, TrialRunRecord
from evaluation.runner import (
    expand_cli_template,
    extract_findings_from_cli_output,
    extract_or_estimate_cli_usage,
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
                ablation_tier="cli_antigravity",
                tier_name="Antigravity CLI (Directory, +TM)",
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
            self.assertEqual(by_tier["full"].unique_open_across_reps, 1)
            self.assertEqual(by_tier["full"].consistent_open_all_reps, 1)
            self.assertEqual(by_tier["full"].unique_tps_across_reps, 1)
            self.assertEqual(by_tier["full"].consistent_tps_all_reps, 1)
            self.assertEqual(by_tier["full"].saturation_curve[1]["expected_open"], 1.0)
            self.assertEqual(by_tier["full"].saturation_curve[1]["expected_tp"], 1.0)
            self.assertEqual(by_tier["full"].severity_distribution_mean.get("Critical"), 1.0)

            # Antigravity CLI had 1 TP and 1 FP -> 50% precision, 100% recall
            self.assertEqual(by_tier["cli_antigravity"].precision_mean, 0.5)
            self.assertEqual(by_tier["cli_antigravity"].pooled_recall_mean, 1.0)

    def test_cli_template_and_usage_parsing(self) -> None:
        argv = expand_cli_template(
            "antigravity -p {prompt} --dangerously-skip-permissions",
            {"prompt": "Audit file 'foo.c' & bar.c"},
        )
        self.assertEqual(
            argv,
            ["antigravity", "-p", "Audit file 'foo.c' & bar.c", "--dangerously-skip-permissions"],
        )

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

        # CLI token extraction from regex / fallback
        cli_telemetry = extract_or_estimate_cli_usage(
            stdout_text="Scan complete.\ninput_tokens: 15,000\noutput_tokens: 2,500\ncached_tokens: 5,000\n",
            stderr_text="",
            out_json_path=None,
            prompt_text="Audit repo",
        )
        self.assertEqual(cli_telemetry["source"], "cli_regex_telemetry")
        self.assertEqual(cli_telemetry["total"]["total_tokens"], 17500)
        self.assertEqual(cli_telemetry["total"]["cache_tokens"], 5000)
        self.assertEqual(cli_telemetry["total"]["uncached_tokens"], 10000)

        cli_fallback = extract_or_estimate_cli_usage(
            stdout_text="[]" * 20,
            stderr_text="",
            out_json_path=None,
            prompt_text="A" * 400,
            scanned_files_bytes=1200,
        )
        self.assertEqual(cli_fallback["source"], "estimated_char_4")
        self.assertEqual(cli_fallback["total"]["prompt_tokens"], 400)

        with tempfile.TemporaryDirectory() as tmp:
            missing_json = Path(tmp) / "out.json"
            stdout = (
                "Here are the findings:\n```json\n"
                '[{"file": "rom_ext.c", "location": "Line 55", "cwe": "CWE-252", "severity": "High", "title": "Bug"}]\n'
                "```\n"
            )
            extracted = extract_findings_from_cli_output(missing_json, stdout)
            self.assertEqual(len(extracted), 1)
            self.assertEqual(extracted[0]["cwe"], "CWE-252")

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
                    "sastTiers": ["semgrep", "clippy"],
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
                tier_key="semgrep",
                tier_cfg={"name": "Semgrep"},
                vulns_data=[
                    {
                        "id": "semgrep-1",
                        "file": "rom/src/main.rs",
                        "location": "Line 1",
                        "cwe": "CWE-190",
                        "title": "rust.lang.security.test",
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
                evaluator_model="gemini-3.8-flash,gemini-4-argon,vertex_ai/claude-sonnet-4-6@20260514",
            )
            self.assertEqual(
                multi_runner.evaluator_models,
                ["gemini-3.8-flash", "gemini-4-argon", "vertex_ai/claude-sonnet-4-6@20260514"],
            )
            self.assertEqual(
                format_model_slug("vertex_ai/claude-sonnet-4-6@20260514"), "claude-sonnet-4-6"
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
            model_version="vertex_ai/claude-sonnet-4-6",
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
                ablation_tier="full[claude-sonnet-4-6]",
                tier_name="Mjolnir Full (claude-sonnet-4-6)",
                model="vertex_ai/claude-sonnet-4-6",
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


if __name__ == "__main__":
    unittest.main()
