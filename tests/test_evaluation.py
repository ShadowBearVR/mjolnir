# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for mjolnir-eval: phase-checkpoint extraction, transition counting, CLI templates, and 2-step grading."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "app"))
sys.path.insert(0, str(ROOT_DIR / "app" / "mjolnir"))

from evaluation.grader import (
    BenchmarkGrader,
    compute_phase_transitions,
    extract_phase_checkpoint_findings,
)
from evaluation.models import NcmCoordinate, VulnInstanceManifest, VulnerableSpan
from evaluation.runner import expand_cli_template, extract_findings_from_cli_output
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
                "file": "sw/device/silicon_creator/rom_ext/rom_ext.c",
                "location": "rom_ext_verify (Line 130)",
                "cwe": "CWE-252",
                "severity": "High",
                "status": "Duplicate",
                "title": "Duplicate sigverify finding",
                "description": "Duplicate of v-true-bug.",
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

        at_dedup = extract_phase_checkpoint_findings(vulns, "deduplication")
        open_dedup = [v for v in at_dedup if v["status"].lower() == "open"]
        self.assertEqual(len(open_dedup), 2)

        at_ir = extract_phase_checkpoint_findings(vulns, "initial_review")
        open_ir = [v for v in at_ir if v["status"].lower() == "open"]
        self.assertEqual(len(open_ir), 1)
        self.assertEqual(open_ir[0]["id"], "v-true-bug")
        self.assertEqual(open_ir[0]["severity"], "High")

        at_final = extract_phase_checkpoint_findings(vulns, "final_review")
        open_final = [v for v in at_final if v["status"].lower() == "open"]
        self.assertEqual(len(open_final), 1)
        self.assertEqual(open_final[0]["severity"], "Critical")

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

        self.assertEqual(transitions["final_review"].entering_count, 1)
        self.assertEqual(transitions["final_review"].severity_upgraded_count, 1)
        self.assertEqual(transitions["final_review"].severity_transitions.get("High->Critical"), 1)

    def test_two_step_grader_rejects_unrelated_cwe_in_same_span(self) -> None:
        manifest = VulnInstanceManifest(
            vuln_id="ot-rom-ext-001",
            dataset_id="v1",
            project_name="opentitan",
            base_commit="c5a58fb8ad7b",
            scope="rom_ext",
            cwe_id="CWE-252",
            title="Unchecked return value in rom_ext_verify",
            description="Signature check return value is not verified.",
            ncm=NcmCoordinate(spatial_scope=1, state_depth=1, domain_subtlety=2),
            vulnerable_spans=[
                VulnerableSpan(
                    file_path="sw/device/silicon_creator/rom_ext/rom_ext.c",
                    function_name="rom_ext_verify",
                    start_line=120,
                    end_line=140,
                )
            ],
        )
        grader = BenchmarkGrader(judge_model="heuristic")

        # Unrelated CWE-190 at the exact same line should NOT match CWE-252 ground truth
        unrelated_finding = [
            {
                "id": "wrong-bug",
                "file": "sw/device/silicon_creator/rom_ext/rom_ext.c",
                "location": "rom_ext_verify (Line 128)",
                "cwe": "CWE-190",
                "severity": "High",
                "status": "Open",
                "title": "Integer overflow",
                "description": "Unrelated overflow.",
                "history": [],
            }
        ]
        grade_wrong = grader.grade_instance_run(
            manifest=manifest,
            ablation_tier="full",
            repetition=1,
            vulnerabilities_data=unrelated_finding,
        )
        self.assertFalse(grade_wrong.survived_final_review)
        self.assertEqual(grade_wrong.false_positives_count, 1)

        # True matching finding + closed false alarm
        grade_hit = grader.grade_instance_run(
            manifest=manifest,
            ablation_tier="full",
            repetition=1,
            vulnerabilities_data=self._sample_vulnerabilities(),
        )
        self.assertTrue(grade_hit.detected_in_discovery)
        self.assertTrue(grade_hit.survived_deduplication)
        self.assertTrue(grade_hit.survived_initial_review)
        self.assertTrue(grade_hit.poc_synthesized_and_verified)
        self.assertTrue(grade_hit.survived_final_review)
        self.assertEqual(grade_hit.false_positives_count, 0)

    def test_cli_template_expansion_and_stdout_extraction(self) -> None:
        argv = expand_cli_template(
            "gemini -p {prompt} --yolo",
            {"prompt": "Audit file 'foo.c' & bar.c"},
        )
        self.assertEqual(argv, ["gemini", "-p", "Audit file 'foo.c' & bar.c", "--yolo"])

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

            # Also verify ScorecardGenerator end-to-end
            manifest = VulnInstanceManifest(
                vuln_id="ot-rom-ext-001",
                dataset_id="v1",
                project_name="opentitan",
                base_commit="c5a58fb8ad7b",
                scope="rom_ext",
                cwe_id="CWE-252",
                title="Bug",
                description="Desc",
                vulnerable_spans=[
                    VulnerableSpan(
                        file_path="sw/device/silicon_creator/rom_ext/rom_ext.c",
                        function_name="rom_ext_verify",
                        start_line=120,
                        end_line=140,
                    )
                ],
            )
            grade = BenchmarkGrader(judge_model="heuristic").grade_instance_run(
                manifest=manifest,
                ablation_tier="full",
                repetition=1,
                vulnerabilities_data=self._sample_vulnerabilities(),
            )
            grades_path = Path(tmp) / "grades.json"
            import json

            grades_path.write_text(json.dumps([grade.model_dump()]), encoding="utf-8")
            summaries = ScorecardGenerator().generate_scorecard(grades_path)
            self.assertEqual(len(summaries), 1)
            self.assertEqual(summaries[0].precision_mean, 1.0)
            self.assertIn("initial_review", summaries[0].phase_funnel_summary)


if __name__ == "__main__":
    unittest.main()
