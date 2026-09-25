# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Automated Ground-Truth Grader and Phase-Survival Diagnostics for Nidhogg."""

import json
from pathlib import Path
import re

import constants as mjolnir_constants
from nidhogg.data.models import InstanceGrade, SyntheticVulnManifest, VulnerableSpan

CWE_CATALOG_PATH = Path(mjolnir_constants.__file__).resolve().parent / "data" / "cwe_catalog.json"


class CweHierarchyMatcher:
    """Checks CWE equivalence using MITRE CWE parent-child relationships."""

    def __init__(self, catalog_path: Path = CWE_CATALOG_PATH):
        self.parents_map: dict[str, set[str]] = {}
        if catalog_path.exists():
            data = json.loads(catalog_path.read_text(encoding="utf-8"))
            weaknesses = data.get("weaknesses", {})
            for cwe_key, info in weaknesses.items():
                norm_id = self.normalize_cwe(cwe_key)
                parents = {self.normalize_cwe(f"CWE-{p}") for p in info.get("parents", [])}
                self.parents_map[norm_id] = parents

    @staticmethod
    def normalize_cwe(raw: str | None) -> str:
        if not raw:
            return ""
        m = re.search(r"CWE-(\d+)", str(raw), re.IGNORECASE)
        return f"CWE-{m.group(1)}" if m else str(raw).strip().upper()

    def ancestors(self, cwe_id: str, max_depth: int = 2) -> set[str]:
        norm = self.normalize_cwe(cwe_id)
        visited = {norm}
        frontier = {norm}
        for _ in range(max_depth):
            next_frontier: set[str] = set()
            for node in frontier:
                for parent in self.parents_map.get(node, set()):
                    if parent not in visited:
                        visited.add(parent)
                        next_frontier.add(parent)
            frontier = next_frontier
            if not frontier:
                break
        return visited

    def are_equivalent(self, reported_cwe: str | None, truth_cwe: str) -> bool:
        rep = self.normalize_cwe(reported_cwe)
        tru = self.normalize_cwe(truth_cwe)
        if not rep or not tru:
            return False
        if rep == tru:
            return True
        rep_anc = self.ancestors(rep, max_depth=2)
        tru_anc = self.ancestors(tru, max_depth=2)
        return tru in rep_anc or rep in tru_anc or bool(rep_anc & tru_anc - {"CWE-1000", "CWE-699"})


class BenchmarkGrader:
    """Grades a benchmark run against a ground-truth SyntheticVulnManifest and extracts phase survival."""

    def __init__(self):
        self.cwe_matcher = CweHierarchyMatcher()

    def grade_instance_run(
        self,
        manifest: SyntheticVulnManifest,
        ablation_tier: str,
        repetition: int,
        vulnerabilities_data: list[dict],
        usage_summary: dict | None = None,
        wall_clock_seconds: float = 0.0,
        tamper_detected: bool = False,
    ) -> InstanceGrade:
        """Computes ground-truth match and phase-by-phase survival diagnostics for a single instance run."""
        grade = InstanceGrade(
            vuln_id=manifest.vuln_id,
            ncm_cell=manifest.ncm.cell_id,
            is_distractor=manifest.ncm.is_distractor,
            cwe_id=manifest.cwe_id,
            ablation_tier=ablation_tier,
            repetition=repetition,
            wall_clock_seconds=round(wall_clock_seconds, 3),
            tamper_detected=tamper_detected,
        )

        if usage_summary:
            totals = usage_summary.get("totals", {})
            grade.total_tokens = int(totals.get("total_tokens", 0))
            grade.estimated_cost_usd = float(totals.get("estimated_cost_usd", 0.0))

        if tamper_detected:
            return grade

        open_findings = [
            v for v in vulnerabilities_data if str(v.get("status", "Open")).lower() == "open"
        ]
        grade.total_reported_open_findings = len(open_findings)

        matched_vuln = None
        for v in vulnerabilities_data:
            if self._matches_ground_truth(v, manifest):
                matched_vuln = v
                break

        if matched_vuln is None:
            grade.false_positives_count = len(open_findings)
            return grade

        grade.matched_finding_id = matched_vuln.get("id")
        grade.matched_cwe_id = self._extract_cwe_from_vuln(matched_vuln)

        # Inspect phase_history (stored in v["history"]) for Phase-Survival Diagnostics
        history = matched_vuln.get("history", [])
        phase_ids_seen = {h.get("phase_id") for h in history if isinstance(h, dict)}
        final_status_open = str(matched_vuln.get("status", "Open")).lower() == "open"

        grade.detected_in_discovery = "discovery" in phase_ids_seen or bool(matched_vuln)

        # Deduplication survival: either deduplication wasn't run, or finding wasn't closed as duplicate
        # (or its primary canonical finding survived)
        dedup_records = [
            h for h in history if isinstance(h, dict) and h.get("phase_id") == "deduplication"
        ]
        if not dedup_records:
            grade.survived_deduplication = grade.detected_in_discovery
        else:
            dedup_finding = dedup_records[-1].get("finding", {})
            grade.survived_deduplication = not bool(dedup_finding.get("is_duplicate", False))

        # Initial Review survival
        init_rev_records = [
            h for h in history if isinstance(h, dict) and h.get("phase_id") == "initial_review"
        ]
        if not init_rev_records:
            grade.survived_initial_review = grade.survived_deduplication
        else:
            verdict = str(init_rev_records[-1].get("finding", {}).get("verdict", "")).lower()
            grade.survived_initial_review = verdict not in ("disproven", "closed", "false_positive")

        # PoC Synthesis survival
        poc_records = [
            h for h in history if isinstance(h, dict) and h.get("phase_id") == "poc_creation"
        ]
        if poc_records:
            grade.poc_synthesized_and_verified = bool(
                poc_records[-1].get("finding", {}).get("poc_verified", False)
            )

        grade.survived_final_review = final_status_open

        if not manifest.ncm.is_distractor:
            if grade.detected_in_discovery and not final_status_open:
                grade.reviewer_falsely_disproved = True
            grade.false_positives_count = max(
                0, len(open_findings) - (1 if final_status_open else 0)
            )
        else:
            # For a distractor injection, closing it in review is a True Rejection
            if grade.detected_in_discovery and not final_status_open:
                grade.distractor_truly_rejected = True
            grade.false_positives_count = len(open_findings)

        return grade

    def _matches_ground_truth(self, vuln: dict, manifest: SyntheticVulnManifest) -> bool:
        reported_file = str(vuln.get("file", "")).replace("\\", "/").lstrip("./")
        if not reported_file:
            return False

        span_matched = False
        for span in manifest.vulnerable_spans:
            if self._file_and_span_match(reported_file, vuln, span):
                span_matched = True
                break
        if not span_matched:
            return False

        reported_cwe = self._extract_cwe_from_vuln(vuln)
        if reported_cwe and self.cwe_matcher.are_equivalent(reported_cwe, manifest.cwe_id):
            return True
        # For mock or non-CWE static tools where cwe_id is omitted, accept file+span match
        if not reported_cwe:
            return True
        return False

    def _file_and_span_match(self, reported_file: str, vuln: dict, span: VulnerableSpan) -> bool:
        truth_file = span.file_path.replace("\\", "/").lstrip("./")
        if not (
            reported_file == truth_file
            or reported_file.endswith("/" + truth_file)
            or truth_file.endswith("/" + reported_file)
        ):
            return False

        location_str = str(vuln.get("location", "")) + " " + str(vuln.get("description", ""))
        if span.function_name and span.function_name in location_str:
            return True

        line_nums = [int(m) for m in re.findall(r"\b(\d+)\b", str(vuln.get("location", "")))]
        if not line_nums:
            return True
        margin = 25
        return any((span.start_line - margin) <= ln <= (span.end_line + margin) for ln in line_nums)

    def _extract_cwe_from_vuln(self, vuln: dict) -> str | None:
        if vuln.get("cwe_id"):
            return str(vuln["cwe_id"])
        for h in reversed(vuln.get("history", [])):
            if isinstance(h, dict):
                finding = h.get("finding", {})
                if isinstance(finding, dict) and finding.get("cwe_id"):
                    return str(finding["cwe_id"])
        return None
