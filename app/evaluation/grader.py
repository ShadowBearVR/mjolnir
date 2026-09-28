# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""2-Step Ground-Truth Grader (Localization + Semantic Root-Cause Judge) and Phase-Checkpoint Extractor."""

import asyncio
import json
from pathlib import Path
import re

import constants as mjolnir_constants
from evaluation.constants import ORDERED_PIPELINE_PHASES, SEVERITY_RANKS
from evaluation.models import (
    InstanceGrade,
    PhaseTransitionStats,
    RootCauseJudgeVerdict,
    VulnInstanceManifest,
    VulnerableSpan,
)
from utilities.logger import logger

CWE_CATALOG_PATH = Path(mjolnir_constants.__file__).resolve().parent / "data" / "cwe_catalog.json"


def normalize_phase_id(raw_phase_id: str | None) -> str:
    """Normalizes legacy numeric or display phase IDs to canonical pipeline phase IDs."""
    if not raw_phase_id:
        return ""
    s = str(raw_phase_id).strip().lower()
    mapping = {
        "1": "discovery",
        "source file exploration": "discovery",
        "source file discovery": "discovery",
        "5": "deduplication",
        "2": "initial_review",
        "initial review": "initial_review",
        "3": "poc_creation",
        "poc creation": "poc_creation",
        "4": "final_review",
        "final review": "final_review",
    }
    return mapping.get(s, s)


def extract_phase_checkpoint_findings(
    vulnerabilities_data: list[dict], checkpoint_phase_id: str
) -> list[dict]:
    """Reconstructs the exact vulnerabilities.json snapshot as it existed at checkpoint_phase_id.

    Allows a single full Mjolnir run to yield intermediate ablation checkpoints
    (@discovery, @deduplication, @initial_review [= no_poc], @poc_creation, @final_review)
    directly from Vulnerability.history without re-executing upstream phases.
    """
    target_norm = normalize_phase_id(checkpoint_phase_id)
    if target_norm not in ORDERED_PIPELINE_PHASES:
        return vulnerabilities_data

    target_idx = ORDERED_PIPELINE_PHASES.index(target_norm)
    allowed_phases = set(ORDERED_PIPELINE_PHASES[: target_idx + 1])

    snapshot_vulns: list[dict] = []
    for vuln in vulnerabilities_data:
        history = vuln.get("history", [])
        if not history:
            snapshot_vulns.append(dict(vuln))
            continue

        kept_history: list[dict] = []
        for h in history:
            if not isinstance(h, dict):
                continue
            pid = normalize_phase_id(h.get("phase_id") or h.get("phase_name"))
            if pid in allowed_phases:
                kept_history.append(h)

        if not kept_history:
            continue

        latest = kept_history[-1]
        nested = latest.get("finding", {}) if isinstance(latest.get("finding"), dict) else {}

        reconstructed = dict(vuln)
        reconstructed["history"] = kept_history
        for key in (
            "status",
            "severity",
            "cwe",
            "title",
            "description",
            "location",
            "poc_code",
            "poc_verified",
            "verdict",
        ):
            val = latest.get(key) if key in latest else nested.get(key)
            if val is not None:
                reconstructed[key] = val

        # If a finding was closed as a duplicate in deduplication, reflect its non-open status
        if normalize_phase_id(latest.get("phase_id")) == "deduplication":
            is_dup = bool(
                latest.get("is_duplicate")
                or nested.get("is_duplicate")
                or str(reconstructed.get("status", "")).lower() == "duplicate"
            )
            if is_dup:
                reconstructed["status"] = "Duplicate"

        snapshot_vulns.append(reconstructed)

    return snapshot_vulns


def compute_phase_transitions(vulnerabilities_data: list[dict]) -> list[PhaseTransitionStats]:
    """Computes finding counts, close/duplicate rates, and severity shifts across each pipeline phase."""
    stats_by_phase: dict[str, PhaseTransitionStats] = {
        pid: PhaseTransitionStats(phase_id=pid) for pid in ORDERED_PIPELINE_PHASES
    }

    for vuln in vulnerabilities_data:
        history = [h for h in vuln.get("history", []) if isinstance(h, dict)]
        if not history:
            continue

        prev_sev = None
        prev_open = True

        for h in history:
            pid = normalize_phase_id(h.get("phase_id") or h.get("phase_name"))
            if pid not in stats_by_phase:
                continue

            nested = h.get("finding", {}) if isinstance(h.get("finding"), dict) else {}
            raw_status = str(h.get("status") or nested.get("status") or "Open").strip()
            status_lower = raw_status.lower()
            verdict_lower = str(h.get("verdict") or nested.get("verdict") or "").strip().lower()
            is_dup = bool(
                h.get("is_duplicate") or nested.get("is_duplicate") or status_lower == "duplicate"
            )
            is_closed = status_lower == "closed" or verdict_lower in (
                "disproven",
                "closed",
                "false_positive",
            )
            cur_sev = str(
                h.get("severity") or nested.get("severity") or vuln.get("severity") or "Medium"
            ).capitalize()

            st = stats_by_phase[pid]
            if pid == "discovery":
                st.entering_count += 1
                st.surviving_open_count += 1
                prev_sev = cur_sev
                prev_open = True
                continue

            if not prev_open:
                continue

            st.entering_count += 1
            from_label = prev_sev or "Medium"

            if is_dup:
                st.duplicate_count += 1
                key = f"{from_label}->Duplicate"
                st.severity_transitions[key] = st.severity_transitions.get(key, 0) + 1
                prev_open = False
            elif is_closed:
                st.closed_count += 1
                key = f"{from_label}->Closed"
                st.severity_transitions[key] = st.severity_transitions.get(key, 0) + 1
                prev_open = False
            else:
                st.surviving_open_count += 1
                prev_rank = SEVERITY_RANKS.get(from_label.lower(), 3)
                cur_rank = SEVERITY_RANKS.get(cur_sev.lower(), 3)
                if cur_rank > prev_rank:
                    st.severity_upgraded_count += 1
                elif cur_rank < prev_rank:
                    st.severity_downgraded_count += 1
                else:
                    st.severity_unchanged_count += 1
                key = f"{from_label}->{cur_sev}"
                st.severity_transitions[key] = st.severity_transitions.get(key, 0) + 1
                prev_sev = cur_sev
                prev_open = True

    return [
        stats_by_phase[pid]
        for pid in ORDERED_PIPELINE_PHASES
        if stats_by_phase[pid].entering_count > 0
    ]


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
    """2-Step Grader: (1) File/Span Localization Filter + (2) Semantic Root-Cause Equivalence Judge."""

    def __init__(self, judge_model: str | None = None):
        self.cwe_matcher = CweHierarchyMatcher()
        self.judge_model = judge_model

    def grade_instance_run(
        self,
        manifest: VulnInstanceManifest,
        ablation_tier: str,
        repetition: int,
        vulnerabilities_data: list[dict],
        vuln_patch: str = "",
        usage_summary: dict | None = None,
        wall_clock_seconds: float = 0.0,
        tamper_detected: bool = False,
    ) -> InstanceGrade:
        """Computes 2-step ground-truth match and phase-by-phase survival diagnostics for a single instance run."""
        grade = InstanceGrade(
            vuln_id=manifest.vuln_id,
            ncm_cell=manifest.ncm.cell_id,
            is_distractor=manifest.ncm.is_distractor,
            cwe_id=manifest.cwe_id,
            ablation_tier=ablation_tier,
            repetition=repetition,
            wall_clock_seconds=round(wall_clock_seconds, 3),
            tamper_detected=tamper_detected,
            phase_transitions=compute_phase_transitions(vulnerabilities_data),
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
        matched_rationale = ""
        for v in vulnerabilities_data:
            is_match, rationale = self._matches_ground_truth(v, manifest, vuln_patch)
            if is_match:
                matched_vuln = v
                matched_rationale = rationale
                break

        if matched_vuln is None:
            grade.false_positives_count = len(open_findings)
            return grade

        grade.matched_finding_id = matched_vuln.get("id")
        grade.matched_cwe_id = self._extract_cwe_from_vuln(matched_vuln)
        grade.judge_rationale = matched_rationale

        history = matched_vuln.get("history", [])
        phase_ids_seen = {
            normalize_phase_id(h.get("phase_id") or h.get("phase_name"))
            for h in history
            if isinstance(h, dict)
        }
        final_status_open = str(matched_vuln.get("status", "Open")).lower() == "open"

        grade.detected_in_discovery = "discovery" in phase_ids_seen or bool(matched_vuln)

        # Deduplication survival
        dedup_records = [
            h
            for h in history
            if isinstance(h, dict)
            and normalize_phase_id(h.get("phase_id") or h.get("phase_name")) == "deduplication"
        ]
        if not dedup_records:
            grade.survived_deduplication = grade.detected_in_discovery
        else:
            last_dedup = dedup_records[-1]
            dedup_status = str(
                last_dedup.get("status") or last_dedup.get("finding", {}).get("status") or "Open"
            ).lower()
            is_dup = bool(
                last_dedup.get("is_duplicate")
                or last_dedup.get("finding", {}).get("is_duplicate")
                or dedup_status in ("duplicate", "closed")
            )
            grade.survived_deduplication = not is_dup

        # Initial Review survival
        init_rev_records = [
            h
            for h in history
            if isinstance(h, dict)
            and normalize_phase_id(h.get("phase_id") or h.get("phase_name")) == "initial_review"
        ]
        if not init_rev_records:
            grade.survived_initial_review = grade.survived_deduplication
        else:
            last_ir = init_rev_records[-1]
            ir_status = str(last_ir.get("status") or "").lower()
            verdict = str(
                last_ir.get("verdict") or last_ir.get("finding", {}).get("verdict") or ""
            ).lower()
            grade.survived_initial_review = ir_status != "closed" and verdict not in (
                "disproven",
                "closed",
                "false_positive",
            )

        # PoC Synthesis survival
        poc_records = [
            h
            for h in history
            if isinstance(h, dict)
            and normalize_phase_id(h.get("phase_id") or h.get("phase_name")) == "poc_creation"
        ]
        if poc_records:
            last_poc = poc_records[-1]
            grade.poc_synthesized_and_verified = bool(
                last_poc.get("poc_verified")
                or last_poc.get("finding", {}).get("poc_verified", False)
            )
        elif matched_vuln.get("poc_verified"):
            grade.poc_synthesized_and_verified = True

        grade.survived_final_review = final_status_open

        if not manifest.ncm.is_distractor:
            if grade.detected_in_discovery and not final_status_open:
                grade.reviewer_falsely_disproved = True
            grade.false_positives_count = max(
                0, len(open_findings) - (1 if final_status_open else 0)
            )
        else:
            if grade.detected_in_discovery and not final_status_open:
                grade.distractor_truly_rejected = True
            grade.false_positives_count = len(open_findings)

        return grade

    def _matches_ground_truth(
        self, vuln: dict, manifest: VulnInstanceManifest, vuln_patch: str = ""
    ) -> tuple[bool, str]:
        """Step 1: File/span localization filter. Step 2: CWE + LLM semantic root-cause judge."""
        reported_file = str(vuln.get("file", "")).replace("\\", "/").lstrip("./")
        if not reported_file:
            return False, "Missing file path"

        span_matched = False
        for span in manifest.vulnerable_spans:
            if self._file_and_span_match(reported_file, vuln, span):
                span_matched = True
                break
        if not span_matched:
            return False, "File or line/function span did not match"

        # Step 2: Semantic Root-Cause Verification
        if self.judge_model and self.judge_model not in ("mock", "heuristic"):
            verdict = self._run_llm_root_cause_judge(vuln, manifest, vuln_patch)
            if verdict is not None:
                return verdict.is_match, verdict.rationale

        # Deterministic CWE + root-cause heuristic fallback
        reported_cwe = self._extract_cwe_from_vuln(vuln)
        if reported_cwe:
            if self.cwe_matcher.are_equivalent(reported_cwe, manifest.cwe_id):
                return True, f"Matched span and equivalent CWE ({reported_cwe} ~ {manifest.cwe_id})"
            return False, f"Mismatched CWE ({reported_cwe} vs {manifest.cwe_id})"

        return True, "Matched file and span (no CWE field reported by tool)"

    def _run_llm_root_cause_judge(
        self, vuln: dict, manifest: VulnInstanceManifest, vuln_patch: str
    ) -> RootCauseJudgeVerdict | None:
        """Invokes a deterministic LLM judge to verify semantic root-cause equivalence."""
        try:
            from google.adk.runners import Runner
            from google.adk.sessions import InMemorySessionService
            from google.genai import types
            from providers.adk.agents.isolated_agent import IsolatedAgent
            from providers.adk.utilities.async_runner import extract_agent_output

            judge_agent = IsolatedAgent(
                name="RootCauseJudge",
                model=self.judge_model,
                instruction=(
                    "You are an impartial security benchmark judge. Given a ground-truth vulnerability "
                    "(title, description, CWE, and diff) and a tool's reported finding in the same file, "
                    "determine whether the reported finding identifies the SAME underlying security flaw / "
                    "root-cause mechanism. Return is_match=False if the finding flags a different or unrelated "
                    "issue that merely happens to reside in the same function or line range."
                ),
                output_schema=RootCauseJudgeVerdict,
                tools=[],
            )
            prompt = json.dumps(
                {
                    "ground_truth": {
                        "cwe_id": manifest.cwe_id,
                        "title": manifest.title,
                        "description": manifest.description,
                        "spans": [s.model_dump() for s in manifest.vulnerable_spans],
                        "vuln_patch": vuln_patch[:2000],
                    },
                    "reported_finding": {
                        "file": vuln.get("file"),
                        "location": vuln.get("location"),
                        "cwe": self._extract_cwe_from_vuln(vuln),
                        "title": vuln.get("title"),
                        "description": vuln.get("description"),
                    },
                },
                indent=2,
            )

            async def _invoke() -> RootCauseJudgeVerdict | None:
                session_service = InMemorySessionService()
                runner = Runner(
                    agent=judge_agent,
                    app_name="mjolnir_eval_judge",
                    session_service=session_service,
                )
                session = await session_service.create_session(
                    app_name="mjolnir_eval_judge", user_id="eval_judge", state={}
                )
                msg = types.Content(role="user", parts=[types.Part.from_text(text=prompt)])
                last_output = None
                for ev in runner.run(user_id="eval_judge", session_id=session.id, new_message=msg):
                    if getattr(ev, "output", None) is not None:
                        last_output = ev.output
                    elif getattr(ev, "content", None) and getattr(ev.content, "parts", None):
                        for part in ev.content.parts:
                            if getattr(part, "text", None):
                                last_output = part.text
                parsed = extract_agent_output(last_output, RootCauseJudgeVerdict)
                return RootCauseJudgeVerdict.model_validate(parsed) if parsed else None

            return asyncio.run(_invoke())
        except Exception as e:
            logger.warning(f"LLM root-cause judge fallback to CWE heuristic: {e}")
            return None

    def _file_and_span_match(self, reported_file: str, vuln: dict, span: VulnerableSpan) -> bool:
        truth_file = span.file_path.replace("\\", "/").lstrip("./")
        if not (
            reported_file == truth_file
            or reported_file.endswith("/" + truth_file)
            or truth_file.endswith("/" + reported_file)
        ):
            return False

        location_str = str(vuln.get("location", ""))
        if span.function_name and span.function_name in location_str:
            return True

        line_nums = [int(m) for m in re.findall(r"\b(\d+)\b", location_str)]
        if not line_nums:
            return bool(span.function_name and span.function_name in str(vuln.get("title", "")))
        margin = 35
        return any((span.start_line - margin) <= ln <= (span.end_line + margin) for ln in line_nums)

    def _extract_cwe_from_vuln(self, vuln: dict) -> str | None:
        for key in ("cwe", "cwe_id"):
            if vuln.get(key):
                return str(vuln[key])
        for h in reversed(vuln.get("history", [])):
            if isinstance(h, dict):
                for key in ("cwe", "cwe_id"):
                    if h.get(key):
                        return str(h[key])
                finding = h.get("finding", {})
                if isinstance(finding, dict):
                    for key in ("cwe", "cwe_id"):
                        if finding.get(key):
                            return str(finding[key])
        return None
