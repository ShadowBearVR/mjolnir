# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Phase-Checkpoint Extractor, CWE Hierarchy Matcher, Blind Review Pooler, and Cohen's Kappa Calculator."""

import asyncio
import hashlib
import json
from pathlib import Path
import re

import constants as mjolnir_constants
from evaluation.constants import ORDERED_PIPELINE_PHASES, SEVERITY_RANKS
from evaluation.models import (
    CanonicalFinding,
    FindingOccurrence,
    FindingPoolMapping,
    InterRaterStats,
    PhaseTransitionStats,
    RootCauseJudgeVerdict,
    TrialRunRecord,
)
from utilities.logger import logger

CWE_CATALOG_PATH = Path(mjolnir_constants.__file__).resolve().parent / "data" / "cwe_catalog.json"

STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "in",
        "on",
        "of",
        "to",
        "for",
        "and",
        "or",
        "with",
        "by",
        "from",
        "at",
        "is",
        "are",
        "be",
        "can",
        "may",
        "when",
        "via",
        "due",
        "that",
        "this",
        "vulnerability",
        "finding",
        "issue",
        "flaw",
    }
)


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
        # Reset poc_verified unless reached poc_creation or final_review
        if "poc_creation" not in allowed_phases:
            reconstructed["poc_verified"] = False
            reconstructed["poc_code"] = None
        if "deduplication" not in allowed_phases:
            reconstructed["duplicate_of"] = None

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
            "duplicate_of",
        ):
            val = latest.get(key) if key in latest else nested.get(key)
            if val is not None:
                reconstructed[key] = val

        if (
            normalize_phase_id(latest.get("phase_id") or latest.get("phase_name"))
            == "deduplication"
        ):
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
    """Computes finding counts, close/duplicate rates, PoC verification, and severity shifts across each phase."""
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
            poc_ver = bool(h.get("poc_verified") or nested.get("poc_verified"))
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

            if poc_ver:
                st.poc_verified_count += 1

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

    def are_equivalent(self, reported_cwe: str | None, truth_cwe: str | None) -> bool:
        rep = self.normalize_cwe(reported_cwe)
        tru = self.normalize_cwe(truth_cwe)
        if not rep or not tru:
            return False
        if rep == tru:
            return True
        rep_anc = self.ancestors(rep, max_depth=2)
        tru_anc = self.ancestors(tru, max_depth=2)
        return tru in rep_anc or rep in tru_anc or bool(rep_anc & tru_anc - {"CWE-1000", "CWE-699"})


def extract_cwe_from_vuln(vuln: dict) -> str:
    """Extracts and normalizes a CWE identifier from a finding or its phase history."""
    for key in ("cwe", "cwe_id"):
        if vuln.get(key):
            return CweHierarchyMatcher.normalize_cwe(str(vuln[key]))
    for h in reversed(vuln.get("history", [])):
        if isinstance(h, dict):
            for key in ("cwe", "cwe_id"):
                if h.get(key):
                    return CweHierarchyMatcher.normalize_cwe(str(h[key]))
            finding = h.get("finding", {})
            if isinstance(finding, dict):
                for key in ("cwe", "cwe_id"):
                    if finding.get(key):
                        return CweHierarchyMatcher.normalize_cwe(str(finding[key]))
    return ""


def parse_line_range(location_str: str) -> tuple[int | None, int | None]:
    """Extracts (start_line, end_line) from a location string if line numbers are present."""
    nums = [int(m) for m in re.findall(r"\b(\d+)\b", str(location_str or ""))]
    if not nums:
        return None, None
    return min(nums), max(nums)


def sanitize_blind_text(text: str) -> str:
    """Strips tool-identifying prefixes or tags from titles and descriptions for blind review."""
    cleaned = re.sub(
        r"^\s*\[?\s*(?:mjolnir|semgrep|clippy|claude|codex|gemini|antigravity|openant)\s*\]?\s*[:\-]?\s*",
        "",
        str(text or ""),
        flags=re.IGNORECASE,
    )
    return cleaned.strip()


def keyword_tokens(text: str) -> set[str]:
    return {
        tok.lower()
        for tok in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", str(text or ""))
        if tok.lower() not in STOPWORDS
    }


def compute_inter_rater_stats(pool: list[CanonicalFinding]) -> InterRaterStats:
    """Computes raw agreement and Cohen's kappa across double-reviewed canonical findings."""
    stats = InterRaterStats(total_canonical_findings=len(pool))
    if not pool:
        return stats

    r1_labels: list[str] = []
    r2_labels: list[str] = []

    for cf in pool:
        r1 = CanonicalFinding._normalize_label(cf.reviewer_1_label)
        r2 = CanonicalFinding._normalize_label(cf.reviewer_2_label)
        resolved = cf.resolved_label
        if resolved == "TP":
            stats.confirmed_tp_count += 1
            stats.adjudicated_count += 1
        elif resolved == "FP":
            stats.confirmed_fp_count += 1
            stats.adjudicated_count += 1
        else:
            stats.unlabeled_count += 1

        if r1 in ("TP", "FP") and r2 in ("TP", "FP"):
            r1_labels.append(r1)
            r2_labels.append(r2)

    n = len(r1_labels)
    stats.double_reviewed_count = n
    if n == 0:
        return stats

    agree = sum(1 for a, b in zip(r1_labels, r2_labels) if a == b)
    p_o = agree / n
    stats.raw_agreement_rate = round(p_o, 4)

    p_r1_tp = sum(1 for a in r1_labels if a == "TP") / n
    p_r1_fp = 1.0 - p_r1_tp
    p_r2_tp = sum(1 for b in r2_labels if b == "TP") / n
    p_r2_fp = 1.0 - p_r2_tp
    p_e = (p_r1_tp * p_r2_tp) + (p_r1_fp * p_r2_fp)

    if abs(1.0 - p_e) < 1e-9:
        stats.cohens_kappa = 1.0 if abs(1.0 - p_o) < 1e-9 else 0.0
    else:
        stats.cohens_kappa = round((p_o - p_e) / (1.0 - p_e), 4)

    return stats


def _extract_duplicate_of_id(vuln: dict) -> str:
    """Extracts the canonical finding ID referenced by duplicate_of on a finding or its phase history."""
    raw = vuln.get("duplicate_of")
    if not raw:
        for h in reversed(vuln.get("history", [])):
            if isinstance(h, dict):
                raw = h.get("duplicate_of") or (
                    h.get("finding", {}).get("duplicate_of")
                    if isinstance(h.get("finding"), dict)
                    else None
                )
                if raw:
                    break
    if not raw:
        return ""
    return str(raw).strip().split("/")[-1]


class FindingPooler:
    """Clusters findings across all trials and checkpoints into a provenance-stripped blind review deck."""

    def __init__(self, judge_model: str | None = None):
        self.cwe_matcher = CweHierarchyMatcher()
        self.judge_model = judge_model

    def build_pool(
        self,
        trials: list[TrialRunRecord],
        output_dir: Path,
        existing_pool_path: Path | None = None,
    ) -> tuple[list[CanonicalFinding], list[FindingPoolMapping]]:
        """Clusters all trial findings, preserves any existing human labels, and writes blind review artifacts."""
        output_dir.mkdir(parents=True, exist_ok=True)
        existing_pool: list[CanonicalFinding] = []
        pool_file = existing_pool_path or (output_dir / "blind_review_pool.json")
        if pool_file.exists():
            try:
                raw_existing = json.loads(pool_file.read_text(encoding="utf-8"))
                existing_pool = [CanonicalFinding.model_validate(item) for item in raw_existing]
            except Exception as e:
                logger.warning(f"Could not load existing blind review pool from {pool_file}: {e}")

        # Pre-link intra-run duplicate_of chains across all trials and checkpoints so cross-file /
        # cross-line duplicates identified by Mjolnir's DeduplicationAgent map to the same root cause.
        dup_parent_map: dict[tuple[str, int, str], str] = {}
        for trial in trials:
            base_tier = trial.ablation_tier.split("@")[0]
            for vuln in trial.findings:
                fid = str(vuln.get("id") or "")
                dup_of = _extract_duplicate_of_id(vuln)
                if fid and dup_of and dup_of != fid:
                    dup_parent_map[(base_tier, trial.repetition, fid)] = dup_of

        def _resolve_root_fid(b_tier: str, rep_num: int, fid: str) -> str:
            cur = fid
            visited: set[str] = {cur}
            while (b_tier, rep_num, cur) in dup_parent_map:
                nxt = dup_parent_map[(b_tier, rep_num, cur)]
                if not nxt or nxt in visited:
                    break
                visited.add(nxt)
                cur = nxt
            return cur

        clusters: list[
            tuple[CanonicalFinding, list[FindingOccurrence], set[tuple[str, int, str]]]
        ] = []

        for trial in trials:
            base_tier = trial.ablation_tier.split("@")[0]
            # Process canonical root findings before findings marked duplicate_of
            ordered_findings = sorted(
                trial.findings,
                key=lambda v: 1
                if (base_tier, trial.repetition, str(v.get("id") or "")) in dup_parent_map
                else 0,
            )
            for vuln in ordered_findings:
                raw_file = (
                    str(vuln.get("file") or vuln.get("file_path") or "")
                    .replace("\\", "/")
                    .lstrip("./")
                )
                if not raw_file:
                    continue
                finding_id = str(vuln.get("id") or "")
                root_fid = (
                    _resolve_root_fid(base_tier, trial.repetition, finding_id) if finding_id else ""
                )
                cwe_str = extract_cwe_from_vuln(vuln)
                loc_str = str(vuln.get("location") or "Line 1")
                start_ln, end_ln = parse_line_range(loc_str)
                status_str = str(vuln.get("status") or "Open").capitalize()
                sev_str = str(vuln.get("severity") or "Medium").capitalize()
                poc_ver = bool(
                    vuln.get("poc_verified")
                    or (isinstance(vuln.get("poc"), dict) and vuln["poc"].get("verified"))
                )
                title_str = sanitize_blind_text(str(vuln.get("title") or "Security Finding"))
                desc_str = sanitize_blind_text(str(vuln.get("description") or ""))
                attack_vec_str = sanitize_blind_text(str(vuln.get("attack_vector") or ""))
                rec_str = sanitize_blind_text(str(vuln.get("recommendation") or ""))

                occ = FindingOccurrence(
                    ablation_tier=trial.ablation_tier,
                    repetition=trial.repetition,
                    finding_id=finding_id,
                    status=status_str,
                    severity=sev_str,
                    poc_verified=poc_ver,
                    cwe=cwe_str or None,
                    raw_title=title_str,
                    raw_location=loc_str,
                )
                run_identity = (base_tier, trial.repetition, finding_id)
                root_identity = (base_tier, trial.repetition, root_fid)

                matched_idx = None
                for idx, (_canon, _occs, run_ids) in enumerate(clusters):
                    if (finding_id and run_identity in run_ids) or (
                        root_fid and root_identity in run_ids
                    ):
                        matched_idx = idx
                        break

                if matched_idx is None:
                    is_mjolnir_run = base_tier.split("[")[0] in ("full", "no_tm", "no_expert")
                    for idx, (canon, _occs, run_ids) in enumerate(clusters):
                        if is_mjolnir_run and any(
                            b == base_tier and r == trial.repetition for (b, r, _) in run_ids
                        ):
                            continue
                        if self._findings_equivalent(
                            canon=canon,
                            file_path=raw_file,
                            loc_str=loc_str,
                            start_ln=start_ln,
                            end_ln=end_ln,
                            cwe_str=cwe_str,
                            title_str=title_str,
                            desc_str=desc_str,
                        ):
                            matched_idx = idx
                            break

                if matched_idx is not None:
                    canon, occs, run_ids = clusters[matched_idx]
                    occs.append(occ)
                    if finding_id:
                        run_ids.add(run_identity)
                    if root_fid:
                        run_ids.add(root_identity)
                    # Enrich canonical finding if a later checkpoint has fuller details or CWE
                    if not canon.cwe and cwe_str:
                        canon.cwe = cwe_str
                    if len(desc_str) > len(canon.description):
                        canon.description = desc_str
                    if len(attack_vec_str) > len(canon.attack_vector):
                        canon.attack_vector = attack_vec_str
                    if len(rec_str) > len(canon.recommendation):
                        canon.recommendation = rec_str
                    if start_ln is not None and canon.start_line is None:
                        canon.start_line = start_ln
                        canon.end_line = end_ln
                else:
                    new_canon = CanonicalFinding(
                        canonical_id="PENDING",
                        project_name=trial.project_name,
                        repo_name=trial.repo_name,
                        pinned_rev=trial.pinned_rev,
                        file=raw_file,
                        location=loc_str,
                        start_line=start_ln,
                        end_line=end_ln,
                        cwe=cwe_str,
                        severity=sev_str,
                        title=title_str,
                        description=desc_str,
                        attack_vector=attack_vec_str,
                        recommendation=rec_str,
                    )
                    id_set: set[tuple[str, int, str]] = set()
                    if finding_id:
                        id_set.add(run_identity)
                    if root_fid:
                        id_set.add(root_identity)
                    clusters.append((new_canon, [occ], id_set))

        # Deterministic hash order so blind review cards do not leak tool execution order
        clusters.sort(
            key=lambda item: hashlib.sha256(
                f"{item[0].repo_name}:{item[0].file}:{item[0].start_line or 0}:{item[0].cwe}".encode(
                    "utf-8"
                )
            ).hexdigest()
        )

        canonical_pool: list[CanonicalFinding] = []
        pool_mappings: list[FindingPoolMapping] = []

        for idx, (canon, occs, _run_ids) in enumerate(clusters, start=1):
            cid = f"CF-{idx:04d}"
            canon.canonical_id = cid

            # Restore any prior human labels if an equivalent canonical finding already existed
            for prev in existing_pool:
                if self._findings_equivalent(
                    canon=prev,
                    file_path=canon.file,
                    loc_str=canon.location,
                    start_ln=canon.start_line,
                    end_ln=canon.end_line,
                    cwe_str=canon.cwe,
                    title_str=canon.title,
                    desc_str=canon.description,
                ):
                    canon.reviewer_1_label = prev.reviewer_1_label
                    canon.reviewer_2_label = prev.reviewer_2_label
                    canon.adjudicated_label = prev.adjudicated_label
                    canon.maintainer_status = prev.maintainer_status
                    canon.notes = prev.notes
                    break

            canonical_pool.append(canon)
            pool_mappings.append(FindingPoolMapping(canonical_id=cid, occurrences=occs))

        (output_dir / "blind_review_pool.json").write_text(
            json.dumps([c.model_dump() for c in canonical_pool], indent=2),
            encoding="utf-8",
        )
        (output_dir / "finding_pool_mapping.json").write_text(
            json.dumps([m.model_dump() for m in pool_mappings], indent=2),
            encoding="utf-8",
        )
        (output_dir / "blind_review_pool.md").write_text(
            self._render_blind_review_markdown(canonical_pool),
            encoding="utf-8",
        )
        self._write_blind_review_web_bundle(canonical_pool, output_dir / "blind_review")
        logger.success(
            f"Exported {len(canonical_pool)} canonical findings to {output_dir / 'blind_review_pool.json'} "
            f"(and hidden provenance map to {output_dir / 'finding_pool_mapping.json'})"
        )
        return canonical_pool, pool_mappings

    def _findings_equivalent(
        self,
        canon: CanonicalFinding,
        file_path: str,
        loc_str: str,
        start_ln: int | None,
        end_ln: int | None,
        cwe_str: str,
        title_str: str,
        desc_str: str,
    ) -> bool:
        # Step 1: File & Span Localization Check
        c_file = canon.file.replace("\\", "/").lstrip("./")
        f_file = file_path.replace("\\", "/").lstrip("./")
        if not (c_file == f_file or c_file.endswith("/" + f_file) or f_file.endswith("/" + c_file)):
            return False

        margin = 35
        span_overlap = False
        if canon.start_line is not None and start_ln is not None:
            c_end = canon.end_line if canon.end_line is not None else canon.start_line
            f_end = end_ln if end_ln is not None else start_ln
            if (canon.start_line - margin) <= f_end and (start_ln - margin) <= c_end:
                span_overlap = True

        file_tokens = keyword_tokens(file_path) | {
            "line",
            "lines",
            "function",
            "rs",
            "sv",
            "c",
            "h",
            "cpp",
            "py",
        }
        loc_tokens_a = keyword_tokens(canon.location) - file_tokens
        loc_tokens_b = keyword_tokens(loc_str) - file_tokens
        shared_func = bool(loc_tokens_a and loc_tokens_b and (loc_tokens_a & loc_tokens_b))

        cwe_equiv = bool(
            canon.cwe and cwe_str and self.cwe_matcher.are_equivalent(canon.cwe, cwe_str)
        )
        toks_a = keyword_tokens(f"{canon.title} {canon.description}")
        toks_b = keyword_tokens(f"{title_str} {desc_str}")
        kw_jaccard = (len(toks_a & toks_b) / len(toks_a | toks_b)) if (toks_a and toks_b) else 0.0

        if not span_overlap and not shared_func:
            if not cwe_equiv and kw_jaccard < 0.25:
                return False

        # Step 2: Semantic Root-Cause Equivalence
        if self.judge_model and self.judge_model not in ("mock", "heuristic"):
            verdict = self._run_llm_equivalence_judge(
                canon=canon,
                file_path=file_path,
                loc_str=loc_str,
                cwe_str=cwe_str,
                title_str=title_str,
                desc_str=desc_str,
            )
            if verdict is not None:
                return verdict.is_match

        if cwe_equiv and (span_overlap or shared_func or kw_jaccard >= 0.35):
            return True

        if kw_jaccard >= 0.30 and (span_overlap or shared_func or not canon.start_line):
            return True

        if (
            canon.start_line is not None
            and start_ln is not None
            and abs(canon.start_line - start_ln) <= 10
            and (not canon.cwe or not cwe_str or cwe_equiv)
        ):
            return True

        return False

    def _run_llm_equivalence_judge(
        self,
        canon: CanonicalFinding,
        file_path: str,
        loc_str: str,
        cwe_str: str,
        title_str: str,
        desc_str: str,
    ) -> RootCauseJudgeVerdict | None:
        try:
            from google.adk.runners import Runner
            from google.adk.sessions import InMemorySessionService
            from google.genai import types
            from providers.adk.agents.isolated_agent import IsolatedAgent
            from providers.adk.utilities.async_runner import extract_agent_output

            judge_agent = IsolatedAgent(
                name="RootCauseEquivalenceJudge",
                model=self.judge_model,
                instruction=(
                    "You are an impartial security evaluation judge. Given two vulnerability findings "
                    "reported in the same source file, determine whether they identify the SAME underlying "
                    "security flaw / root-cause mechanism. Return is_match=False if they describe distinct "
                    "bugs that merely reside in the same function or nearby lines."
                ),
                output_schema=RootCauseJudgeVerdict,
                tools=[],
            )
            prompt = json.dumps(
                {
                    "finding_a": {
                        "file": canon.file,
                        "location": canon.location,
                        "cwe": canon.cwe,
                        "title": canon.title,
                        "description": canon.description,
                    },
                    "finding_b": {
                        "file": file_path,
                        "location": loc_str,
                        "cwe": cwe_str,
                        "title": title_str,
                        "description": desc_str,
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
            logger.warning(f"LLM root-cause equivalence judge fallback to heuristic: {e}")
            return None

    @staticmethod
    def _render_blind_review_markdown(pool: list[CanonicalFinding]) -> str:
        lines = [
            "# Blind Dual-Expert Vulnerability Review Deck",
            "",
            "Each canonical finding below has been stripped of tool/tier provenance and shuffled.",
            "Record independent labels (`TP` or `FP`) in `blind_review_pool.json`.",
            "",
        ]
        for cf in pool:
            r1 = cf.reviewer_1_label or "Unlabeled"
            r2 = cf.reviewer_2_label or "Unlabeled"
            adj = cf.resolved_label or "Pending"
            lines.extend(
                [
                    f"## `{cf.canonical_id}` — {cf.title}",
                    f"- **Project**: `{cf.repo_name}` (`{cf.pinned_rev[:12]}`)",
                    f"- **File**: `{cf.file}` ({cf.location})",
                    f"- **CWE / Severity**: `{cf.cwe or 'N/A'}` | `{cf.severity}`",
                    f"- **Review Status**: Reviewer 1: `{r1}` | Reviewer 2: `{r2}` | Resolved: `{adj}`",
                    "",
                    f"{cf.description}",
                ]
            )
            if cf.attack_vector:
                lines.extend(["", f"### Attack Vector\n{cf.attack_vector}"])
            if cf.recommendation:
                lines.extend(["", f"### Recommendation\n{cf.recommendation}"])
            lines.extend(["", "---", ""])
        return "\n".join(lines)

    @staticmethod
    def _write_blind_review_web_bundle(pool: list[CanonicalFinding], web_dir: Path) -> None:
        """Emits a provenance-stripped Web-UI run directory so reviewers can inspect the blind pool in web-viewer."""
        web_dir.mkdir(parents=True, exist_ok=True)
        repo_name = pool[0].repo_name if pool else "evaluation"
        pinned_rev = pool[0].pinned_rev if pool else "HEAD"
        metadata = {
            "repo": repo_name,
            "model": "Blind Review Pool (Provenance-Stripped)",
            "ref": pinned_rev[:12],
            "target_commit": pinned_rev,
            "timestamp": "2026-01-01T00:00:00Z",
            "mode": "Blind Dual-Expert Review",
            "trigger": "mjolnir-eval pool",
            "auth_mode": "Blind Review",
            "status": "Success",
        }
        vulns = [
            {
                "id": cf.canonical_id,
                "file": cf.file,
                "title": cf.title,
                "severity": cf.severity,
                "location": cf.location,
                "description": cf.description,
                "attack_vector": cf.attack_vector,
                "recommendation": cf.recommendation,
                "cwe": cf.cwe,
                "status": "Open",
                "history": [],
            }
            for cf in pool
        ]
        (web_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        (web_dir / "vulnerabilities.json").write_text(json.dumps(vulns, indent=2), encoding="utf-8")
        (web_dir / "vulnerabilities_minimal.json").write_text(
            json.dumps(vulns, indent=2), encoding="utf-8"
        )
