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
    first = nums[0]
    near = [n for n in nums if abs(n - first) <= 80]
    return min(near), max(near)


def sanitize_blind_text(text: str) -> str:
    """Strips tool-identifying and verdict-leaking prefixes from titles and descriptions for blind review."""
    cleaned = re.sub(
        r"^\s*\[?\s*(?:mjolnir|claude|codex|gemini)\s*\]?\s*[:\-]?\s*",
        "",
        str(text or ""),
        flags=re.IGNORECASE,
    )
    cleaned = re.sub(
        r"^\s*\[?\s*(?:false\s+positive|disproven|not\s+a\s+vulnerability|closed)\s*\]?\s*[:\-]\s*",
        "",
        cleaned,
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
            if r1 != r2 and resolved is None:
                stats.disputed_unadjudicated_count += 1

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
        self._genai_client = None
        self._judge_cache: dict[str, RootCauseJudgeVerdict] = {}

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

        # Reuse previous cluster decisions from finding_pool_mapping.json so incremental runs
        # do not re-invoke the LLM judge on already-clustered trials.
        prev_cid_by_run_id: dict[tuple[str, int, str, str], str] = {}
        mapping_file = output_dir / "finding_pool_mapping.json"
        if mapping_file.exists():
            try:
                raw_mappings = json.loads(mapping_file.read_text(encoding="utf-8"))
                for m_item in raw_mappings:
                    m_obj = FindingPoolMapping.model_validate(m_item)
                    for occ in m_obj.occurrences:
                        if occ.finding_id:
                            b_tier = occ.ablation_tier.split("@")[0]
                            prev_cid_by_run_id[
                                (b_tier, occ.repetition, occ.finding_id, occ.raw_title or "")
                            ] = m_obj.canonical_id
            except Exception as e:
                logger.warning(f"Could not load existing finding_pool_mapping.json: {e}")

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

        def _open_rank(tier_name: str, status_val: str) -> int:
            if status_val.lower() != "open":
                return 0
            return 2 if "@" not in tier_name else 1

        # Pre-index the best Open vulnerability text per (base_tier, repetition, finding_id) so
        # findings that were closed in initial_review/final_review never seed clusters with
        # verifier disproof text ("False Positive: ...", "The audit finding alleges...").
        best_open_text_by_run_id: dict[tuple[str, int, str], tuple[int, dict[str, str]]] = {}
        for trial in trials:
            base_tier = trial.ablation_tier.split("@")[0]
            for vuln in trial.findings:
                fid = str(vuln.get("id") or "")
                if not fid:
                    continue
                raw_status = vuln.get("status") or "Open"
                status_val = (
                    str(getattr(raw_status, "value", raw_status)).split(".")[-1].capitalize()
                )
                rank = _open_rank(trial.ablation_tier, status_val)
                if rank == 0:
                    continue
                t_str = sanitize_blind_text(str(vuln.get("title") or "Security Finding"))
                d_str = sanitize_blind_text(str(vuln.get("description") or ""))
                av_str = sanitize_blind_text(str(vuln.get("attack_vector") or ""))
                rc_str = sanitize_blind_text(str(vuln.get("recommendation") or ""))
                sv_str = str(vuln.get("severity") or "Medium").capitalize()
                cw_str = extract_cwe_from_vuln(vuln)
                lc_str = str(vuln.get("location") or "Line 1")
                for key_id in {fid, _resolve_root_fid(base_tier, trial.repetition, fid)}:
                    if not key_id:
                        continue
                    k = (base_tier, trial.repetition, key_id)
                    prev_entry = best_open_text_by_run_id.get(k)
                    if (
                        prev_entry is None
                        or rank > prev_entry[0]
                        or (
                            rank == prev_entry[0] and len(d_str) > len(prev_entry[1]["description"])
                        )
                    ):
                        best_open_text_by_run_id[k] = (
                            rank,
                            {
                                "title": t_str,
                                "description": d_str,
                                "attack_vector": av_str,
                                "recommendation": rc_str,
                                "severity": sv_str,
                                "cwe": cw_str,
                                "location": lc_str,
                            },
                        )

        clusters: list[
            tuple[CanonicalFinding, list[FindingOccurrence], set[tuple[str, int, str]]]
        ] = []
        cluster_best_rank: list[int] = []

        mapped_trial_keys = {(b, r) for (b, r, _, _) in prev_cid_by_run_id}
        ordered_trials = sorted(
            trials,
            key=lambda t: 0
            if (t.ablation_tier.split("@")[0], t.repetition) in mapped_trial_keys
            else 1,
        )

        for trial in ordered_trials:
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
                raw_st = vuln.get("status") or "Open"
                status_str = str(getattr(raw_st, "value", raw_st)).split(".")[-1].capitalize()
                raw_sv = vuln.get("severity") or "Medium"
                sev_str = str(getattr(raw_sv, "value", raw_sv)).split(".")[-1].capitalize()
                poc_ver = bool(
                    vuln.get("poc_verified")
                    or (isinstance(vuln.get("poc"), dict) and vuln["poc"].get("verified"))
                )
                raw_title_str = sanitize_blind_text(str(vuln.get("title") or "Security Finding"))
                title_str = raw_title_str
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
                    raw_title=raw_title_str,
                    raw_location=loc_str,
                )
                run_identity = (base_tier, trial.repetition, finding_id)
                root_identity = (base_tier, trial.repetition, root_fid)

                cur_rank = _open_rank(trial.ablation_tier, status_str)
                if cur_rank == 0:
                    fallback_open = best_open_text_by_run_id.get(
                        run_identity
                    ) or best_open_text_by_run_id.get(root_identity)
                    if fallback_open is not None:
                        cur_rank, open_fields = fallback_open
                        title_str = open_fields["title"] or title_str
                        desc_str = open_fields["description"] or desc_str
                        attack_vec_str = open_fields["attack_vector"] or attack_vec_str
                        rec_str = open_fields["recommendation"] or rec_str
                        sev_str = open_fields["severity"] or sev_str
                        cwe_str = cwe_str or open_fields["cwe"]

                matched_idx = None
                prev_cid = prev_cid_by_run_id.get(
                    (base_tier, trial.repetition, finding_id, raw_title_str)
                ) or (
                    prev_cid_by_run_id.get((base_tier, trial.repetition, root_fid, title_str))
                    if root_fid
                    else None
                )
                for idx, (_canon, _occs, run_ids) in enumerate(clusters):
                    if (
                        (finding_id and run_identity in run_ids)
                        or (root_fid and root_identity in run_ids)
                        or (prev_cid and ("__prev_cid__", 0, prev_cid) in run_ids)
                    ):
                        matched_idx = idx
                        break

                if matched_idx is None and prev_cid is None:
                    is_mjolnir_run = base_tier.split("[")[0] in ("full", "no_tm", "no_expert")
                    cand_canons: list[tuple[int, CanonicalFinding]] = []
                    for idx, (canon, _occs, run_ids) in enumerate(clusters):
                        if is_mjolnir_run and any(
                            b == base_tier and r == trial.repetition
                            for (b, r, _) in run_ids
                            if b != "__prev_cid__"
                        ):
                            continue
                        c_file = canon.file.replace("\\", "/").lstrip("./")
                        if not (
                            c_file == raw_file
                            or c_file.endswith("/" + raw_file)
                            or raw_file.endswith("/" + c_file)
                        ):
                            continue
                        cand_canons.append((idx, canon))

                    # Pass 1: check fast deterministic equivalence across all candidates before invoking LLM judge
                    for idx, canon in cand_canons:
                        if self._findings_equivalent(
                            canon=canon,
                            file_path=raw_file,
                            loc_str=loc_str,
                            start_ln=start_ln,
                            end_ln=end_ln,
                            cwe_str=cwe_str,
                            title_str=title_str,
                            desc_str=desc_str,
                            use_llm=False,
                        ):
                            matched_idx = idx
                            break

                    if (
                        matched_idx is None
                        and cand_canons
                        and self.judge_model
                        and self.judge_model not in ("mock", "heuristic")
                    ):
                        if self._genai_client is None:
                            import os
                            from google.genai import Client, types

                            os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "false"
                            vertexai = not bool(os.environ.get("GEMINI_API_KEY"))
                            self._genai_client = Client(
                                vertexai=vertexai,
                                location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
                                if vertexai
                                else None,
                                http_options=types.HttpOptions(
                                    timeout=30000,
                                    retry_options=types.HttpRetryOptions(
                                        attempts=3, initial_delay=1.0, max_delay=10.0
                                    ),
                                ),
                            )

                        if len(cand_canons) > 1:
                            from concurrent.futures import ThreadPoolExecutor

                            with ThreadPoolExecutor(max_workers=min(8, len(cand_canons))) as ex:
                                results = list(
                                    ex.map(
                                        lambda item: self._findings_equivalent(
                                            canon=item[1],
                                            file_path=raw_file,
                                            loc_str=loc_str,
                                            start_ln=start_ln,
                                            end_ln=end_ln,
                                            cwe_str=cwe_str,
                                            title_str=title_str,
                                            desc_str=desc_str,
                                            use_llm=True,
                                        ),
                                        cand_canons,
                                    )
                                )
                            for (idx, _canon), is_eq in zip(cand_canons, results):
                                if is_eq:
                                    matched_idx = idx
                                    break
                        else:
                            idx, canon = cand_canons[0]
                            if self._findings_equivalent(
                                canon=canon,
                                file_path=raw_file,
                                loc_str=loc_str,
                                start_ln=start_ln,
                                end_ln=end_ln,
                                cwe_str=cwe_str,
                                title_str=title_str,
                                desc_str=desc_str,
                                use_llm=True,
                            ):
                                matched_idx = idx

                if matched_idx is not None:
                    canon, occs, run_ids = clusters[matched_idx]
                    prev_rank = cluster_best_rank[matched_idx]
                    occs.append(occ)
                    if finding_id:
                        run_ids.add(run_identity)
                    if root_fid:
                        run_ids.add(root_identity)
                    if prev_cid:
                        run_ids.add(("__prev_cid__", 0, prev_cid))
                    # Enrich canonical finding, strictly preferring Open text over Closed disproof text
                    if not canon.cwe and cwe_str:
                        canon.cwe = cwe_str
                    if cur_rank > prev_rank:
                        if title_str:
                            canon.title = title_str
                        if desc_str:
                            canon.description = desc_str
                        if attack_vec_str:
                            canon.attack_vector = attack_vec_str
                        if rec_str:
                            canon.recommendation = rec_str
                        if sev_str:
                            canon.severity = sev_str
                        cluster_best_rank[matched_idx] = cur_rank
                    elif cur_rank == prev_rank:
                        if len(desc_str) > len(canon.description):
                            canon.description = desc_str
                            if title_str:
                                canon.title = title_str
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
                    if prev_cid:
                        id_set.add(("__prev_cid__", 0, prev_cid))
                    clusters.append((new_canon, [occ], id_set))
                    cluster_best_rank.append(cur_rank)

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

        labeled_existing_pool = [
            prev
            for prev in existing_pool
            if (
                prev.reviewer_1_label
                or prev.reviewer_2_label
                or prev.adjudicated_label
                or prev.maintainer_status
                or prev.notes
            )
        ]
        labeled_by_cid = {prev.canonical_id: prev for prev in labeled_existing_pool}

        for idx, (canon, occs, _run_ids) in enumerate(clusters, start=1):
            cid = f"CF-{idx:04d}"
            canon.canonical_id = cid

            # Restore any prior human labels if an equivalent canonical finding already existed
            matched_prev: CanonicalFinding | None = None
            for b_key, _, p_cid in _run_ids:
                if b_key == "__prev_cid__" and p_cid in labeled_by_cid:
                    matched_prev = labeled_by_cid[p_cid]
                    break
            if matched_prev is None:
                for prev in labeled_existing_pool:
                    if self._findings_equivalent(
                        canon=prev,
                        file_path=canon.file,
                        loc_str=canon.location,
                        start_ln=canon.start_line,
                        end_ln=canon.end_line,
                        cwe_str=canon.cwe,
                        title_str=canon.title,
                        desc_str=canon.description,
                        use_llm=False,
                    ):
                        matched_prev = prev
                        break
            if matched_prev is not None:
                canon.reviewer_1_label = matched_prev.reviewer_1_label
                canon.reviewer_2_label = matched_prev.reviewer_2_label
                canon.adjudicated_label = matched_prev.adjudicated_label
                canon.maintainer_status = matched_prev.maintainer_status
                canon.notes = matched_prev.notes

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
        use_llm: bool = True,
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
            "execute",
            "new",
            "run",
            "init",
            "main",
            "default",
            "from",
            "into",
            "try_from",
            "cmd",
            "command",
            "rs",
            "sv",
            "c",
            "h",
            "cpp",
            "py",
        }
        loc_a_unqual = re.sub(r"[A-Za-z0-9_]+::", "", str(canon.location or ""))
        loc_b_unqual = re.sub(r"[A-Za-z0-9_]+::", "", str(loc_str or ""))
        loc_tokens_a = keyword_tokens(loc_a_unqual) - file_tokens
        loc_tokens_b = keyword_tokens(loc_b_unqual) - file_tokens
        both_have_lines = canon.start_line is not None and start_ln is not None
        lines_far_apart = (
            both_have_lines
            and not span_overlap
            and abs((canon.start_line or 0) - (start_ln or 0)) > (2 * margin)
        )
        shared_func = bool(
            not lines_far_apart and loc_tokens_a and loc_tokens_b and (loc_tokens_a & loc_tokens_b)
        )

        cwe_equiv = bool(
            canon.cwe and cwe_str and self.cwe_matcher.are_equivalent(canon.cwe, cwe_str)
        )
        toks_a = keyword_tokens(f"{canon.title} {canon.description}")
        toks_b = keyword_tokens(f"{title_str} {desc_str}")
        kw_jaccard = (len(toks_a & toks_b) / len(toks_a | toks_b)) if (toks_a and toks_b) else 0.0

        if not span_overlap and not shared_func:
            if both_have_lines or (not cwe_equiv and kw_jaccard < 0.25):
                return False

        # Step 2: CWE Hierarchy or Semantic Root-Cause Equivalence
        if cwe_equiv and (span_overlap or shared_func or kw_jaccard >= 0.35):
            return True

        if not use_llm:
            return False

        if (
            kw_jaccard >= 0.08
            and self.judge_model
            and self.judge_model not in ("mock", "heuristic")
        ):
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
            import os
            from google.genai import Client, types

            prompt = json.dumps(
                {
                    "finding_a": {
                        "file": canon.file,
                        "location": canon.location,
                        "cwe": canon.cwe,
                        "title": canon.title,
                        "description": canon.description[:600],
                    },
                    "finding_b": {
                        "file": file_path,
                        "location": loc_str,
                        "cwe": cwe_str,
                        "title": title_str,
                        "description": desc_str[:600],
                    },
                },
                indent=2,
            )
            cache_key = hashlib.sha256(
                json.dumps(
                    [
                        canon.file,
                        canon.location,
                        canon.cwe,
                        canon.title,
                        file_path,
                        loc_str,
                        cwe_str,
                        title_str,
                    ]
                ).encode("utf-8")
            ).hexdigest()
            if cache_key in self._judge_cache:
                return self._judge_cache[cache_key]

            if self._genai_client is None:
                os.environ["GOOGLE_API_USE_CLIENT_CERTIFICATE"] = "false"
                vertexai = not bool(os.environ.get("GEMINI_API_KEY"))
                self._genai_client = Client(
                    vertexai=vertexai,
                    location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global")
                    if vertexai
                    else None,
                    http_options=types.HttpOptions(
                        timeout=30000,
                        retry_options=types.HttpRetryOptions(
                            attempts=3, initial_delay=1.0, max_delay=10.0
                        ),
                    ),
                )

            resp = self._genai_client.models.generate_content(
                model=self.judge_model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=(
                        "You are an impartial security evaluation judge. Given two vulnerability findings "
                        "reported in the same source file, determine whether they identify the SAME underlying "
                        "security flaw / root-cause mechanism. Return is_match=False if they describe distinct "
                        "bugs that merely reside in the same function or nearby lines. Keep rationale under 15 words."
                    ),
                    response_mime_type="application/json",
                    response_schema=RootCauseJudgeVerdict,
                    thinking_config=types.ThinkingConfig(thinking_budget=0),
                ),
            )
            parsed = getattr(resp, "parsed", None) or (
                json.loads(resp.text) if getattr(resp, "text", None) else None
            )
            verdict = RootCauseJudgeVerdict.model_validate(parsed) if parsed else None
            if verdict is not None:
                self._judge_cache[cache_key] = verdict
            return verdict
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
