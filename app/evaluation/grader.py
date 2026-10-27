# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Phase-Checkpoint Extractor, Per-Finding Blind Review Deck Builder, and Cohen's Kappa Calculator."""

import hashlib
import json
from pathlib import Path
import re

from evaluation.constants import ORDERED_PIPELINE_PHASES, SEVERITY_RANKS
from evaluation.models import (
    BlindReviewFinding,
    InterRaterStats,
    PhaseTransitionStats,
    TrialRunRecord,
)
from utilities.logger import logger

GITHUB_REPO_URLS: dict[str, str] = {
    "caliptra-sw": "https://github.com/chipsalliance/caliptra-sw",
    "caliptra-sw-v210": "https://github.com/chipsalliance/caliptra-sw",
    "caliptra-mcu-sw": "https://github.com/chipsalliance/caliptra-mcu-sw",
    "caliptra-dpe": "https://github.com/chipsalliance/caliptra-dpe",
    "opentitan": "https://github.com/lowRISC/opentitan",
    "opentitan-fw": "https://github.com/lowRISC/opentitan",
    "opentitan-rtl": "https://github.com/lowRISC/opentitan",
    "openprot": "https://github.com/openprot/openprot",
}


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


def normalize_cwe(raw: str | None) -> str:
    """Normalizes a CWE string (e.g. 'CWE-190: Integer Overflow') to 'CWE-190'."""
    if not raw:
        return ""
    m = re.search(r"CWE-(\d+)", str(raw), re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else str(raw).strip().upper()


def extract_cwe_from_vuln(vuln: dict) -> str:
    """Extracts and normalizes a CWE identifier from a finding or its phase history."""
    for key in ("cwe", "cwe_id"):
        if vuln.get(key):
            return normalize_cwe(str(vuln[key]))
    for h in reversed(vuln.get("history", [])):
        if isinstance(h, dict):
            for key in ("cwe", "cwe_id"):
                if h.get(key):
                    return normalize_cwe(str(h[key]))
            finding = h.get("finding", {})
            if isinstance(finding, dict):
                for key in ("cwe", "cwe_id"):
                    if finding.get(key):
                        return normalize_cwe(str(finding[key]))
    return ""


def parse_line_range(location_str: str) -> tuple[int | None, int | None]:
    """Extracts (start_line, end_line) from a location string if line numbers are present."""
    nums = [
        int(m) for m in re.findall(r"(?:^|(?<![A-Za-z0-9_])|[Ll])(\d+)\b", str(location_str or ""))
    ]
    if not nums:
        return None, None
    first = nums[0]
    near = [n for n in nums if abs(n - first) <= 80]
    return min(near), max(near)


def build_github_permalink(
    repo_name: str,
    pinned_rev: str,
    file_path: str,
    start_line: int | None = None,
    end_line: int | None = None,
) -> str | None:
    """Builds a GitHub blob permalink for the pinned commit and source line range when known."""
    base_url = GITHUB_REPO_URLS.get(str(repo_name or "").strip().lower())
    rev = str(pinned_rev or "").strip()
    clean_file = str(file_path or "").replace("\\", "/").lstrip("./")
    if not base_url or not rev or rev.upper() == "HEAD" or not clean_file:
        return None
    url = f"{base_url}/blob/{rev}/{clean_file}"
    if start_line is not None and start_line > 0:
        if end_line is not None and end_line > start_line:
            return f"{url}#L{start_line}-L{end_line}"
        return f"{url}#L{start_line}"
    return url


def discover_pinned_source_tree(
    repo_name: str,
    pinned_rev: str = "",
    explicit_root: Path | None = None,
) -> Path | None:
    """Locates the immutable Nix-pinned source checkout for (repo_name, pinned_rev) when present on disk."""
    if explicit_root is not None and explicit_root.is_dir():
        return explicit_root.resolve()
    nix_store = Path("/nix/store")
    if not nix_store.is_dir():
        return None
    r_lower = str(repo_name or "").strip().lower()
    rev_clean = str(pinned_rev or "").strip().lower()
    fallback_match: Path | None = None
    for spec_path in sorted(nix_store.glob("*-mjolnir-eval-spec-*.json")):
        try:
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        proj = spec.get("project") if isinstance(spec, dict) else None
        if not isinstance(proj, dict):
            continue
        if str(proj.get("repoName") or "").strip().lower() != r_lower:
            continue
        nsrc_str = str(proj.get("nixSourcePath") or "").strip()
        if not nsrc_str:
            continue
        nsrc = Path(nsrc_str).resolve()
        if not nsrc.is_dir() or not nsrc.is_relative_to(nix_store.resolve()):
            continue
        spec_rev = str(proj.get("pinnedRev") or "").strip().lower()
        if rev_clean and spec_rev == rev_clean:
            return nsrc
        fallback_match = nsrc
    return fallback_match


def _find_brace_block_end(lines: list[str], start_idx: int, max_span: int = 55) -> int:
    depth = 0
    saw_open = False
    limit = min(len(lines), start_idx + max_span)
    for i in range(start_idx, limit):
        code = lines[i].split("//", 1)[0]
        opens = code.count("{")
        closes = code.count("}")
        if opens > 0:
            saw_open = True
        depth += opens - closes
        if saw_open and depth <= 0 and i > start_idx:
            return i + 1
    return min(len(lines), start_idx + min(30, max_span))


def resolve_source_span(
    lines: list[str],
    start_line: int | None,
    end_line: int | None,
    location_str: str = "",
    description: str = "",
) -> tuple[int, int]:
    """Resolves 1-based (focus_start_line, focus_end_line) from numeric lines or symbol/function names."""
    n = len(lines)
    if n == 0:
        return 1, 1
    if start_line and 1 <= start_line <= n:
        end_resolved = end_line if (end_line and start_line <= end_line <= n) else start_line
        if end_resolved == start_line:
            end_resolved = _find_brace_block_end(lines, start_line - 1, max_span=32)
        return start_line, min(n, max(start_line, end_resolved))

    clean_loc = str(location_str or "")
    if ":" in clean_loc and (
        "/" in clean_loc.split(":", 1)[0] or "." in clean_loc.split(":", 1)[0]
    ):
        clean_loc = clean_loc.split(":", 1)[1]

    stop_tokens = {
        "fn",
        "pub",
        "impl",
        "struct",
        "enum",
        "mod",
        "in",
        "and",
        "or",
        "line",
        "lines",
        "function",
        "method",
        "the",
        "of",
        "src",
        "rs",
        "c",
        "h",
        "sv",
    }
    raw_syms = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", clean_loc)
    syms = [s for s in reversed(raw_syms) if s.lower() not in stop_tokens and len(s) >= 3]
    pairs = re.findall(
        r"([A-Za-z_][A-Za-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)", str(location_str or "")
    )

    for typ, meth in pairs:
        in_impl = False
        for idx, ln in enumerate(lines):
            if re.search(rf"\bimpl\b.*\b{re.escape(typ)}\b", ln):
                in_impl = True
            if in_impl and re.search(rf"\bfn\s+{re.escape(meth)}\b", ln):
                return idx + 1, _find_brace_block_end(lines, idx)

    def_patterns = [
        lambda s: rf"\b(?:fn|struct|enum|trait|union|const|static|type|module)\s+{re.escape(s)}\b",
        lambda s: rf"^\s*(?:[A-Za-z_][A-Za-z0-9_\s\*]*\s+)?{re.escape(s)}\s*\(",
        lambda s: rf"\b{re.escape(s)}\b",
    ]
    for pat_fn in def_patterns:
        for sym in syms:
            for idx, ln in enumerate(lines):
                if re.search(pat_fn(sym), ln):
                    return idx + 1, _find_brace_block_end(lines, idx)

    for sym in re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", description or ""):
        if len(sym) >= 4 and sym.lower() not in stop_tokens:
            for idx, ln in enumerate(lines):
                if re.search(rf"\b(?:fn|struct|enum|const)\s+{re.escape(sym)}\b", ln) or re.search(
                    rf"\b{re.escape(sym)}\b", ln
                ):
                    return idx + 1, _find_brace_block_end(lines, idx)

    return 1, min(n, 40)


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


def _extract_duplicate_of_id(vuln: dict) -> str:
    """Extracts the finding ID referenced by duplicate_of on a finding or its phase history."""
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


def compute_inter_rater_stats(pool: list[BlindReviewFinding]) -> InterRaterStats:
    """Computes raw agreement, Cohen's kappa, and expert-pass summary counts across blind review findings."""
    in_sample = [bf for bf in pool if bf.in_blind_sample]
    stats = InterRaterStats(
        total_findings=len(pool),
        in_sample_findings=len(in_sample),
        expert_severity_counts={
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        },
        poc_demonstrates_counts={"yes": 0, "no": 0},
    )
    if not in_sample:
        return stats

    r1_labels: list[str] = []
    r2_labels: list[str] = []

    for bf in in_sample:
        r1 = BlindReviewFinding._normalize_label(bf.reviewer_1_label)
        r2 = BlindReviewFinding._normalize_label(bf.reviewer_2_label)
        if bf.is_excluded:
            stats.excluded_count += 1
        else:
            resolved = bf.resolved_label
            if resolved == "TP":
                stats.confirmed_tp_count += 1
                stats.adjudicated_count += 1
                exp_sev = bf.normalized_expert_severity
                if exp_sev:
                    stats.expert_severity_counts[exp_sev] = (
                        stats.expert_severity_counts.get(exp_sev, 0) + 1
                    )
                    if exp_sev in ("Critical", "High", "Medium"):
                        stats.confirmed_tp_medium_or_above_count += 1
            elif resolved == "FP":
                stats.confirmed_fp_count += 1
                stats.adjudicated_count += 1
            else:
                stats.unlabeled_count += 1

        poc_dem = bf.normalized_poc_demonstrates
        if poc_dem:
            stats.poc_demonstrates_counts[poc_dem] = (
                stats.poc_demonstrates_counts.get(poc_dem, 0) + 1
            )

        if r1 in ("TP", "FP") and r2 in ("TP", "FP"):
            r1_labels.append(r1)
            r2_labels.append(r2)
            if r1 != r2 and not bf.is_excluded and bf.resolved_label is None:
                stats.disputed_unadjudicated_count += 1
        elif (r1 in ("TP", "FP")) ^ (r2 in ("TP", "FP")):
            stats.single_reviewed_count += 1

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


class FindingPooler:
    """Builds a provenance-stripped per-finding blind review deck across evaluation trials."""

    @staticmethod
    def _status_str(vuln: dict) -> str:
        raw_st = vuln.get("status") or "Open"
        return str(getattr(raw_st, "value", raw_st)).split(".")[-1].capitalize()

    @staticmethod
    def _extract_fields(vuln: dict) -> dict[str, str]:
        raw_sv = vuln.get("severity") or "Medium"
        return {
            "title": sanitize_blind_text(str(vuln.get("title") or "Security Finding")),
            "description": sanitize_blind_text(str(vuln.get("description") or "")),
            "attack_vector": sanitize_blind_text(str(vuln.get("attack_vector") or "")),
            "recommendation": sanitize_blind_text(str(vuln.get("recommendation") or "")),
            "severity": str(getattr(raw_sv, "value", raw_sv)).split(".")[-1].capitalize(),
            "cwe": extract_cwe_from_vuln(vuln),
            "location": str(vuln.get("location") or "Line 1"),
        }

    def build_pool(
        self,
        trials: list[TrialRunRecord],
        output_dir: Path,
        existing_pool_path: Path | None = None,
    ) -> list[BlindReviewFinding]:
        """Collects one blind-review entry per (base_tier, repetition, finding_id) and preserves human labels."""
        output_dir.mkdir(parents=True, exist_ok=True)
        existing_pool: list[BlindReviewFinding] = []
        pool_file = existing_pool_path or (output_dir / "blind_review_pool.json")
        if pool_file.exists():
            try:
                raw_existing = json.loads(pool_file.read_text(encoding="utf-8"))
                existing_pool = [
                    BlindReviewFinding.model_validate(item)
                    for item in raw_existing
                    if isinstance(item, dict) and "review_id" in item
                ]
            except Exception as e:
                logger.warning(f"Could not load existing blind review pool from {pool_file}: {e}")

        # Collect best Open writeup and final status per (base_tier, repetition, finding_id).
        # Rank: 2 = final primary Open writeup, 1 = checkpoint Open writeup, 0 = non-Open fallback.
        entries: dict[tuple[str, int, str], tuple[int, BlindReviewFinding]] = {}

        # Process primary (non-checkpoint) trials first so final_status and poc_verified reflect final outcome.
        ordered_trials = sorted(trials, key=lambda t: 1 if "@" in t.ablation_tier else 0)
        for trial in ordered_trials:
            is_ckpt = "@" in trial.ablation_tier
            base_tier = trial.ablation_tier.split("@")[0]
            for idx_v, vuln in enumerate(trial.findings):
                raw_file = (
                    str(vuln.get("file") or vuln.get("file_path") or "")
                    .replace("\\", "/")
                    .lstrip("./")
                )
                if not raw_file:
                    continue
                fid = str(vuln.get("id") or f"idx-{idx_v}")
                key = (base_tier, trial.repetition, fid)
                status_str = self._status_str(vuln)
                poc_ver = bool(
                    vuln.get("poc_verified")
                    or (isinstance(vuln.get("poc"), dict) and vuln["poc"].get("verified"))
                )

                if status_str.lower() == "open":
                    rank = 1 if is_ckpt else 2
                    fields = self._extract_fields(vuln)
                else:
                    disc_snap = extract_phase_checkpoint_findings([vuln], "discovery")
                    if disc_snap and self._status_str(disc_snap[0]).lower() == "open":
                        rank = 1
                        fields = self._extract_fields(disc_snap[0])
                    else:
                        rank = 0
                        fields = self._extract_fields(vuln)

                loc_str = fields["location"]
                start_ln, end_ln = parse_line_range(loc_str)
                permalink = build_github_permalink(
                    repo_name=trial.repo_name,
                    pinned_rev=trial.pinned_rev,
                    file_path=raw_file,
                    start_line=start_ln,
                    end_line=end_ln,
                )

                prev_pair = entries.get(key)
                if prev_pair is None:
                    bf = BlindReviewFinding(
                        review_id="PENDING",
                        ablation_tier=base_tier,
                        repetition=trial.repetition,
                        finding_id=fid,
                        final_status=status_str,
                        poc_verified=poc_ver if not is_ckpt else False,
                        project_name=trial.project_name,
                        repo_name=trial.repo_name,
                        pinned_rev=trial.pinned_rev,
                        file=raw_file,
                        location=loc_str,
                        start_line=start_ln,
                        end_line=end_ln,
                        source_url=permalink,
                        cwe=fields["cwe"],
                        severity=fields["severity"],
                        title=fields["title"],
                        description=fields["description"],
                        attack_vector=fields["attack_vector"],
                        recommendation=fields["recommendation"],
                    )
                    entries[key] = (rank, bf)
                else:
                    prev_rank, prev_bf = prev_pair
                    if not is_ckpt:
                        prev_bf.final_status = status_str
                        prev_bf.poc_verified = poc_ver
                    if rank > prev_rank or (
                        rank == prev_rank and len(fields["description"]) > len(prev_bf.description)
                    ):
                        prev_bf.title = fields["title"] or prev_bf.title
                        prev_bf.description = fields["description"] or prev_bf.description
                        prev_bf.attack_vector = fields["attack_vector"] or prev_bf.attack_vector
                        prev_bf.recommendation = fields["recommendation"] or prev_bf.recommendation
                        prev_bf.severity = fields["severity"] or prev_bf.severity
                        prev_bf.cwe = fields["cwe"] or prev_bf.cwe
                        prev_bf.location = loc_str or prev_bf.location
                        if start_ln is not None:
                            prev_bf.start_line = start_ln
                            prev_bf.end_line = end_ln
                            prev_bf.source_url = permalink
                        entries[key] = (rank, prev_bf)

        # Group by file so human reviewers read each file once, with provenance-free hash order inside each file.
        pool = [pair[1] for pair in entries.values()]
        pool.sort(
            key=lambda bf: (
                bf.file,
                hashlib.sha256(
                    f"{bf.repo_name}:{bf.ablation_tier}:{bf.repetition}:{bf.finding_id}".encode(
                        "utf-8"
                    )
                ).hexdigest(),
            )
        )

        prev_by_key = {
            (p.ablation_tier, p.repetition, p.finding_id): p for p in existing_pool if p.finding_id
        }
        prev_by_rid = {p.review_id: p for p in existing_pool}

        for idx, bf in enumerate(pool, start=1):
            bf.review_id = f"BF-{idx:04d}"
            matched_prev = prev_by_key.get(
                (bf.ablation_tier, bf.repetition, bf.finding_id)
            ) or prev_by_rid.get(bf.review_id)
            if matched_prev is not None:
                bf.in_blind_sample = matched_prev.in_blind_sample
                bf.sampling_weight = matched_prev.sampling_weight
                bf.sampling_stratum = matched_prev.sampling_stratum
                bf.reviewer_1_label = matched_prev.reviewer_1_label
                bf.reviewer_2_label = matched_prev.reviewer_2_label
                bf.adjudicated_label = matched_prev.adjudicated_label
                bf.expert_severity = matched_prev.expert_severity
                bf.poc_demonstrates = matched_prev.poc_demonstrates
                bf.maintainer_status = matched_prev.maintainer_status
                bf.notes = matched_prev.notes

        (output_dir / "blind_review_pool.json").write_text(
            json.dumps([bf.model_dump() for bf in pool], indent=2), encoding="utf-8"
        )
        (output_dir / "blind_review_pool.md").write_text(
            self._render_blind_review_markdown(pool), encoding="utf-8"
        )
        self._write_blind_review_web_bundle(pool, output_dir / "blind_review")

        logger.success(
            f"Exported {len(pool)} blind-review findings to {output_dir / 'blind_review_pool.json'}"
        )
        return pool

    @staticmethod
    def _render_blind_review_markdown(pool: list[BlindReviewFinding]) -> str:
        sample = [bf for bf in pool if bf.in_blind_sample]
        lines = [
            "# Blind Dual-Expert Vulnerability Review Deck",
            "",
            "Each finding below has been stripped of model, configuration, and checkpoint provenance,",
            "grouped by file, and deterministically shuffled within each file.",
            "Record independent verdicts (`TP` or `FP`) in `blind_review_pool.json`.",
            "",
        ]
        for bf in sample:
            r1 = bf.reviewer_1_label or "Unlabeled"
            r2 = bf.reviewer_2_label or "Unlabeled"
            adj = "Excluded" if bf.is_excluded else (bf.resolved_label or "Pending")
            exp_sev = bf.normalized_expert_severity or "Unrated"
            poc_dem = bf.normalized_poc_demonstrates or "N/A"
            file_line = (
                f"[`{bf.file}`]({bf.source_url}) ({bf.location})"
                if bf.source_url
                else f"`{bf.file}` ({bf.location})"
            )
            lines.extend(
                [
                    f"## `{bf.review_id}` — {bf.title}",
                    f"- **Project**: `{bf.repo_name}` (`{bf.pinned_rev[:12]}`)",
                    f"- **File**: {file_line}",
                    f"- **CWE / Reported Severity**: `{bf.cwe or 'N/A'}` | `{bf.severity}`",
                    f"- **Review Status**: Reviewer 1: `{r1}` | Reviewer 2: `{r2}` | Resolved: `{adj}`",
                    f"- **Expert Pass**: Expert Severity: `{exp_sev}` | PoC Demonstrates: `{poc_dem}`",
                    "",
                    f"{bf.description}",
                ]
            )
            if bf.attack_vector:
                lines.extend(["", f"### Attack Vector\n{bf.attack_vector}"])
            if bf.recommendation:
                lines.extend(["", f"### Recommendation\n{bf.recommendation}"])
            lines.extend(["", "---", ""])
        return "\n".join(lines)

    @staticmethod
    def _write_blind_review_web_bundle(pool: list[BlindReviewFinding], web_dir: Path) -> None:
        """Emits a provenance-stripped Web-UI run directory so reviewers can inspect the blind deck in web-viewer."""
        web_dir.mkdir(parents=True, exist_ok=True)
        sample = [bf for bf in pool if bf.in_blind_sample]
        repo_name = sample[0].repo_name if sample else (pool[0].repo_name if pool else "evaluation")
        pinned_rev = sample[0].pinned_rev if sample else (pool[0].pinned_rev if pool else "HEAD")
        metadata = {
            "repo": repo_name,
            "model": "Blind Review Deck (Provenance-Stripped)",
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
                "id": bf.review_id,
                "file": bf.file,
                "start_line": bf.start_line,
                "end_line": bf.end_line,
                "source_url": bf.source_url,
                "title": bf.title,
                "severity": bf.severity,
                "location": bf.location,
                "description": bf.description,
                "attack_vector": bf.attack_vector,
                "recommendation": bf.recommendation,
                "cwe": bf.cwe,
                "status": "Open",
                "reviewer_1_label": bf.reviewer_1_label,
                "reviewer_2_label": bf.reviewer_2_label,
                "adjudicated_label": bf.adjudicated_label,
                "expert_severity": bf.expert_severity,
                "poc_demonstrates": bf.poc_demonstrates,
                "maintainer_status": bf.maintainer_status,
                "notes": bf.notes,
                "history": [],
            }
            for bf in sample
        ]
        (web_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        (web_dir / "vulnerabilities.json").write_text(json.dumps(vulns, indent=2), encoding="utf-8")
        (web_dir / "vulnerabilities_minimal.json").write_text(
            json.dumps(vulns, indent=2), encoding="utf-8"
        )

    def sample_blind_pool(
        self,
        eval_dir: Path,
        seed: str = "mjolnir-blind-sample-v1",
        full_closed_sample: int = 25,
        per_file_sample_per_rep: int = 5,
        threat_model_path: Path | None = None,
        source_root: Path | None = None,
    ) -> list[BlindReviewFinding]:
        """Applies deterministic per-(tier, repetition) Horvitz-Thompson sampling (154 cards) and emits Pass-1 deck."""
        resolved_eval = eval_dir.resolve()
        pool_path = resolved_eval / "blind_review_pool.json"
        if not pool_path.is_file():
            raise FileNotFoundError(f"blind_review_pool.json not found in {resolved_eval}")

        raw_pool = json.loads(pool_path.read_text(encoding="utf-8"))
        pool = [BlindReviewFinding.model_validate(item) for item in raw_pool]

        def _det_rank(bf: BlindReviewFinding) -> str:
            return hashlib.sha256(
                f"{seed}:{bf.review_id}:{bf.finding_id}".encode("utf-8")
            ).hexdigest()

        # Group items by (ablation_tier, is_open, repetition) for exact per-run Horvitz-Thompson weights.
        census_open_tiers = {"full", "no_tm", "no_expert", "holistic", "holistic_no_tm"}
        sampled_open_tiers = {"per_file", "per_file_no_tm"}

        by_group: dict[tuple[str, bool, int], list[BlindReviewFinding]] = {}
        for bf in pool:
            is_open = bf.final_status.strip().lower() == "open"
            by_group.setdefault((bf.ablation_tier, is_open, bf.repetition), []).append(bf)

        # Allocate full_closed_sample evenly across repetitions (e.g., 25 across 3 reps -> 8, 8, 9)
        full_closed_reps = sorted(
            r for (tier, is_open, r) in by_group if tier == "full" and not is_open
        )
        closed_alloc: dict[int, int] = {}
        if full_closed_reps:
            base_q, rem = divmod(full_closed_sample, len(full_closed_reps))
            for idx_r, r in enumerate(full_closed_reps):
                closed_alloc[r] = base_q + (1 if idx_r >= len(full_closed_reps) - rem else 0)

        for (tier, is_open, rep), items in by_group.items():
            n_grp = len(items)
            if is_open and tier in census_open_tiers:
                for bf in items:
                    bf.in_blind_sample = True
                    bf.sampling_weight = 1.0
                    bf.sampling_stratum = f"{tier}_open_census"
            elif is_open and tier in sampled_open_tiers:
                m = min(per_file_sample_per_rep, n_grp)
                ranked = sorted(items, key=_det_rank)
                chosen = {b.review_id for b in ranked[:m]}
                weight = round(n_grp / m, 6) if m > 0 else 0.0
                for bf in items:
                    if bf.review_id in chosen:
                        bf.in_blind_sample = True
                        bf.sampling_weight = weight
                        bf.sampling_stratum = f"{tier}_rep{rep}_sample{m}"
                    else:
                        bf.in_blind_sample = False
                        bf.sampling_weight = 0.0
                        bf.sampling_stratum = f"{tier}_rep{rep}_unsampled"
            elif (not is_open) and tier == "full":
                m = min(closed_alloc.get(rep, 0), n_grp)
                ranked = sorted(items, key=_det_rank)
                chosen = {b.review_id for b in ranked[:m]}
                weight = round(n_grp / m, 6) if m > 0 else 0.0
                for bf in items:
                    if bf.review_id in chosen:
                        bf.in_blind_sample = True
                        bf.sampling_weight = weight
                        bf.sampling_stratum = f"full_closed_rep{rep}_sample{m}"
                    else:
                        bf.in_blind_sample = False
                        bf.sampling_weight = 0.0
                        bf.sampling_stratum = f"full_closed_rep{rep}_unsampled"
            else:
                for bf in items:
                    bf.in_blind_sample = False
                    bf.sampling_weight = 0.0
                    bf.sampling_stratum = "excluded_stratum"

        pool_path.write_text(
            json.dumps([bf.model_dump() for bf in pool], indent=2), encoding="utf-8"
        )
        (resolved_eval / "blind_review_pool.md").write_text(
            self._render_blind_review_markdown(pool), encoding="utf-8"
        )
        self._write_blind_review_web_bundle(pool, resolved_eval / "blind_review")
        self.write_pass1_spa_deck(
            pool=pool,
            out_path=resolved_eval / "blind_review" / "pass1_deck.json",
            seed=seed,
            threat_model_path=threat_model_path,
            source_root=source_root,
        )
        selected_cnt = sum(1 for bf in pool if bf.in_blind_sample)
        logger.success(
            f"Stamped stratified blind sample ({selected_cnt}/{len(pool)} findings) in {pool_path}"
        )
        return pool

    @staticmethod
    def _collect_deck_sources_and_spans(
        items: list[BlindReviewFinding],
        repo_name: str,
        pinned_rev: str,
        source_root: Path | None = None,
    ) -> tuple[dict[str, str], dict[str, tuple[int | None, int | None, str | None]]]:
        """Loads pinned source files for deck items and resolves (focus_start, focus_end, source_url) per review_id."""
        src_tree = discover_pinned_source_tree(
            repo_name=repo_name, pinned_rev=pinned_rev, explicit_root=source_root
        )
        source_files: dict[str, str] = {}
        file_lines_cache: dict[str, list[str]] = {}
        spans: dict[str, tuple[int | None, int | None, str | None]] = {}

        for bf in items:
            clean_file = str(bf.file or "").replace("\\", "/").lstrip("./")
            if src_tree is not None and clean_file and clean_file not in file_lines_cache:
                candidate = (src_tree / clean_file).resolve()
                if candidate.is_file() and candidate.is_relative_to(src_tree):
                    txt = candidate.read_text(encoding="utf-8", errors="replace")
                    if len(txt) <= 512 * 1024:
                        source_files[clean_file] = txt
                    file_lines_cache[clean_file] = txt.splitlines()

            lines = file_lines_cache.get(clean_file)
            if lines:
                f_start, f_end = resolve_source_span(
                    lines=lines,
                    start_line=bf.start_line,
                    end_line=bf.end_line,
                    location_str=bf.location,
                    description=bf.description,
                )
                url = (
                    build_github_permalink(
                        repo_name=repo_name,
                        pinned_rev=pinned_rev,
                        file_path=clean_file,
                        start_line=f_start,
                        end_line=f_end,
                    )
                    or bf.source_url
                )
                spans[bf.review_id] = (f_start, f_end, url)
            else:
                spans[bf.review_id] = (bf.start_line, bf.end_line, bf.source_url)

        return source_files, spans

    @staticmethod
    def _resolve_threat_model_markdown(
        threat_model_path: Path | None,
        repo_name: str,
        pinned_rev: str,
        source_root: Path | None = None,
        fallback_deck_path: Path | None = None,
    ) -> str:
        if threat_model_path and threat_model_path.is_file():
            return threat_model_path.read_text(encoding="utf-8")
        src_tree = discover_pinned_source_tree(
            repo_name=repo_name, pinned_rev=pinned_rev, explicit_root=source_root
        )
        if src_tree is not None:
            candidate = (src_tree / "tools" / "mjolnir" / "threat_model.md").resolve()
            if candidate.is_file() and candidate.is_relative_to(src_tree):
                return candidate.read_text(encoding="utf-8")
        if fallback_deck_path and fallback_deck_path.is_file():
            try:
                prev = json.loads(fallback_deck_path.read_text(encoding="utf-8"))
                return str(prev.get("threat_model_markdown") or "")
            except Exception:
                return ""
        return ""

    @staticmethod
    def write_pass1_spa_deck(
        pool: list[BlindReviewFinding],
        out_path: Path,
        seed: str = "mjolnir-blind-sample-v1",
        threat_model_path: Path | None = None,
        source_root: Path | None = None,
    ) -> dict:
        """Writes a 100% provenance- and PoC-stripped Pass-1 JSON deck for the standalone blind-review SPA."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        sample = [bf for bf in pool if bf.in_blind_sample]
        repo_name = (
            sample[0].repo_name if sample else (pool[0].repo_name if pool else "caliptra-sw")
        )
        project_name = (
            sample[0].project_name if sample else (pool[0].project_name if pool else repo_name)
        )
        pinned_rev = sample[0].pinned_rev if sample else (pool[0].pinned_rev if pool else "")
        repo_url = GITHUB_REPO_URLS.get(repo_name.lower(), "")
        tree_url = f"{repo_url}/tree/{pinned_rev}" if (repo_url and pinned_rev) else repo_url

        tm_markdown = FindingPooler._resolve_threat_model_markdown(
            threat_model_path=threat_model_path,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            source_root=source_root,
            fallback_deck_path=out_path,
        )

        source_files, spans = FindingPooler._collect_deck_sources_and_spans(
            items=sample,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            source_root=source_root,
        )

        cards = []
        for bf in sample:
            f_start, f_end, s_url = spans.get(
                bf.review_id, (bf.start_line, bf.end_line, bf.source_url)
            )
            cards.append(
                {
                    "review_id": bf.review_id,
                    "file": bf.file,
                    "location": bf.location,
                    "start_line": f_start,
                    "end_line": f_end,
                    "source_url": s_url,
                    "cwe": bf.cwe,
                    "reported_severity": bf.severity,
                    "title": bf.title,
                    "description": bf.description,
                    "attack_vector": bf.attack_vector,
                    "recommendation": bf.recommendation,
                }
            )
        deck_hash = hashlib.sha256(
            json.dumps([c["review_id"] for c in cards], separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:12]
        deck = {
            "schema_version": 1,
            "deck_id": f"{repo_name}-pass1-{deck_hash}",
            "pass": "pass1",
            "project_name": project_name,
            "repo_name": repo_name,
            "pinned_rev": pinned_rev,
            "repo_tree_url": tree_url,
            "sampling_seed": seed,
            "card_count": len(cards),
            "threat_model_markdown": tm_markdown,
            "source_files": source_files,
            "cards": cards,
        }
        out_path.write_text(json.dumps(deck, indent=2), encoding="utf-8")
        return deck

    @staticmethod
    def write_pass2_poc_spa_deck(
        eval_dir: Path,
        out_path: Path,
        threat_model_path: Path | None = None,
        source_root: Path | None = None,
    ) -> dict:
        """Builds the Pass-2 PoC faithfulness deck for confirmed-TP findings with poc_verified=True."""
        resolved_eval = eval_dir.resolve()
        pool_path = resolved_eval / "blind_review_pool.json"
        raw_pool = json.loads(pool_path.read_text(encoding="utf-8"))
        pool = [BlindReviewFinding.model_validate(item) for item in raw_pool]

        trials_dir = resolved_eval / "trials"
        poc_dirs: dict[tuple[str, int, str], Path] = {}
        vuln_poc_text: dict[tuple[str, int, str], str] = {}
        if trials_dir.is_dir():
            for tier_dir in sorted(trials_dir.iterdir()):
                if not tier_dir.is_dir():
                    continue
                for rep_dir in sorted(tier_dir.glob("rep_*")):
                    if not rep_dir.is_dir():
                        continue
                    try:
                        rep_n = int(rep_dir.name.split("_", 1)[1])
                    except ValueError:
                        continue
                    run_dirs = sorted(p for p in rep_dir.glob("run_*") if p.is_dir())
                    rdir = run_dirs[-1] if run_dirs else rep_dir
                    pa_root = rdir / "poc_artifacts"
                    if pa_root.is_dir():
                        for pa in pa_root.iterdir():
                            if pa.is_dir() and pa.resolve().is_relative_to(resolved_eval):
                                poc_dirs[(tier_dir.name, rep_n, pa.name)] = pa
                    vfile = rdir / "vulnerabilities.json"
                    if vfile.is_file():
                        for v in json.loads(vfile.read_text(encoding="utf-8")):
                            fid = str(v.get("id") or "")
                            if fid and v.get("poc"):
                                vuln_poc_text[(tier_dir.name, rep_n, fid)] = str(v["poc"])

        eligible = [
            bf
            for bf in pool
            if bf.in_blind_sample and bf.poc_verified and bf.resolved_label == "TP"
        ]
        repo_name = (
            eligible[0].repo_name if eligible else (pool[0].repo_name if pool else "caliptra-sw")
        )
        project_name = (
            eligible[0].project_name if eligible else (pool[0].project_name if pool else repo_name)
        )
        pinned_rev = eligible[0].pinned_rev if eligible else (pool[0].pinned_rev if pool else "")
        repo_url = GITHUB_REPO_URLS.get(repo_name.lower(), "")
        tree_url = f"{repo_url}/tree/{pinned_rev}" if (repo_url and pinned_rev) else repo_url
        tm_markdown = FindingPooler._resolve_threat_model_markdown(
            threat_model_path=threat_model_path,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            source_root=source_root,
            fallback_deck_path=resolved_eval / "blind_review" / "pass1_deck.json",
        )

        source_files, spans = FindingPooler._collect_deck_sources_and_spans(
            items=eligible,
            repo_name=repo_name,
            pinned_rev=pinned_rev,
            source_root=source_root,
        )

        cards = []
        for bf in eligible:
            f_start, f_end, s_url = spans.get(
                bf.review_id, (bf.start_line, bf.end_line, bf.source_url)
            )
            key = (bf.ablation_tier, bf.repetition, bf.finding_id)
            pdir = poc_dirs.get(key)
            diff_txt = ""
            repro_txt = ""
            log_txt = ""
            if pdir and pdir.is_dir():
                if (pdir / "poc_patch.diff").is_file():
                    diff_txt = (pdir / "poc_patch.diff").read_text(
                        encoding="utf-8", errors="replace"
                    )[:40000]
                if (pdir / "reproduce.sh").is_file():
                    repro_txt = (pdir / "reproduce.sh").read_text(
                        encoding="utf-8", errors="replace"
                    )[:8000]
                if (pdir / "harness_commands.log").is_file():
                    raw_log = (
                        (pdir / "harness_commands.log")
                        .read_text(encoding="utf-8", errors="replace")
                        .splitlines()
                    )
                    filtered_log = [
                        ln
                        for ln in raw_log
                        if "unstable feature specified" not in ln
                        and "this feature is not stably supported" not in ln
                    ]
                    log_txt = "\n".join(filtered_log[-180:])[-16000:]
            cards.append(
                {
                    "review_id": bf.review_id,
                    "file": bf.file,
                    "location": bf.location,
                    "start_line": f_start,
                    "end_line": f_end,
                    "source_url": s_url,
                    "cwe": bf.cwe,
                    "reported_severity": bf.normalized_expert_severity or bf.severity,
                    "title": bf.title,
                    "description": bf.description,
                    "attack_vector": bf.attack_vector,
                    "recommendation": bf.recommendation,
                    "poc_summary": vuln_poc_text.get(key, ""),
                    "poc_patch_diff": diff_txt,
                    "reproduce_sh": repro_txt,
                    "harness_log_tail": log_txt,
                }
            )

        deck_hash = hashlib.sha256(
            json.dumps([c["review_id"] for c in cards], separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:12]
        deck = {
            "schema_version": 1,
            "deck_id": f"{repo_name}-pass2-poc-{deck_hash}",
            "pass": "pass2",
            "project_name": project_name,
            "repo_name": repo_name,
            "pinned_rev": pinned_rev,
            "repo_tree_url": tree_url,
            "card_count": len(cards),
            "threat_model_markdown": tm_markdown,
            "source_files": source_files,
            "cards": cards,
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(deck, indent=2), encoding="utf-8")
        return deck

    @staticmethod
    def import_reviewer_labels(
        eval_dir: Path,
        r1_path: Path | None = None,
        r2_path: Path | None = None,
        adjudication_path: Path | None = None,
        pass2_path: Path | None = None,
    ) -> InterRaterStats:
        """Merges exported reviewer JSON files into blind_review_pool.json and computes Cohen's kappa."""
        resolved_eval = eval_dir.resolve()
        pool_path = resolved_eval / "blind_review_pool.json"
        if not pool_path.is_file():
            raise FileNotFoundError(f"blind_review_pool.json not found in {resolved_eval}")

        raw_pool = json.loads(pool_path.read_text(encoding="utf-8"))
        pool = [BlindReviewFinding.model_validate(item) for item in raw_pool]
        by_id = {bf.review_id: bf for bf in pool}
        valid_id_re = re.compile(r"^BF-\d{4}$")

        def _load_reviews(path: Path | None) -> tuple[str, dict[str, dict]]:
            if path is None:
                return "", {}
            rp = path.resolve()
            if not rp.is_file():
                raise FileNotFoundError(f"Reviewer label file not found: {rp}")
            if rp.stat().st_size > 10 * 1024 * 1024:
                raise ValueError(f"Reviewer label file exceeds 10 MiB limit: {rp}")
            payload = json.loads(rp.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("reviews"), dict):
                raise ValueError(f"Invalid reviewer JSON envelope in {rp}")
            ldap = re.sub(r"[^a-z0-9._-]", "", str(payload.get("reviewer_ldap") or "").lower())[:64]
            cleaned: dict[str, dict] = {}
            for rid, entry in payload["reviews"].items():
                if valid_id_re.match(str(rid)) and isinstance(entry, dict):
                    cleaned[str(rid)] = entry
            return ldap, cleaned

        r1_ldap, r1_map = _load_reviews(r1_path)
        r2_ldap, r2_map = _load_reviews(r2_path)
        _adj_ldap, adj_map = _load_reviews(adjudication_path)
        _p2_ldap, p2_map = _load_reviews(pass2_path)

        for rid, entry in r1_map.items():
            bf = by_id.get(rid)
            if not bf:
                continue
            lbl = BlindReviewFinding._normalize_label(entry.get("verdict") or entry.get("label"))
            if lbl:
                bf.reviewer_1_label = lbl
            sev = BlindReviewFinding._normalize_severity(entry.get("expert_severity"))
            if sev and lbl == "TP":
                bf.expert_severity = sev
            note = str(entry.get("notes") or "").strip()[:1000]
            if note:
                tag = f"[{r1_ldap or 'r1'}] {note}"
                if tag not in bf.notes:
                    bf.notes = f"{bf.notes} | {tag}".strip(" |")

        for rid, entry in r2_map.items():
            bf = by_id.get(rid)
            if not bf:
                continue
            lbl = BlindReviewFinding._normalize_label(entry.get("verdict") or entry.get("label"))
            if lbl:
                bf.reviewer_2_label = lbl
            sev = BlindReviewFinding._normalize_severity(entry.get("expert_severity"))
            if sev and lbl == "TP" and not bf.expert_severity:
                bf.expert_severity = sev
            note = str(entry.get("notes") or "").strip()[:1000]
            if note:
                tag = f"[{r2_ldap or 'r2'}] {note}"
                if tag not in bf.notes:
                    bf.notes = f"{bf.notes} | {tag}".strip(" |")

        for rid, entry in adj_map.items():
            bf = by_id.get(rid)
            if not bf:
                continue
            raw_v = str(entry.get("verdict") or entry.get("adjudicated_label") or "").strip()
            if raw_v.lower() in ("exclude", "excluded"):
                bf.adjudicated_label = "exclude"
            else:
                lbl = BlindReviewFinding._normalize_label(raw_v)
                if lbl:
                    bf.adjudicated_label = lbl
            sev = BlindReviewFinding._normalize_severity(entry.get("expert_severity"))
            if sev:
                bf.expert_severity = sev
            note = str(entry.get("notes") or "").strip()[:1000]
            if note:
                tag = f"[{_adj_ldap or 'adj'}] {note}"
                if tag not in bf.notes:
                    bf.notes = f"{bf.notes} | {tag}".strip(" |")

        for rid, entry in p2_map.items():
            bf = by_id.get(rid)
            if not bf:
                continue
            poc_yn = BlindReviewFinding._normalize_yes_no(
                entry.get("poc_demonstrates") or entry.get("verdict")
            )
            if poc_yn:
                bf.poc_demonstrates = poc_yn
            note = str(entry.get("notes") or "").strip()[:1000]
            if note:
                tag = f"[{_p2_ldap or 'pass2'}] {note}"
                if tag not in bf.notes:
                    bf.notes = f"{bf.notes} | {tag}".strip(" |")

        pool_path.write_text(
            json.dumps([bf.model_dump() for bf in pool], indent=2), encoding="utf-8"
        )
        stats = compute_inter_rater_stats(pool)

        disputed_reviews: dict[str, dict] = {}
        for bf in pool:
            if not bf.in_blind_sample or bf.is_excluded or bf.resolved_label is not None:
                continue
            r1 = BlindReviewFinding._normalize_label(bf.reviewer_1_label)
            r2 = BlindReviewFinding._normalize_label(bf.reviewer_2_label)
            if r1 in ("TP", "FP") and r2 in ("TP", "FP") and r1 != r2:
                disputed_reviews[bf.review_id] = {
                    "verdict": "",
                    "expert_severity": bf.normalized_expert_severity or bf.severity,
                    "notes": "",
                    "title": bf.title,
                    "file": bf.file,
                    "location": bf.location,
                    "source_url": bf.source_url or "",
                    "r1_verdict": r1,
                    "r2_verdict": r2,
                    "reviewer_notes": bf.notes,
                }

        adj_template_path = resolved_eval / "blind_review" / "adjudication_template.json"
        adj_template_path.parent.mkdir(parents=True, exist_ok=True)
        adj_template_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "pass": "adjudication",
                    "reviewer_ldap": "referee",
                    "disputed_count": len(disputed_reviews),
                    "instructions": (
                        "For each disputed BF-xxxx card below, set 'verdict' to 'TP', 'FP', or 'exclude' "
                        "(and verify 'expert_severity' when 'TP'), then run: "
                        "mjolnir-eval import-labels --eval-dir <dir> --adjudication <this-file>"
                    ),
                    "reviews": disputed_reviews,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        logger.success(
            f"Imported labels into {pool_path}: double_reviewed={stats.double_reviewed_count}, "
            f"agreement={stats.raw_agreement_rate * 100:.1f}%, kappa={stats.cohens_kappa:.3f}, "
            f"disputed_unadjudicated={stats.disputed_unadjudicated_count} "
            f"(template: {adj_template_path})"
        )
        return stats
