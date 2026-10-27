# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Stratified Ground-Truth Security Baseline & Known-CVE Recall Evaluator.

Supports three stratified upstream ground-truth tiers on historical pinned snapshots:
- Tier A: Published CVEs / GitHub Security Advisories
- Tier B: Maintainer-patched exploitable firmware security bugs (without separate CVE IDs)
- Tier C: Secret zeroization, attestation completeness, and side-channel/fault hardening fixes

Security Architecture Note:
- Processes local evaluation JSON artifacts strictly via `json.loads` and Pydantic models
  (no insecure deserialization, `eval`, `exec`, or shell execution).
- Validates external reference URLs against an explicit `https://github.com/` / `https://nvd.nist.gov/`
  allow-list and canonicalizes filesystem paths via `Path.resolve()`.
- TODO(security): Web-specific controls (HTTP cookies, sessions, OAuth/MFA, CSRF, CSP,
  SQL parameterization, and multipart file-upload scanning) are intentionally omitted
  because this module is a pure offline local CLI evaluator with no network or DB surface.
"""

import json
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from evaluation.models import TrialRunRecord
from utilities.logger import logger

LINE_TOLERANCE_DEFAULT = 30
_ALLOWED_URL_PREFIXES = (
    "https://github.com/",
    "https://nvd.nist.gov/",
)

_LINE_RANGE_RE = re.compile(r"(?:lines?|l)\s*(\d+)(?:\s*[-–:]\s*(\d+))?", re.IGNORECASE)
_COLON_LINE_RE = re.compile(r":(\d+)(?:-(\d+))?")


class CveSiteSpec(BaseModel):
    """Source file and function/line location for a vulnerable site of a baseline item."""

    site_id: str
    file: str
    symbols: list[str] = Field(default_factory=list)
    start_line: int
    end_line: int


class KnownCveSpec(BaseModel):
    """Ground-truth specification for a historical CVE or upstream-patched security bug."""

    cve_id: str
    tier: Literal["A", "B", "C"] = "A"
    category: str = ""
    ghsa_id: str = ""
    advisory_url: str = ""
    severity: str
    cwe: str = ""
    published_date: str = ""
    release_tag: str = ""
    fix_pr: int | None = None
    fix_pr_url: str = ""
    additional_prs: list[int] = Field(default_factory=list)
    fix_commit: str = ""
    fix_commit_url: str = ""
    title: str
    summary: str
    sites: list[CveSiteSpec]
    concept_groups: list[list[str]] = Field(default_factory=list)

    @field_validator("advisory_url", "fix_pr_url", "fix_commit_url")
    @classmethod
    def _validate_reference_url(cls, val: str) -> str:
        clean = str(val or "").strip()
        if not clean:
            return ""
        if not clean.startswith(_ALLOWED_URL_PREFIXES):
            raise ValueError(
                f"Reference URL must start with one of {_ALLOWED_URL_PREFIXES}: {clean}"
            )
        if any(ch in clean for ch in (" ", "\n", "\r", "\t", '"', "<", ">", ")")):
            raise ValueError(f"Unsafe character in reference URL: {clean}")
        return clean


class CveGroundTruthManifest(BaseModel):
    """Top-level ground-truth manifest for a historical security-recall benchmark."""

    benchmark_id: str
    project_name: str
    repo_name: str
    upstream_repo: str
    pinned_tag: str
    pinned_rev: str
    pinned_date: str
    contamination_disclosure: str = ""
    cves: list[KnownCveSpec]


class MatchedFindingSummary(BaseModel):
    """Concise summary of a Mjolnir finding matching a ground-truth item."""

    finding_id: str
    site_id: str
    file: str
    location: str
    status: str
    poc_verified: bool
    severity: str
    title: str


class PerCveTrialResult(BaseModel):
    """Per-item recall outcome within a single trial or pipeline checkpoint."""

    cve_id: str
    tier: Literal["A", "B", "C"] = "A"
    ghsa_id: str = ""
    severity: str
    detected_any_status: bool
    detected_open: bool
    detected_poc_verified: bool
    matched_site_ids_open: list[str] = Field(default_factory=list)
    total_sites: int = 1
    matched_findings: list[MatchedFindingSummary] = Field(default_factory=list)
    same_file_unmatched: list[MatchedFindingSummary] = Field(default_factory=list)


class TierRecallBreakdown(BaseModel):
    """Stratified X/N recall breakdown for a subset of baseline tiers."""

    tier_key: str
    label: str
    total: int
    recalled_any_status: int
    recalled_open: int
    recalled_poc_verified: int


class TrialCveRecallSummary(BaseModel):
    """Aggregate and tier-stratified recall summary for a single trial or checkpoint."""

    ablation_tier: str
    tier_name: str
    model: str
    repetition: int
    is_checkpoint: bool
    total_cves: int
    recalled_any_status: int
    recalled_open: int
    recalled_poc_verified: int
    total_open_findings: int
    by_tier: dict[str, TierRecallBreakdown] = Field(default_factory=dict)
    per_cve: list[PerCveTrialResult]


class CveRecallReport(BaseModel):
    """Complete structured recall output written to cve_recall_results.json."""

    benchmark_id: str
    project_name: str
    pinned_tag: str
    pinned_rev: str
    contamination_disclosure: str
    trials: list[TrialCveRecallSummary]


_STRATA_DEFINITIONS: tuple[tuple[str, str, set[str]], ...] = (
    ("A", "Tier A — Published CVEs", {"A"}),
    ("B", "Tier B — Maintainer Security Bugs", {"B"}),
    ("A+B", "Core Security Bugs (Tier A + B)", {"A", "B"}),
    ("C", "Tier C — Zeroization & Hardening", {"C"}),
    ("A+B+C", "Complete Security Baseline (Tier A–C)", {"A", "B", "C"}),
)


def _compute_tier_breakdowns(
    per_cve_results: list[PerCveTrialResult],
) -> dict[str, TierRecallBreakdown]:
    out: dict[str, TierRecallBreakdown] = {}
    for key, label, allowed_tiers in _STRATA_DEFINITIONS:
        subset = [r for r in per_cve_results if r.tier in allowed_tiers]
        out[key] = TierRecallBreakdown(
            tier_key=key,
            label=label,
            total=len(subset),
            recalled_any_status=sum(1 for r in subset if r.detected_any_status),
            recalled_open=sum(1 for r in subset if r.detected_open),
            recalled_poc_verified=sum(1 for r in subset if r.detected_poc_verified),
        )
    return out


def _normalize_repo_rel_path(raw_path: str) -> str:
    clean = str(raw_path or "").split(":")[0].strip().replace("\\", "/")
    while clean.startswith("./"):
        clean = clean[2:]
    return clean.lstrip("/")


def parse_finding_line_span(location: str, raw_file: str = "") -> tuple[int, int] | None:
    """Extracts 1-indexed (start_line, end_line) from location or file:line strings."""
    for text in (location or "", raw_file or ""):
        m = _LINE_RANGE_RE.search(text)
        if m:
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else start
            return (min(start, end), max(start, end))
        m_colon = _COLON_LINE_RE.search(text)
        if m_colon:
            start = int(m_colon.group(1))
            end = int(m_colon.group(2)) if m_colon.group(2) else start
            return (min(start, end), max(start, end))
    return None


def _extract_finding_fields(vuln: dict) -> dict:
    """Normalizes latest finding metadata from raw vulnerabilities.json / TrialRunRecord."""
    history = vuln.get("history")
    nested: dict = {}
    if isinstance(history, list) and history:
        last_entry = history[-1]
        if isinstance(last_entry, dict) and isinstance(last_entry.get("finding"), dict):
            nested = last_entry["finding"]

    file_val = _normalize_repo_rel_path(str(vuln.get("file") or nested.get("file") or ""))
    loc_val = str(vuln.get("location") or nested.get("location") or "")
    title_val = str(vuln.get("title") or nested.get("title") or "")
    desc_val = str(vuln.get("description") or nested.get("description") or "")
    rec_val = str(vuln.get("recommendation") or nested.get("recommendation") or "")
    atk_val = str(vuln.get("attack_vector") or nested.get("attack_vector") or "")
    status_val = str(vuln.get("status") or nested.get("status") or "Open")
    sev_val = str(vuln.get("severity") or nested.get("severity") or "Medium")
    poc_val = bool(vuln.get("poc_verified", False))
    fid_val = str(vuln.get("id") or vuln.get("finding_id") or "")

    return {
        "finding_id": fid_val,
        "file": file_val,
        "raw_file": str(vuln.get("file") or ""),
        "location": loc_val,
        "title": title_val,
        "description": desc_val,
        "recommendation": rec_val,
        "attack_vector": atk_val,
        "status": status_val,
        "severity": sev_val,
        "poc_verified": poc_val,
    }


def _site_matches(
    site: CveSiteSpec,
    norm_finding: dict,
    line_tolerance: int = LINE_TOLERANCE_DEFAULT,
) -> bool:
    if norm_finding["file"] != _normalize_repo_rel_path(site.file):
        return False

    span = parse_finding_line_span(norm_finding["location"], norm_finding["raw_file"])
    if span is not None:
        f_start, f_end = span
        if f_end >= (site.start_line - line_tolerance) and f_start <= (
            site.end_line + line_tolerance
        ):
            return True

    haystack = (
        f"{norm_finding['location']} {norm_finding['title']} {norm_finding['description']}".lower()
    )
    return any(sym.lower() in haystack for sym in site.symbols if sym)


def _concepts_match(concept_groups: list[list[str]], norm_finding: dict) -> bool:
    if not concept_groups:
        return True
    combined = " ".join(
        [
            norm_finding["location"],
            norm_finding["title"],
            norm_finding["description"],
            norm_finding["attack_vector"],
            norm_finding["recommendation"],
        ]
    ).lower()
    for group in concept_groups:
        if group and not any(term.lower() in combined for term in group):
            return False
    return True


def _escape_latex(text: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in str(text))


def _resolve_safe_path(raw_path: Path) -> Path:
    raw_str = str(raw_path)
    if "\x00" in raw_str:
        raise ValueError("Invalid null byte in filesystem path.")
    return raw_path.expanduser().resolve()


def _format_ref_links(meta: KnownCveSpec) -> str:
    parts: list[str] = []
    if meta.ghsa_id and meta.advisory_url:
        parts.append(f"[{meta.ghsa_id}]({meta.advisory_url})")
    elif meta.ghsa_id:
        parts.append(f"`{meta.ghsa_id}`")
    if meta.fix_pr and meta.fix_pr_url:
        parts.append(f"[PR #{meta.fix_pr}]({meta.fix_pr_url})")
    elif meta.fix_pr:
        parts.append(f"PR #{meta.fix_pr}")
    parts.append(meta.severity)
    if meta.cwe:
        parts.append(meta.cwe)
    return ", ".join(parts)


class CveRecallEvaluator:
    """Evaluates Mjolnir trial records against a declarative stratified security baseline."""

    def __init__(self, line_tolerance: int = LINE_TOLERANCE_DEFAULT) -> None:
        self.line_tolerance = line_tolerance

    def evaluate_trials(
        self,
        trials: list[TrialRunRecord],
        ground_truth: CveGroundTruthManifest,
    ) -> CveRecallReport:
        summaries: list[TrialCveRecallSummary] = []

        for trial in trials:
            norm_findings = [_extract_finding_fields(v) for v in trial.findings]
            per_cve_results: list[PerCveTrialResult] = []

            for cve in ground_truth.cves:
                affected_files = {_normalize_repo_rel_path(s.file) for s in cve.sites}
                matched_summaries: list[MatchedFindingSummary] = []
                unmatched_same_file: list[MatchedFindingSummary] = []
                matched_open_sites: set[str] = set()

                for nf in norm_findings:
                    if nf["file"] not in affected_files:
                        continue

                    matched_site: CveSiteSpec | None = None
                    for site in cve.sites:
                        if _site_matches(site, nf, line_tolerance=self.line_tolerance):
                            matched_site = site
                            break

                    if matched_site is not None and _concepts_match(cve.concept_groups, nf):
                        matched_summaries.append(
                            MatchedFindingSummary(
                                finding_id=nf["finding_id"],
                                site_id=matched_site.site_id,
                                file=nf["file"],
                                location=nf["location"],
                                status=nf["status"],
                                poc_verified=nf["poc_verified"],
                                severity=nf["severity"],
                                title=nf["title"],
                            )
                        )
                        if nf["status"].lower() == "open":
                            matched_open_sites.add(matched_site.site_id)
                    else:
                        unmatched_same_file.append(
                            MatchedFindingSummary(
                                finding_id=nf["finding_id"],
                                site_id=matched_site.site_id if matched_site else "other_region",
                                file=nf["file"],
                                location=nf["location"],
                                status=nf["status"],
                                poc_verified=nf["poc_verified"],
                                severity=nf["severity"],
                                title=nf["title"],
                            )
                        )

                det_any = len(matched_summaries) > 0
                det_open = any(m.status.lower() == "open" for m in matched_summaries)
                det_poc = any(
                    m.status.lower() == "open" and m.poc_verified for m in matched_summaries
                )

                per_cve_results.append(
                    PerCveTrialResult(
                        cve_id=cve.cve_id,
                        tier=cve.tier,
                        ghsa_id=cve.ghsa_id,
                        severity=cve.severity,
                        detected_any_status=det_any,
                        detected_open=det_open,
                        detected_poc_verified=det_poc,
                        matched_site_ids_open=sorted(matched_open_sites),
                        total_sites=len(cve.sites),
                        matched_findings=matched_summaries,
                        same_file_unmatched=unmatched_same_file,
                    )
                )

            open_count = sum(1 for nf in norm_findings if nf["status"].lower() == "open")
            tier_breakdowns = _compute_tier_breakdowns(per_cve_results)
            summaries.append(
                TrialCveRecallSummary(
                    ablation_tier=trial.ablation_tier,
                    tier_name=trial.tier_name,
                    model=trial.model,
                    repetition=trial.repetition,
                    is_checkpoint=trial.is_checkpoint,
                    total_cves=len(ground_truth.cves),
                    recalled_any_status=sum(1 for r in per_cve_results if r.detected_any_status),
                    recalled_open=sum(1 for r in per_cve_results if r.detected_open),
                    recalled_poc_verified=sum(
                        1 for r in per_cve_results if r.detected_poc_verified
                    ),
                    total_open_findings=open_count,
                    by_tier=tier_breakdowns,
                    per_cve=per_cve_results,
                )
            )

        return CveRecallReport(
            benchmark_id=ground_truth.benchmark_id,
            project_name=ground_truth.project_name,
            pinned_tag=ground_truth.pinned_tag,
            pinned_rev=ground_truth.pinned_rev,
            contamination_disclosure=ground_truth.contamination_disclosure,
            trials=summaries,
        )

    def render_markdown(
        self,
        report: CveRecallReport,
        ground_truth: CveGroundTruthManifest,
    ) -> str:
        n_a = sum(1 for c in ground_truth.cves if c.tier == "A")
        n_b = sum(1 for c in ground_truth.cves if c.tier == "B")
        n_c = sum(1 for c in ground_truth.cves if c.tier == "C")

        lines: list[str] = [
            f"# Stratified Security Baseline & CVE Recall Scorecard: {report.project_name} (`{report.pinned_tag}`)",
            "",
            f"- **Pinned Revision**: `{report.pinned_rev}` (`{ground_truth.upstream_repo}` @ `{report.pinned_tag}`, `{ground_truth.pinned_date}`)",
            (
                f"- **Ground-Truth Benchmark**: `{report.benchmark_id}` "
                f"(`{len(ground_truth.cves)}` total items: Tier A = `{n_a}` CVEs, "
                f"Tier B = `{n_b}` security bugs, Tier C = `{n_c}` hardening fixes)"
            ),
        ]
        if report.contamination_disclosure:
            lines.append(f"- **Contamination Disclosure**: {report.contamination_disclosure}")
        lines.append("")

        # Section 1: Stratified Tier Recall Matrix
        lines.extend(
            [
                "## 1. Stratified Recall Across Baseline Tiers (Open / PoC-Verified)",
                "",
                "| Tier / Checkpoint | Rep | Model | Total Open | Tier A CVEs (Open / PoC) | Tier B Bugs (Open / PoC) | Core A+B (Open / PoC) | Tier C Hardening (Open / PoC) | All A–C (Open / PoC) |",
                "| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
            ]
        )
        for t in report.trials:
            bt = t.by_tier
            ta = bt["A"]
            tb = bt["B"]
            tab = bt["A+B"]
            tc = bt["C"]
            tall = bt["A+B+C"]
            lines.append(
                f"| `{t.ablation_tier}` | {t.repetition} | `{t.model}` | {t.total_open_findings} | "
                f"**{ta.recalled_open}/{ta.total}** ({ta.recalled_poc_verified} PoC) | "
                f"**{tb.recalled_open}/{tb.total}** ({tb.recalled_poc_verified} PoC) | "
                f"**{tab.recalled_open}/{tab.total}** ({tab.recalled_poc_verified} PoC) | "
                f"{tc.recalled_open}/{tc.total} ({tc.recalled_poc_verified} PoC) | "
                f"**{tall.recalled_open}/{tall.total}** ({tall.recalled_poc_verified} PoC) |"
            )

        # Section 2: Tier A Per-CVE Matrix
        tier_a_ids = [c.cve_id for c in ground_truth.cves if c.tier == "A"]
        if tier_a_ids:
            header = (
                "| Tier / Checkpoint | Rep | Model | Tier A Open | Tier A PoC | Total Open | "
                + " | ".join(f"`{cid}`" for cid in tier_a_ids)
                + " |"
            )
            sep = (
                "| :--- | :---: | :--- | :---: | :---: | :---: | "
                + " | ".join(":---:" for _ in tier_a_ids)
                + " |"
            )
            lines.extend(
                ["", "## 2. Tier A — Published CVEs Per-Checkpoint Matrix", "", header, sep]
            )

            for t in report.trials:
                by_id = {r.cve_id: r for r in t.per_cve}
                ta = t.by_tier["A"]
                cells: list[str] = []
                for cid in tier_a_ids:
                    r = by_id[cid]
                    if r.detected_poc_verified:
                        badge = "OPEN+PoC"
                    elif r.detected_open:
                        badge = "OPEN"
                    elif r.detected_any_status:
                        badge = "Closed/Dup"
                    else:
                        badge = "MISS"
                    if r.total_sites > 1 and r.detected_open:
                        badge += f" ({len(r.matched_site_ids_open)}/{r.total_sites})"
                    cells.append(badge)

                lines.append(
                    f"| `{t.ablation_tier}` | {t.repetition} | `{t.model}` | "
                    f"**{ta.recalled_open}/{ta.total}** | {ta.recalled_poc_verified}/{ta.total} | "
                    f"{t.total_open_findings} | " + " | ".join(cells) + " |"
                )

        # Section 3: Detailed Matched Findings by Tier
        lines.extend(["", "## 3. Matched Findings by Baseline Tier (Primary Trials)", ""])
        cve_meta = {c.cve_id: c for c in ground_truth.cves}
        primary_trials = [t for t in report.trials if not t.is_checkpoint]
        if not primary_trials:
            primary_trials = report.trials

        tier_titles = {
            "A": "Tier A — Published CVEs / GHSAs",
            "B": "Tier B — Maintainer-Patched Security Bugs",
            "C": "Tier C — Zeroization, Attestation & Side-Channel Hardening",
        }
        for t in primary_trials:
            lines.append(f"### `{t.ablation_tier}` (Rep {t.repetition}, `{t.model}`)")
            lines.append("")
            for tier_code in ("A", "B", "C"):
                tier_items = [r for r in t.per_cve if r.tier == tier_code]
                if not tier_items:
                    continue
                tb = t.by_tier[tier_code]
                lines.append(
                    f"#### {tier_titles[tier_code]} "
                    f"(Open: `{tb.recalled_open}/{tb.total}`, Any-Stage: `{tb.recalled_any_status}/{tb.total}`, PoC: `{tb.recalled_poc_verified}/{tb.total}`)"
                )
                lines.append("")
                for r in tier_items:
                    # For Tier B/C, show all detected items prominently and summarize missed count cleanly
                    if tier_code != "A" and not r.detected_any_status:
                        continue
                    meta = cve_meta[r.cve_id]
                    verdict = (
                        "DETECTED (Open + PoC)"
                        if r.detected_poc_verified
                        else (
                            "DETECTED (Open)"
                            if r.detected_open
                            else (
                                "DETECTED BEFORE TRIAGE (Closed/Duplicate)"
                                if r.detected_any_status
                                else "MISSED"
                            )
                        )
                    )
                    lines.append(
                        f"- **`{r.cve_id}`** ({_format_ref_links(meta)}) — **{verdict}**: {meta.title}"
                    )
                    for m in r.matched_findings:
                        poc_tag = ", `poc_verified=True`" if m.poc_verified else ""
                        lines.append(
                            f"  - Matched `[{m.status}{poc_tag}]` `{m.file}` ({m.location}): *{m.title}*"
                        )
                    if tier_code == "A" and not r.matched_findings and r.same_file_unmatched:
                        lines.append(
                            "  - *Same-file non-matching findings (manual verification check)*:"
                        )
                        for u in r.same_file_unmatched[:5]:
                            lines.append(
                                f"    - `[{u.status}]` `{u.file}` ({u.location}): *{u.title}*"
                            )
                if tier_code != "A":
                    missed_ids = [r.cve_id for r in tier_items if not r.detected_any_status]
                    if missed_ids:
                        lines.append(
                            f"- *Undetected {tier_code} items ({len(missed_ids)})*: "
                            + ", ".join(f"`{mid}`" for mid in missed_ids)
                        )
                lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def render_latex_table(
        self,
        report: CveRecallReport,
        ground_truth: CveGroundTruthManifest,
    ) -> str:
        primary_trials = [t for t in report.trials if not t.is_checkpoint]
        if not primary_trials:
            primary_trials = report.trials

        lines: list[str] = [
            "% Auto-generated by mjolnir-eval score-cve-recall",
            r"\begin{table}[t]",
            r"\centering",
            r"\small",
            (
                r"\caption{Stratified Security Baseline and Known-CVE Recall on \texttt{"
                + _escape_latex(ground_truth.upstream_repo)
                + r"} pinned at \texttt{"
                + _escape_latex(report.pinned_tag)
                + r"} (\texttt{"
                + _escape_latex(report.pinned_rev[:10])
                + r"}).}"
            ),
            r"\label{tab:caliptra-v210-cve-recall}",
            r"\begin{tabular}{llcccc}",
            r"\toprule",
            r"Baseline Item / Stratum & Component / Scope & Severity & Discovered & Final Open & PoC Verified \\",
            r"\midrule",
        ]

        disc_by_rep = {
            t.repetition: {r.cve_id: r for r in t.per_cve}
            for t in report.trials
            if t.ablation_tier.endswith("@discovery")
        }
        n_trials = max(1, len(primary_trials))

        tier_a_cves = [c for c in ground_truth.cves if c.tier == "A"]
        for cve in tier_a_cves:
            comp = ", ".join(sorted({s.file.split("/")[0] for s in cve.sites}))
            disc_hits = 0
            open_hits = 0
            poc_hits = 0
            for t in primary_trials:
                r_map = {r.cve_id: r for r in t.per_cve}
                r = r_map[cve.cve_id]
                disc_r = disc_by_rep.get(t.repetition, {}).get(cve.cve_id)
                if (disc_r and disc_r.detected_open) or r.detected_any_status:
                    disc_hits += 1
                if r.detected_open:
                    open_hits += 1
                if r.detected_poc_verified:
                    poc_hits += 1

            fmt = (
                (lambda k: r"\checkmark" if k > 0 else "---")
                if n_trials == 1
                else (lambda k: f"{k}/{n_trials}")
            )
            lines.append(
                f"\\texttt{{{_escape_latex(cve.cve_id)}}} & "
                f"\\texttt{{{_escape_latex(comp)}}} & "
                f"{_escape_latex(cve.severity)} & "
                f"{fmt(disc_hits)} & {fmt(open_hits)} & {fmt(poc_hits)} \\\\"
            )

        # Stratified aggregate summary rows across Tier A, Tier B, Core A+B, Tier C, Total A-C
        if any(c.tier != "A" for c in ground_truth.cves):
            lines.append(r"\midrule")
            strata_rows = (
                ("A", "Tier A (Published CVEs)", "5 GHSAs"),
                ("B", "Tier B (Maintainer Security Bugs)", "22 PRs"),
                ("A+B", r"\textbf{Core Security Bugs (Tier A+B)}", r"\textbf{27 Bugs}"),
                ("C", "Tier C (Zeroization \\& Hardening)", "9 PRs"),
                ("A+B+C", r"\textbf{Complete Baseline (Tier A--C)}", r"\textbf{36 Total}"),
            )
            t0 = primary_trials[0]
            disc_t0 = next(
                (
                    dt
                    for dt in report.trials
                    if dt.repetition == t0.repetition and dt.ablation_tier.endswith("@discovery")
                ),
                None,
            )
            for skey, slabel, sscope in strata_rows:
                tb = t0.by_tier[skey]
                if tb.total == 0:
                    continue
                disc_cnt = (
                    disc_t0.by_tier[skey].recalled_open
                    if disc_t0 is not None
                    else tb.recalled_any_status
                )
                lines.append(
                    f"{slabel} & {sscope} & --- & "
                    f"{disc_cnt}/{tb.total} & {tb.recalled_open}/{tb.total} & "
                    f"{tb.recalled_poc_verified}/{tb.total} \\\\"
                )

        lines.extend(
            [
                r"\bottomrule",
                r"\end{tabular}",
                r"\end{table}",
            ]
        )
        return "\n".join(lines) + "\n"

    def evaluate_and_write(
        self,
        eval_dir: Path,
        ground_truth_path: Path,
        output_dir: Path | None = None,
    ) -> CveRecallReport:
        safe_eval = _resolve_safe_path(eval_dir)
        manifest_path = safe_eval if safe_eval.is_file() else safe_eval / "trials_manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"trials_manifest.json not found at {manifest_path}")

        safe_gt = _resolve_safe_path(ground_truth_path)
        if not safe_gt.exists() or not safe_gt.is_file():
            raise FileNotFoundError(f"CVE ground truth file not found at {safe_gt}")

        target_out = _resolve_safe_path(
            output_dir if output_dir else (safe_eval.parent if safe_eval.is_file() else safe_eval)
        )
        target_out.mkdir(parents=True, exist_ok=True)

        raw_trials = json.loads(manifest_path.read_text(encoding="utf-8"))
        trials = [TrialRunRecord.model_validate(item) for item in raw_trials]
        gt = CveGroundTruthManifest.model_validate(json.loads(safe_gt.read_text(encoding="utf-8")))

        report = self.evaluate_trials(trials=trials, ground_truth=gt)
        json_out = target_out / "cve_recall_results.json"
        md_out = target_out / "cve_recall_scorecard.md"
        tex_out = target_out / "cve_recall_table.tex"

        json_out.write_text(
            json.dumps(report.model_dump(mode="json"), indent=2) + "\n",
            encoding="utf-8",
        )
        md_out.write_text(self.render_markdown(report, gt), encoding="utf-8")
        tex_out.write_text(self.render_latex_table(report, gt), encoding="utf-8")

        logger.success(f"Wrote Known-CVE recall artifacts to {md_out} and {tex_out}")
        return report
