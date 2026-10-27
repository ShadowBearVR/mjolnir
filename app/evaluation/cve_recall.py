# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Known-CVE Ground-Truth Recall Evaluator for Historical Pinned Snapshots.

Security Architecture Note:
- Processes local evaluation JSON artifacts strictly via `json.loads` and Pydantic models
  (no insecure deserialization, `eval`, `exec`, or shell execution).
- Validates and canonicalizes filesystem paths via `Path.resolve()` before reading or writing.
- TODO(security): Web-specific controls (HTTP cookies, sessions, OAuth/MFA, CSRF, CSP,
  SQL parameterization, and multipart file-upload scanning) are intentionally omitted
  because this module is a pure offline local CLI evaluator with no network or DB surface.
"""

import json
from pathlib import Path
import re

from pydantic import BaseModel, Field

from evaluation.models import TrialRunRecord
from utilities.logger import logger

LINE_TOLERANCE_DEFAULT = 30

_LINE_RANGE_RE = re.compile(r"(?:lines?|l)\s*(\d+)(?:\s*[-–:]\s*(\d+))?", re.IGNORECASE)
_COLON_LINE_RE = re.compile(r":(\d+)(?:-(\d+))?")


class CveSiteSpec(BaseModel):
    """Source file and function/line location for a vulnerable site of a known CVE."""

    site_id: str
    file: str
    symbols: list[str] = Field(default_factory=list)
    start_line: int
    end_line: int


class KnownCveSpec(BaseModel):
    """Ground-truth specification for a publicly disclosed historical CVE."""

    cve_id: str
    ghsa_id: str = ""
    severity: str
    cwe: str = ""
    published_date: str = ""
    fix_pr: int | None = None
    fix_commit: str = ""
    title: str
    summary: str
    sites: list[CveSiteSpec]
    concept_groups: list[list[str]] = Field(default_factory=list)


class CveGroundTruthManifest(BaseModel):
    """Top-level ground-truth manifest for a historical CVE-recall benchmark."""

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
    """Concise summary of a Mjolnir finding matching a ground-truth CVE."""

    finding_id: str
    site_id: str
    file: str
    location: str
    status: str
    poc_verified: bool
    severity: str
    title: str


class PerCveTrialResult(BaseModel):
    """Per-CVE recall outcome within a single trial or pipeline checkpoint."""

    cve_id: str
    ghsa_id: str
    severity: str
    detected_any_status: bool
    detected_open: bool
    detected_poc_verified: bool
    matched_site_ids_open: list[str] = Field(default_factory=list)
    total_sites: int = 1
    matched_findings: list[MatchedFindingSummary] = Field(default_factory=list)
    same_file_unmatched: list[MatchedFindingSummary] = Field(default_factory=list)


class TrialCveRecallSummary(BaseModel):
    """Aggregate X/N CVE recall summary for a single trial or checkpoint record."""

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
    per_cve: list[PerCveTrialResult]


class CveRecallReport(BaseModel):
    """Complete structured CVE-recall output written to cve_recall_results.json."""

    benchmark_id: str
    project_name: str
    pinned_tag: str
    pinned_rev: str
    contamination_disclosure: str
    trials: list[TrialCveRecallSummary]


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


class CveRecallEvaluator:
    """Evaluates Mjolnir trial records against a declarative Known-CVE ground-truth manifest."""

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
        lines: list[str] = [
            f"# Historical Known-CVE Recall Scorecard: {report.project_name} (`{report.pinned_tag}`)",
            "",
            f"- **Pinned Revision**: `{report.pinned_rev}` (`{ground_truth.upstream_repo}` @ `{report.pinned_tag}`, `{ground_truth.pinned_date}`)",
            f"- **Ground-Truth Benchmark**: `{report.benchmark_id}` ({len(ground_truth.cves)} published CVEs)",
        ]
        if report.contamination_disclosure:
            lines.append(f"- **Contamination Disclosure**: {report.contamination_disclosure}")
        lines.append("")

        cve_ids = [c.cve_id for c in ground_truth.cves]
        header = (
            "| Tier / Checkpoint | Rep | Model | Open Recall | PoC-Verified | Total Open | "
            + " | ".join(f"`{cid}`" for cid in cve_ids)
            + " |"
        )
        sep = (
            "| :--- | :---: | :--- | :---: | :---: | :---: | "
            + " | ".join(":---:" for _ in cve_ids)
            + " |"
        )
        lines.extend(["## 1. Per-Trial & Pipeline-Checkpoint Recall Matrix", "", header, sep])

        for t in report.trials:
            by_id = {r.cve_id: r for r in t.per_cve}
            cells: list[str] = []
            for cid in cve_ids:
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
                f"**{t.recalled_open}/{t.total_cves}** | {t.recalled_poc_verified}/{t.total_cves} | "
                f"{t.total_open_findings} | " + " | ".join(cells) + " |"
            )

        lines.extend(["", "## 2. Per-CVE Matched Findings (Primary Non-Checkpoint Trials)", ""])
        cve_meta = {c.cve_id: c for c in ground_truth.cves}
        primary_trials = [t for t in report.trials if not t.is_checkpoint]
        if not primary_trials:
            primary_trials = report.trials

        for t in primary_trials:
            lines.append(f"### `{t.ablation_tier}` (Rep {t.repetition}, `{t.model}`)")
            lines.append("")
            for r in t.per_cve:
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
                    f"- **`{r.cve_id}`** (`{r.ghsa_id}`, {r.severity}) — **{verdict}**: {meta.title}"
                )
                for m in r.matched_findings:
                    poc_tag = ", `poc_verified=True`" if m.poc_verified else ""
                    lines.append(
                        f"  - Matched `[{m.status}{poc_tag}]` `{m.file}` ({m.location}): *{m.title}*"
                    )
                if not r.matched_findings and r.same_file_unmatched:
                    lines.append(
                        "  - *Same-file non-matching findings (manual verification check)*:"
                    )
                    for u in r.same_file_unmatched[:5]:
                        lines.append(f"    - `[{u.status}]` `{u.file}` ({u.location}): *{u.title}*")
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
                r"\caption{Historical Known-CVE Recall on \texttt{"
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
            r"CVE ID & Affected Component & Severity & Discovered & Final Open & PoC Verified \\",
            r"\midrule",
        ]

        disc_by_rep = {
            t.repetition: {r.cve_id: r for r in t.per_cve}
            for t in report.trials
            if t.ablation_tier.endswith("@discovery")
        }
        n_trials = max(1, len(primary_trials))

        for cve in ground_truth.cves:
            comp = ", ".join({s.file.split("/")[0] for s in cve.sites})
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
