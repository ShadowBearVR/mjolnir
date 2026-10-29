#!/usr/bin/env python3
# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Stages and deploys Mjolnir evaluation archives, maintainer triage viewer, and blind review SPA to GCS."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "app"))
sys.path.insert(0, str(REPO_ROOT / "app" / "mjolnir"))

from evaluation.grader import (  # noqa: E402
    build_github_permalink,
    discover_pinned_source_tree,
    parse_line_range,
    resolve_source_span,
)

DEFAULT_BUCKET = os.environ.get("MJOLNIR_EVAL_BUCKET", "")
DEFAULT_SUBMISSIONS_BUCKET = os.environ.get("MJOLNIR_SUBMISSIONS_BUCKET", "")
DEFAULT_SIGNER_SA = os.environ.get("MJOLNIR_UPLOADER_SA", "")
DEFAULT_STUDY_KEY = os.environ.get("MJOLNIR_STUDY_KEY", "caliptra-v2")
DEFAULT_PRIORITY_BATCHES = os.environ.get("MJOLNIR_PRIORITY_BATCHES", "")
DEFAULT_POLICY_TTL_SECONDS = 604000  # ~6.99 days (inside GCP's 604,800s = 7-day ceiling)
MAX_POLICY_UPLOAD_BYTES = 60 * 1024
VALID_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
VALID_SLUG_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
VALID_SA_EMAIL_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]{1,63}@[a-z0-9][a-z0-9._:-]{1,99}\.iam\.gserviceaccount\.com$"
)
PROHIBITED_PROVENANCE_KEYS = {
    "ablation_tier",
    "repetition",
    "finding_id",
    "final_status",
    "poc_verified",
    "sampling_weight",
    "sampling_stratum",
}
MAX_LOG_TAIL_BYTES = 256 * 1024


def ensure_within(path: Path, allowed_root: Path) -> Path:
    resolved = path.resolve()
    root_resolved = allowed_root.resolve()
    if not resolved.is_relative_to(root_resolved):
        raise ValueError(f"Path {resolved} escapes allowed boundary {root_resolved}")
    return resolved


def sanitize_slug(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(raw or "").strip()).strip("-")
    return cleaned or "default"


def run_checked(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, shell=False, check=True)


def load_manifest_repo_info(eval_dir: Path) -> tuple[str, str]:
    manifest_file = eval_dir / "trials_manifest.json"
    if manifest_file.is_file():
        rows = json.loads(manifest_file.read_text(encoding="utf-8"))
        if isinstance(rows, list) and rows:
            first = rows[0]
            return str(first.get("repo_name") or eval_dir.parent.name), str(
                first.get("pinned_rev") or ""
            )
    return eval_dir.parent.name, ""


def condense_harness_log(src_log: Path, dst_log: Path) -> None:
    raw_bytes = src_log.read_bytes()
    if len(raw_bytes) > 4 * 1024 * 1024:
        raw_bytes = raw_bytes[-4 * 1024 * 1024 :]
    lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
    filtered = [
        ln
        for ln in lines
        if "unstable feature specified" not in ln
        and "this feature is not stably supported" not in ln
    ]
    tail_text = "\n".join(filtered[-1500:])
    encoded = tail_text.encode("utf-8")
    if len(encoded) > MAX_LOG_TAIL_BYTES:
        encoded = encoded[-MAX_LOG_TAIL_BYTES:]
    dst_log.write_bytes(encoded)


def copy_poc_artifacts(
    src_poc_root: Path,
    dst_poc_root: Path,
    orig_id: str,
    dst_id: str,
    allowed_src_root: Path,
    allowed_dst_root: Path,
) -> None:
    if not orig_id or not dst_id or not src_poc_root.is_dir():
        return
    src_dir = src_poc_root / sanitize_slug(orig_id)
    if not src_dir.is_dir():
        src_dir = src_poc_root / orig_id
    if not src_dir.is_dir():
        return
    ensure_within(src_dir, allowed_src_root)

    target_dir = ensure_within(dst_poc_root / dst_id, allowed_dst_root)
    target_dir.mkdir(parents=True, exist_ok=True)

    for fname in ("poc_patch.diff", "reproduce.sh"):
        fsrc = src_dir / fname
        if fsrc.is_file():
            ensure_within(fsrc, allowed_src_root)
            shutil.copy2(fsrc, target_dir / fname)

    log_src = src_dir / "harness_commands.log"
    if log_src.is_file():
        ensure_within(log_src, allowed_src_root)
        condense_harness_log(log_src, target_dir / "harness_commands.log")


def enrich_vulnerability(
    vuln: dict,
    repo_name: str,
    pinned_rev: str,
    src_tree: Path | None = None,
    dst_sources_root: Path | None = None,
    file_lines_cache: dict[tuple[str, str], list[str]] | None = None,
) -> dict:
    enriched = dict(vuln)
    raw_file = (
        str(enriched.get("file") or enriched.get("file_path") or "").replace("\\", "/").lstrip("./")
    )
    loc_str = str(enriched.get("location") or "")
    start_ln, end_ln = parse_line_range(loc_str)

    if src_tree is not None and raw_file and ".." not in raw_file.split("/"):
        cache_key = (repo_name, raw_file)
        lines: list[str] | None = (
            file_lines_cache.get(cache_key) if file_lines_cache is not None else None
        )
        if lines is None:
            candidate = (src_tree / raw_file).resolve()
            if candidate.is_file() and candidate.is_relative_to(src_tree):
                txt = candidate.read_text(encoding="utf-8", errors="replace")
                lines = txt.splitlines()
                if file_lines_cache is not None:
                    file_lines_cache[cache_key] = lines
                if dst_sources_root is not None:
                    dst_src_file = ensure_within(
                        dst_sources_root / sanitize_slug(repo_name) / raw_file,
                        dst_sources_root,
                    )
                    if not dst_src_file.is_file():
                        dst_src_file.parent.mkdir(parents=True, exist_ok=True)
                        dst_src_file.write_text(txt, encoding="utf-8")
        if lines:
            f_start, f_end = resolve_source_span(
                lines=lines,
                start_line=start_ln,
                end_line=end_ln,
                location_str=loc_str,
                description=str(enriched.get("description") or ""),
            )
            start_ln, end_ln = f_start, f_end
            enriched["source_repo"] = sanitize_slug(repo_name)
            enriched["source_rel_file"] = raw_file
            enriched["resolved_start_line"] = f_start
            enriched["resolved_end_line"] = f_end

    permalink = build_github_permalink(
        repo_name=repo_name,
        pinned_rev=pinned_rev,
        file_path=raw_file,
        start_line=start_ln,
        end_line=end_ln,
    )
    if permalink:
        enriched["source_url"] = permalink
    return enriched


def build_cold_archives(
    eval_root: Path,
    stage_archive_dir: Path,
    bucket: str | None = None,
    preserve_remote_sums: bool = False,
    only_archives: set[str] | None = None,
) -> list[Path]:
    stage_archive_dir.mkdir(parents=True, exist_ok=True)
    specs: list[tuple[str, Path, Path]] = [
        ("caliptra-sw-pinned.tar.zst", eval_root / "caliptra-sw", Path("pinned")),
        ("caliptra-sw-stability.tar.zst", eval_root / "caliptra-sw", Path("stability")),
        ("caliptra-sw-v210-pinned.tar.zst", eval_root / "caliptra-sw-v210", Path("pinned")),
        ("caliptra-mcu-sw-pinned.tar.zst", eval_root / "caliptra-mcu-sw", Path("pinned")),
        ("caliptra-dpe-pinned.tar.zst", eval_root / "caliptra-dpe", Path("pinned")),
        ("openprot-pinned.tar.zst", eval_root / "openprot", Path("pinned")),
        ("opentitan-fw-pinned.tar.zst", eval_root / "opentitan-fw", Path("pinned")),
    ]
    if (eval_root / "opentitan-rtl" / "pinned-v1").is_dir():
        specs.append(
            ("opentitan-rtl-pinned.tar.zst", eval_root / "opentitan-rtl", Path("pinned-v1"))
        )
        specs.append(
            ("opentitan-rtl-pinned-v2.tar.zst", eval_root / "opentitan-rtl", Path("pinned"))
        )
    else:
        specs.append(("opentitan-rtl-pinned.tar.zst", eval_root / "opentitan-rtl", Path("pinned")))
    prerev_v1_dir = REPO_ROOT / "pre-review-v1"
    if prerev_v1_dir.is_dir():
        specs.append(("caliptra-sw-pre-review-v1.tar.zst", REPO_ROOT, Path("pre-review-v1")))
    prerev_dir = REPO_ROOT / "pre-review-v2"
    if prerev_dir.is_dir():
        specs.append(("caliptra-sw-pre-review-v2.tar.zst", REPO_ROOT, Path("pre-review-v2")))

    created: list[Path] = []
    sha_by_name: dict[str, str] = {}

    if preserve_remote_sums and bucket:
        res = subprocess.run(
            ["/usr/bin/gcloud", "storage", "cat", f"gs://{bucket}/eval-archive/SHA256SUMS.txt"],
            shell=False,
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            for ln in res.stdout.splitlines():
                m = re.match(r"^([0-9a-f]{64})\s+([a-zA-Z0-9._-]+\.tar\.zst)$", ln.strip())
                if m:
                    sha_by_name[m.group(2)] = m.group(1)

    for archive_name, parent_dir, rel_target in specs:
        if only_archives is not None and archive_name not in only_archives:
            continue
        src_full = ensure_within(parent_dir / rel_target, REPO_ROOT)
        if not src_full.exists():
            print(f"[archive] Skipping missing directory: {src_full}")
            continue
        out_archive = ensure_within(stage_archive_dir / archive_name, stage_archive_dir)
        print(f"[archive] Compressing {src_full} -> {out_archive.name} ...")
        run_checked(
            [
                "/usr/bin/tar",
                "--exclude=.cargo_target_cache",
                "--exclude=poc_worktrees",
                "--exclude=obj_dir",
                "--exclude=__pycache__",
                "--exclude=*.pyc",
                "-I",
                "zstd -T0 -3",
                "-cf",
                str(out_archive),
                "-C",
                str(parent_dir),
                str(rel_target),
            ]
        )
        h = hashlib.sha256()
        with out_archive.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        digest = h.hexdigest()
        size_mb = out_archive.stat().st_size / (1024 * 1024)
        print(f"          {out_archive.name}: {size_mb:.1f} MiB  sha256={digest[:16]}...")
        sha_by_name[out_archive.name] = digest
        created.append(out_archive)

    sha_lines = [f"{digest}  {name}" for name, digest in sha_by_name.items()]
    sha_file = ensure_within(stage_archive_dir / "SHA256SUMS.txt", stage_archive_dir)
    sha_file.write_text("\n".join(sha_lines) + "\n", encoding="utf-8")
    created.append(sha_file)
    return created


def resolve_latest_run_dir(rep_dir: Path) -> Path:
    run_subdirs = sorted(p for p in rep_dir.glob("run_*") if p.is_dir())
    return run_subdirs[-1] if run_subdirs else rep_dir


def stage_single_raw_run(
    src_run_dir: Path,
    dst_runs_root: Path,
    proj: str,
    job: str,
    run_id: str,
    repo_name: str,
    pinned_rev: str,
    allowed_src_root: Path,
    src_tree: Path | None = None,
    dst_sources_root: Path | None = None,
    file_lines_cache: dict[tuple[str, str], list[str]] | None = None,
) -> list[dict]:
    ensure_within(src_run_dir, allowed_src_root)
    dst_run_dir = ensure_within(dst_runs_root / proj / job / run_id, dst_runs_root)
    dst_run_dir.mkdir(parents=True, exist_ok=True)

    meta_src = src_run_dir / "metadata.json"
    vuln_src = src_run_dir / "vulnerabilities.json"
    if not meta_src.is_file() or not vuln_src.is_file():
        return []

    meta = json.loads(meta_src.read_text(encoding="utf-8"))
    meta["project"] = proj
    meta["job"] = job
    meta["run_id"] = run_id
    if pinned_rev:
        meta["target_commit"] = pinned_rev
        meta["ref"] = pinned_rev[:12]
    (dst_run_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    raw_vulns = json.loads(vuln_src.read_text(encoding="utf-8"))
    enriched_vulns = [
        enrich_vulnerability(
            v,
            repo_name,
            pinned_rev,
            src_tree=src_tree,
            dst_sources_root=dst_sources_root,
            file_lines_cache=file_lines_cache,
        )
        for v in raw_vulns
    ]
    (dst_run_dir / "vulnerabilities.json").write_text(
        json.dumps(enriched_vulns, indent=2), encoding="utf-8"
    )

    for opt_name in (
        "token_usage.json",
        "tool_usage.json",
        "reasoning_log.json",
        "project_expert_summary.md",
    ):
        opt_src = src_run_dir / opt_name
        if opt_src.is_file():
            ensure_within(opt_src, allowed_src_root)
            shutil.copy2(opt_src, dst_run_dir / opt_name)

    src_poc_root = src_run_dir / "poc_artifacts"
    dst_poc_root = dst_run_dir / "poc_artifacts"
    if src_poc_root.is_dir():
        for v in enriched_vulns:
            fid = str(v.get("id") or "")
            if fid:
                copy_poc_artifacts(
                    src_poc_root=src_poc_root,
                    dst_poc_root=dst_poc_root,
                    orig_id=fid,
                    dst_id=fid,
                    allowed_src_root=allowed_src_root,
                    allowed_dst_root=dst_runs_root,
                )

    open_vulns = [
        v for v in enriched_vulns if str(v.get("status") or "Open").strip().lower() == "open"
    ]
    return open_vulns


def write_synthetic_open_run(
    dst_runs_root: Path,
    proj: str,
    job: str,
    run_id: str,
    model_desc: str,
    target_commit: str,
    timestamp: str,
    open_items: list[tuple[str, Path, dict]],
    prefix_repo_in_file: bool,
    allowed_src_root: Path,
) -> int:
    dst_run_dir = ensure_within(dst_runs_root / proj / job / run_id, dst_runs_root)
    dst_run_dir.mkdir(parents=True, exist_ok=True)
    dst_poc_root = dst_run_dir / "poc_artifacts"

    staged_vulns: list[dict] = []
    for tag_prefix, src_poc_root, vuln in open_items:
        v_copy = dict(vuln)
        orig_id = str(v_copy.get("id") or "")
        new_id = f"{sanitize_slug(tag_prefix)}-{orig_id}" if (tag_prefix and orig_id) else orig_id
        if new_id:
            v_copy["id"] = new_id
        if prefix_repo_in_file and tag_prefix:
            orig_file = str(v_copy.get("file") or "")
            if not orig_file.startswith("["):
                v_copy["file"] = f"[{tag_prefix}] {orig_file}"
        v_copy["status"] = "Open"
        staged_vulns.append(v_copy)

        if orig_id and new_id:
            copy_poc_artifacts(
                src_poc_root=src_poc_root,
                dst_poc_root=dst_poc_root,
                orig_id=orig_id,
                dst_id=new_id,
                allowed_src_root=allowed_src_root,
                allowed_dst_root=dst_runs_root,
            )

    meta = {
        "project": proj,
        "job": job,
        "run_id": run_id,
        "model": model_desc,
        "ref": target_commit[:12] if len(target_commit) >= 12 else target_commit,
        "target_commit": target_commit,
        "timestamp": timestamp,
        "mode": "Maintainer Disclosure Triage (Open Only)",
        "trigger": "Eval Triage",
        "status": "Success",
    }
    (dst_run_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (dst_run_dir / "vulnerabilities.json").write_text(
        json.dumps(staged_vulns, indent=2), encoding="utf-8"
    )
    (dst_run_dir / "token_usage.json").write_text("{}", encoding="utf-8")
    (dst_run_dir / "tool_usage.json").write_text("{}", encoding="utf-8")
    return len(staged_vulns)


def stage_eval_viewer(eval_root: Path, web_src_dir: Path, stage_viewer_dir: Path) -> dict:
    stage_viewer_dir.mkdir(parents=True, exist_ok=True)
    dist_dir = web_src_dir / "dist"
    if not (dist_dir / "mjolnir_dashboard_wasm_bg.wasm").is_file():
        raise FileNotFoundError(
            f"Missing built WASM bundle in {dist_dir}; run 'cargo xtask web' first."
        )

    shutil.copy2(web_src_dir / "index.html", stage_viewer_dir / "index.html")
    dst_web_sub = stage_viewer_dir / "web"
    dst_dist_sub = dst_web_sub / "dist"
    dst_dist_sub.mkdir(parents=True, exist_ok=True)

    for asset in ("style.css", "app.js", "constants.js", "wasm-worker.js"):
        shutil.copy2(web_src_dir / asset, dst_web_sub / asset)
    for dist_file in sorted(dist_dir.iterdir()):
        if dist_file.is_file() and not dist_file.name.endswith(".d.ts"):
            shutil.copy2(dist_file, dst_dist_sub / dist_file.name)

    dst_runs_root = stage_viewer_dir / "v1" / "runs"
    dst_runs_root.mkdir(parents=True, exist_ok=True)
    dst_sources_root = stage_viewer_dir / "v1" / "sources"
    dst_sources_root.mkdir(parents=True, exist_ok=True)
    file_lines_cache: dict[tuple[str, str], list[str]] = {}

    datasets: list[tuple[str, Path]] = [
        ("caliptra-sw", eval_root / "caliptra-sw" / "pinned"),
        ("caliptra-sw-stability", eval_root / "caliptra-sw" / "stability"),
        ("caliptra-sw-v210", eval_root / "caliptra-sw-v210" / "pinned"),
        ("caliptra-mcu-sw", eval_root / "caliptra-mcu-sw" / "pinned"),
        ("caliptra-dpe", eval_root / "caliptra-dpe" / "pinned"),
        ("openprot", eval_root / "openprot" / "pinned"),
        ("opentitan-fw", eval_root / "opentitan-fw" / "pinned"),
    ]
    rtl_v1_dir = eval_root / "opentitan-rtl" / "pinned-v1"
    rtl_v2_dir = eval_root / "opentitan-rtl" / "pinned"
    has_separate_rtl_v2 = rtl_v1_dir.is_dir()
    if has_separate_rtl_v2:
        datasets.append(("opentitan-rtl", rtl_v1_dir))
        datasets.append(("opentitan-rtl-v2", rtl_v2_dir))
    else:
        datasets.append(("opentitan-rtl", rtl_v2_dir))

    one_off_targets = {
        "caliptra-mcu-sw",
        "caliptra-dpe",
        "openprot",
        "opentitan-fw",
        "opentitan-rtl",
    }
    one_off_v2_targets = {
        "caliptra-mcu-sw",
        "caliptra-dpe",
        "openprot",
        "opentitan-fw",
        "opentitan-rtl-v2",
    }
    combined_one_off_open: list[tuple[str, Path, dict]] = []
    combined_one_off_v2_open: list[tuple[str, Path, dict]] = []
    per_target_open: dict[str, tuple[str, list[tuple[str, Path, dict]]]] = {}
    caliptra_sw_full_open: list[tuple[str, Path, dict]] = []
    raw_run_count = 0

    for proj_slug, ds_dir in datasets:
        trials_dir = ds_dir / "trials"
        if not trials_dir.is_dir():
            continue
        repo_name, pinned_rev = load_manifest_repo_info(ds_dir)
        src_tree = discover_pinned_source_tree(repo_name=repo_name, pinned_rev=pinned_rev)
        for tier_dir in sorted(trials_dir.iterdir()):
            if not tier_dir.is_dir():
                continue
            job_slug = sanitize_slug(tier_dir.name)
            for rep_dir in sorted(tier_dir.glob("rep_*")):
                if not rep_dir.is_dir():
                    continue
                src_run = resolve_latest_run_dir(rep_dir)
                open_vulns = stage_single_raw_run(
                    src_run_dir=src_run,
                    dst_runs_root=dst_runs_root,
                    proj=proj_slug,
                    job=job_slug,
                    run_id=rep_dir.name,
                    repo_name=repo_name,
                    pinned_rev=pinned_rev,
                    allowed_src_root=eval_root,
                    src_tree=src_tree,
                    dst_sources_root=dst_sources_root,
                    file_lines_cache=file_lines_cache,
                )
                raw_run_count += 1
                src_poc = src_run / "poc_artifacts"

                if (
                    proj_slug in one_off_targets or proj_slug in one_off_v2_targets
                ) and tier_dir.name == "full":
                    per_target_open.setdefault(proj_slug, (pinned_rev, []))
                    for ov in open_vulns:
                        per_target_open[proj_slug][1].append(("", src_poc, ov))
                        if proj_slug in one_off_targets:
                            combined_one_off_open.append((proj_slug, src_poc, ov))
                        if proj_slug in one_off_v2_targets:
                            combined_one_off_v2_open.append((proj_slug, src_poc, ov))
                elif proj_slug == "caliptra-sw" and tier_dir.name == "full":
                    for ov in open_vulns:
                        caliptra_sw_full_open.append((rep_dir.name, src_poc, ov))

    # Build 00-maintainer-reporting top-of-sidebar views (preserving original v1 URLs while adding RTL v2 alongside)
    combined_cnt = write_synthetic_open_run(
        dst_runs_root=dst_runs_root,
        proj="00-maintainer-reporting",
        job="00-all-one-off-targets",
        run_id="open-findings",
        model_desc="Mjolnir Full (Consolidated One-Off Open Findings)",
        target_commit="multi-repo-pinned",
        timestamp="2026-10-27T07:00:00Z",
        open_items=combined_one_off_open,
        prefix_repo_in_file=True,
        allowed_src_root=eval_root,
    )
    combined_v2_cnt = 0
    if has_separate_rtl_v2 and combined_one_off_v2_open:
        combined_v2_cnt = write_synthetic_open_run(
            dst_runs_root=dst_runs_root,
            proj="00-maintainer-reporting",
            job="00-all-one-off-targets",
            run_id="open-findings-v2",
            model_desc="Mjolnir Full (Consolidated One-Off Open Findings — incl. RTL v2)",
            target_commit="multi-repo-pinned",
            timestamp="2026-10-29T01:05:00Z",
            open_items=combined_one_off_v2_open,
            prefix_repo_in_file=True,
            allowed_src_root=eval_root,
        )

    ts_idx = 59
    for t_slug in sorted(per_target_open.keys()):
        p_rev, items = per_target_open[t_slug]
        if not items:
            continue
        ts_idx -= 1
        item_ts = (
            "2026-10-29T01:00:00Z"
            if t_slug == "opentitan-rtl-v2"
            else f"2026-10-27T06:{ts_idx:02d}:00Z"
        )
        item_desc = (
            "Mjolnir Full (opentitan-rtl v2 Multi-IP Open Findings)"
            if t_slug == "opentitan-rtl-v2"
            else f"Mjolnir Full ({t_slug} Open Findings)"
        )
        write_synthetic_open_run(
            dst_runs_root=dst_runs_root,
            proj="00-maintainer-reporting",
            job=t_slug,
            run_id="open-findings",
            model_desc=item_desc,
            target_commit=p_rev,
            timestamp=item_ts,
            open_items=items,
            prefix_repo_in_file=False,
            allowed_src_root=eval_root,
        )

    _, csw_rev = load_manifest_repo_info(eval_root / "caliptra-sw" / "pinned")
    csw_cnt = write_synthetic_open_run(
        dst_runs_root=dst_runs_root,
        proj="00-maintainer-reporting",
        job="caliptra-sw",
        run_id="full-open-3reps",
        model_desc="Mjolnir Full (caliptra-sw 3-Rep Open Findings)",
        target_commit=csw_rev,
        timestamp="2026-10-27T06:50:00Z",
        open_items=caliptra_sw_full_open,
        prefix_repo_in_file=True,
        allowed_src_root=eval_root,
    )

    manifest_keys = sorted(
        str(p.relative_to(stage_viewer_dir)).replace("\\", "/")
        for p in dst_runs_root.rglob("*")
        if p.is_file()
    )
    manifest_path = stage_viewer_dir / "v1" / "runs_manifest.json"
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "keys": manifest_keys}, indent=2),
        encoding="utf-8",
    )

    summary = {
        "raw_runs": raw_run_count,
        "one_off_open_total": combined_cnt,
        "one_off_open_v2_total": combined_v2_cnt,
        "caliptra_sw_full_open_total": csw_cnt,
        "manifest_blob_count": len(manifest_keys),
    }
    print(f"[viewer] Staged eval-viewer: {summary}")
    return summary


def render_meta_reviews_markdown(meta_jsonl_path: Path) -> str:
    if not meta_jsonl_path.is_file():
        return "# Stage-3 File Meta-Reviews\n\nNo meta_reviews.jsonl found.\n"
    rows = [
        json.loads(line)
        for line in meta_jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows.sort(key=lambda r: str(r.get("file") or ""))
    tot_bugs = sum(int(r.get("distinct_real_bugs_count") or 0) for r in rows)
    tot_warns = sum(len(r.get("consistency_warnings") or []) for r in rows)
    lines = [
        "# Stage-3 Cross-Claim File Meta-Reviews (pre-review-v2)",
        "",
        f"- **Files Audited**: `{len(rows)}`",
        f"- **Estimated Distinct Real Bugs Across Files**: `{tot_bugs}`",
        f"- **Cross-Claim Consistency Warnings**: `{tot_warns}`",
        "",
        "| File | Claims | AI TP | AI FP | Est. Distinct Bugs | Warnings |",
        "| :--- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        lines.append(
            f"| `{r.get('file')}` | {r.get('total_findings', 0)} | {r.get('tp_findings', 0)} | "
            f"{r.get('fp_findings', 0)} | **{r.get('distinct_real_bugs_count', 0)}** | "
            f"{len(r.get('consistency_warnings') or [])} |"
        )
    lines.append("")
    for r in rows:
        lines.extend(
            [
                "---",
                "",
                f"## `{r.get('file')}`",
                f"- **Counts**: `{r.get('total_findings', 0)}` claims (`{r.get('tp_findings', 0)}` TP, `{r.get('fp_findings', 0)}` FP) • **Estimated Distinct Real Bugs**: `{r.get('distinct_real_bugs_count', 0)}`",
                f"- **Takeaway**: {r.get('file_takeaway', 'N/A')}",
            ]
        )
        if r.get("poc_audit_summary"):
            lines.append(f"- **PoC Audit Summary**: {r['poc_audit_summary']}")
        bugs = r.get("distinct_real_bugs") or []
        if bugs:
            lines.append("")
            lines.append("### Distinct Real Bugs")
            for b in bugs:
                if isinstance(b, dict):
                    lines.append(
                        f"- **{b.get('bug_title') or b.get('summary') or 'Bug'}** (`{b.get('severity', '')}`): "
                        f"{b.get('description') or b.get('root_cause') or json.dumps(b)}"
                    )
                else:
                    lines.append(f"- {b}")
        warns = r.get("consistency_warnings") or []
        if warns:
            lines.append("")
            lines.append("### Consistency Warnings")
            for w in warns:
                lines.append(f"- {w if isinstance(w, str) else json.dumps(w)}")
        lines.append("")
    return "\n".join(lines)


def format_ai_audit_block(
    bf_id: str,
    s1: dict | None,
    s2: dict | None,
    s3: dict | None,
    orig_just: str,
) -> str:
    parts: list[str] = []
    if s1:
        verdict = str(s1.get("verdict") or "UNGRADED").upper()
        sev = str(s1.get("expert_severity") or "N/A")
        conf = str(s1.get("confidence") or "N/A")
        acc = str(s1.get("claim_accuracy") or "N/A")
        tb = str(s1.get("trust_boundary_crossed") or "N/A")
        mit = str(s1.get("mitigation_status") or "N/A")
        fmode = str(s1.get("failure_mode") or "N/A")
        parts.append(
            f"**[AI Stage-1 Claim Review — `{bf_id}`]**\n"
            f"- **Verdict**: `{verdict}` | **Expert Severity**: `{sev}` | **Confidence**: `{conf}`\n"
            f"- **Claim Accuracy**: `{acc}` | **Trust Boundary Crossed**: `{tb}` | **Mitigation**: `{mit}` | **Failure Mode**: `{fmode}`\n"
            f"- **Stage-1 Rationale**: {s1.get('rationale') or 'N/A'}"
        )
    if s2:
        p_dem = str(s2.get("poc_demonstrates") or "N/A")
        p_qual = str(s2.get("poc_quality") or "N/A")
        tm_ok = str(s2.get("threat_model_faithful") if "threat_model_faithful" in s2 else "N/A")
        prod_mod = str(s2.get("prod_files_modified") if "prod_files_modified" in s2 else "N/A")
        parts.append(
            f"**[AI Stage-2 PoC Faithfulness Audit]**\n"
            f"- **PoC Demonstrates Bug**: `{p_dem}` | **Quality**: `{p_qual}` | **Threat-Model Faithful**: `{tm_ok}` | **Prod Files Modified**: `{prod_mod}`\n"
            f"- **Stage-2 Rationale**: {s2.get('poc_rationale') or 'N/A'}"
        )
    if s3 and s3.get("file_takeaway"):
        parts.append(
            f"**[AI Stage-3 File Meta-Review (`{s3.get('file')}`)]**\n"
            f"- **Est. Distinct Real Bugs in File**: `{s3.get('distinct_real_bugs_count', 0)}` — {s3.get('file_takeaway')}"
        )
    if orig_just:
        parts.append(f"**[Original Mjolnir Agent Justification]**\n{orig_just}")
    return "\n\n".join(parts)


def stage_ai_eval(
    eval_root: Path,
    web_src_dir: Path,
    reports_src_dir: Path,
    v2_dir: Path,
    v1_dir: Path,
    stage_ai_dir: Path,
) -> dict:
    stage_ai_dir.mkdir(parents=True, exist_ok=True)
    dist_dir = web_src_dir / "dist"
    if not (dist_dir / "mjolnir_dashboard_wasm_bg.wasm").is_file():
        raise FileNotFoundError(
            f"Missing built WASM bundle in {dist_dir}; run 'cargo xtask web' first."
        )

    # Customize index.html header/sidebar slightly so AI Eval is unmistakable and links to ./reports.html
    idx_html = (web_src_dir / "index.html").read_text(encoding="utf-8")
    idx_html = idx_html.replace(
        "<title>Mjolnir Security Dashboard</title>",
        "<title>Mjolnir AI Pre-Review Explorer (caliptra-sw)</title>",
    )
    idx_html = idx_html.replace(
        '<div class="subtitle">AI Audit Platform</div>',
        '<div class="subtitle">AI Pre-Review (v2 &amp; v1)</div>',
    )
    idx_html = idx_html.replace(
        '<a href="#/runs" class="nav-item" id="nav-all-runs">\n          <span>All Runs</span>\n        </a>',
        '<a href="#/runs" class="nav-item" id="nav-all-runs">\n          <span>All Runs</span>\n        </a>\n        <a href="./reports.html" class="nav-item" id="nav-written-reports">\n          <span>Written Reports &amp; Plots &#8599;</span>\n        </a>',
    )
    (stage_ai_dir / "index.html").write_text(idx_html, encoding="utf-8")

    dst_web_sub = stage_ai_dir / "web"
    dst_dist_sub = dst_web_sub / "dist"
    dst_dist_sub.mkdir(parents=True, exist_ok=True)
    for asset in ("style.css", "app.js", "constants.js", "wasm-worker.js"):
        shutil.copy2(web_src_dir / asset, dst_web_sub / asset)
    for dist_file in sorted(dist_dir.iterdir()):
        if dist_file.is_file() and not dist_file.name.endswith(".d.ts"):
            shutil.copy2(dist_file, dst_dist_sub / dist_file.name)

    # Stage standalone reports.html + Markdown docs + SVG plots
    for r_asset in ("reports.html", "reports.css", "reports.js"):
        shutil.copy2(reports_src_dir / r_asset, stage_ai_dir / r_asset)
    docs_dir = stage_ai_dir / "docs"
    plots_dir = docs_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    if (v2_dir / "caliptra_sw_prereview_v2_report.md").is_file():
        shutil.copy2(v2_dir / "caliptra_sw_prereview_v2_report.md", docs_dir / "v2_report.md")
    if (v2_dir / "scorecard.md").is_file():
        shutil.copy2(v2_dir / "scorecard.md", docs_dir / "v2_scorecard.md")
    (docs_dir / "v2_meta_reviews.md").write_text(
        render_meta_reviews_markdown(v2_dir / "meta_reviews.jsonl"), encoding="utf-8"
    )
    if (v2_dir / "plots").is_dir():
        for svg_f in sorted((v2_dir / "plots").glob("*.svg")):
            shutil.copy2(svg_f, plots_dir / svg_f.name)

    if v1_dir.is_dir():
        if (v1_dir / "caliptra_sw_prereview_report.md").is_file():
            shutil.copy2(v1_dir / "caliptra_sw_prereview_report.md", docs_dir / "v1_report.md")
        if (v1_dir / "scorecard.md").is_file():
            shutil.copy2(v1_dir / "scorecard.md", docs_dir / "v1_scorecard.md")

    # Load Stage 1, Stage 2, Stage 3 maps from pre-review-v2
    pool_items = json.loads((v2_dir / "blind_review_pool.json").read_text(encoding="utf-8"))
    bf_by_key: dict[tuple[str, int, str], dict] = {}
    for item in pool_items:
        bf_by_key[
            (str(item["ablation_tier"]), int(item["repetition"]), str(item["finding_id"]))
        ] = item

    s1_by_rid: dict[str, dict] = {}
    for line in (v2_dir / "reviews.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            obj = json.loads(line)
            s1_by_rid[str(obj["review_id"])] = obj

    s2_by_rid: dict[str, dict] = {}
    if (v2_dir / "poc_reviews.jsonl").is_file():
        for line in (v2_dir / "poc_reviews.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                obj = json.loads(line)
                s2_by_rid[str(obj["review_id"])] = obj

    s3_by_file: dict[str, dict] = {}
    if (v2_dir / "meta_reviews.jsonl").is_file():
        for line in (v2_dir / "meta_reviews.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                obj = json.loads(line)
                s3_by_file[str(obj["file"])] = obj

    csw_eval_dir = eval_root / "caliptra-sw" / "pinned"
    repo_name, pinned_rev = load_manifest_repo_info(csw_eval_dir)
    src_tree = discover_pinned_source_tree(repo_name=repo_name, pinned_rev=pinned_rev)

    dst_runs_root = stage_ai_dir / "v1" / "runs"
    dst_sources_root = stage_ai_dir / "v1" / "sources"
    dst_runs_root.mkdir(parents=True, exist_ok=True)
    dst_sources_root.mkdir(parents=True, exist_ok=True)
    file_lines_cache: dict[tuple[str, str], list[str]] = {}

    full_open_24: list[tuple[str, Path, dict]] = []
    full_false_disproofs: list[tuple[str, Path, dict]] = []
    poc_all_111: list[tuple[str, Path, dict]] = []
    poc_rejected_13: list[tuple[str, Path, dict]] = []
    all_711_claims: list[tuple[str, Path, dict]] = []

    trials_dir = csw_eval_dir / "trials"
    staged_tier_runs = 0
    for tier_dir in sorted(trials_dir.iterdir()):
        if not tier_dir.is_dir():
            continue
        raw_tier = tier_dir.name
        job_slug = sanitize_slug(raw_tier)
        for rep_dir in sorted(tier_dir.glob("rep_*")):
            if not rep_dir.is_dir():
                continue
            rep_n = int(rep_dir.name.split("_", 1)[1])
            src_run = resolve_latest_run_dir(rep_dir)
            meta_src = src_run / "metadata.json"
            vuln_src = src_run / "vulnerabilities.json"
            if not meta_src.is_file() or not vuln_src.is_file():
                continue

            dst_run_dir = ensure_within(
                dst_runs_root / "v2-caliptra-sw-tiers" / job_slug / rep_dir.name, dst_runs_root
            )
            dst_run_dir.mkdir(parents=True, exist_ok=True)

            meta = json.loads(meta_src.read_text(encoding="utf-8"))
            meta["project"] = "v2-caliptra-sw-tiers"
            meta["job"] = job_slug
            meta["run_id"] = rep_dir.name
            meta["target_commit"] = pinned_rev
            meta["ref"] = pinned_rev[:12]
            meta["mode"] = "AI Pre-Review v2 Graded Run"
            (dst_run_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

            for opt_name in ("token_usage.json", "tool_usage.json", "project_expert_summary.md"):
                if (src_run / opt_name).is_file():
                    shutil.copy2(src_run / opt_name, dst_run_dir / opt_name)

            raw_vulns = json.loads(vuln_src.read_text(encoding="utf-8"))
            ai_vulns: list[dict] = []
            src_poc_root = src_run / "poc_artifacts"
            dst_poc_root = dst_run_dir / "poc_artifacts"

            for idx_v, rv in enumerate(raw_vulns):
                ev = enrich_vulnerability(
                    rv,
                    repo_name,
                    pinned_rev,
                    src_tree=src_tree,
                    dst_sources_root=dst_sources_root,
                    file_lines_cache=file_lines_cache,
                )
                fid = str(ev.get("id") or f"idx-{idx_v}")
                bf_item = bf_by_key.get((raw_tier, rep_n, fid))
                rid = str(bf_item["review_id"]) if bf_item else ""
                s1 = s1_by_rid.get(rid)
                s2 = s2_by_rid.get(rid)
                clean_f = str(ev.get("file") or "").replace("\\", "/").lstrip("./")
                s3 = s3_by_file.get(clean_f)

                verdict = str((s1 or {}).get("verdict") or "UNGRADED").upper()
                exp_sev = str((s1 or {}).get("expert_severity") or "")
                poc_dem = str((s2 or {}).get("poc_demonstrates") or "")
                tag_bits = [rid or fid[:8], f"AI:{verdict}"]
                if poc_dem:
                    tag_bits.append(f"PoC:{poc_dem}")
                orig_title = str(bf_item.get("title") if bf_item else ev.get("title") or "Finding")
                ev["title"] = f"[{' • '.join(tag_bits)}] {orig_title}"
                ev["verdict"] = f"AI Judge: {verdict}" + (f" ({exp_sev})" if exp_sev else "")
                ev["justification"] = format_ai_audit_block(
                    bf_id=rid or fid,
                    s1=s1,
                    s2=s2,
                    s3=s3,
                    orig_just=str(ev.get("justification") or ""),
                )
                ai_vulns.append(ev)

                if fid and src_poc_root.is_dir():
                    copy_poc_artifacts(
                        src_poc_root=src_poc_root,
                        dst_poc_root=dst_poc_root,
                        orig_id=fid,
                        dst_id=fid,
                        allowed_src_root=eval_root,
                        allowed_dst_root=dst_runs_root,
                    )

                st_lower = str(ev.get("status") or "Open").strip().lower()
                if rid:
                    claim_view = dict(ev)
                    if bf_item:
                        claim_view["description"] = bf_item.get("description") or claim_view.get(
                            "description"
                        )
                    claim_view["status"] = "Open"
                    all_711_claims.append((f"{job_slug}-r{rep_n}", src_poc_root, claim_view))

                    if raw_tier == "full" and st_lower == "open":
                        full_open_24.append((f"r{rep_n}", src_poc_root, dict(ev)))
                    elif raw_tier == "full" and st_lower == "closed" and verdict == "TP":
                        fd_copy = dict(claim_view)
                        fd_copy["status"] = "Open"
                        full_false_disproofs.append((f"r{rep_n}", src_poc_root, fd_copy))

                    if s2:
                        p_copy = dict(ev)
                        p_copy["status"] = "Open"
                        poc_all_111.append((f"{job_slug}-r{rep_n}", src_poc_root, p_copy))
                        if poc_dem.lower() == "no":
                            poc_rejected_13.append(
                                (f"{job_slug}-r{rep_n}", src_poc_root, dict(p_copy))
                            )

            (dst_run_dir / "vulnerabilities.json").write_text(
                json.dumps(ai_vulns, indent=2), encoding="utf-8"
            )
            staged_tier_runs += 1

    # Stage 00-ai-eval-v2-highlights
    write_synthetic_open_run(
        dst_runs_root=dst_runs_root,
        proj="00-ai-eval-v2-highlights",
        job="01-full-open-24",
        run_id="ai-graded",
        model_desc="AI Judge v2 on Mjolnir Full Open (23 TP, 1 FP = 95.8%)",
        target_commit=pinned_rev,
        timestamp="2026-10-27T09:59:00Z",
        open_items=full_open_24,
        prefix_repo_in_file=False,
        allowed_src_root=eval_root,
    )
    write_synthetic_open_run(
        dst_runs_root=dst_runs_root,
        proj="00-ai-eval-v2-highlights",
        job="02-full-false-disproofs",
        run_id="closed-but-ai-tp",
        model_desc="AI Judge v2 — Findings Closed by Initial Review Graded TP",
        target_commit=pinned_rev,
        timestamp="2026-10-27T09:58:00Z",
        open_items=full_false_disproofs,
        prefix_repo_in_file=False,
        allowed_src_root=eval_root,
    )
    write_synthetic_open_run(
        dst_runs_root=dst_runs_root,
        proj="00-ai-eval-v2-highlights",
        job="03-poc-audit-all-111",
        run_id="stage2-pocs",
        model_desc="AI Stage-2 PoC Faithfulness Audit (98 yes, 13 no = 88.3%)",
        target_commit=pinned_rev,
        timestamp="2026-10-27T09:57:00Z",
        open_items=poc_all_111,
        prefix_repo_in_file=False,
        allowed_src_root=eval_root,
    )
    write_synthetic_open_run(
        dst_runs_root=dst_runs_root,
        proj="00-ai-eval-v2-highlights",
        job="04-poc-audit-13-rejected",
        run_id="poc-no",
        model_desc="AI Stage-2 Rejected PoCs (poc_demonstrates = no)",
        target_commit=pinned_rev,
        timestamp="2026-10-27T09:56:00Z",
        open_items=poc_rejected_13,
        prefix_repo_in_file=False,
        allowed_src_root=eval_root,
    )
    write_synthetic_open_run(
        dst_runs_root=dst_runs_root,
        proj="00-ai-eval-v2-highlights",
        job="05-all-711-claims",
        run_id="stage1-pool",
        model_desc="AI Stage-1 Complete Pool (252 TP, 459 FP across 9 tiers)",
        target_commit=pinned_rev,
        timestamp="2026-10-27T09:55:00Z",
        open_items=all_711_claims,
        prefix_repo_in_file=False,
        allowed_src_root=eval_root,
    )

    # Also stage pre-review-v1 (deprecated clustered pool) for reference
    v1_count = 0
    if v1_dir.is_dir() and (v1_dir / "blind_review_pool.json").is_file():
        v1_pool = json.loads((v1_dir / "blind_review_pool.json").read_text(encoding="utf-8"))
        v1_revs: dict[str, dict] = {}
        if (v1_dir / "reviews.jsonl").is_file():
            for line in (v1_dir / "reviews.jsonl").read_text(encoding="utf-8").splitlines():
                if line.strip():
                    o = json.loads(line)
                    v1_revs[str(o.get("canonical_id") or "")] = o
        v1_items: list[tuple[str, Path, dict]] = []
        for item in v1_pool:
            cid = str(item.get("canonical_id") or "")
            rv1 = v1_revs.get(cid, {})
            verdict = str(rv1.get("verdict") or item.get("adjudicated_label") or "UNGRADED").upper()
            cerr = bool(rv1.get("cluster_error") or item.get("cluster_error"))
            v_dict = enrich_vulnerability(
                {
                    "id": cid,
                    "file": item.get("file") or "",
                    "location": item.get("location") or "",
                    "severity": item.get("severity") or "Medium",
                    "cwe": item.get("cwe") or "",
                    "title": f"[{cid} • v1-AI:{verdict}{' • CLUSTER_ERR' if cerr else ''}] {item.get('title') or ''}",
                    "description": item.get("description") or "",
                    "attack_vector": item.get("attack_vector") or "",
                    "recommendation": item.get("recommendation") or "",
                    "status": "Open",
                    "verdict": f"v1 AI: {verdict}" + (" (cluster_error)" if cerr else ""),
                    "justification": (
                        f"**[Deprecated Pre-Review v1 Clustered Review — `{cid}`]**\n"
                        f"- **Verdict**: `{verdict}` | **Expert Severity**: `{rv1.get('expert_severity', 'N/A')}` | **Cluster Error**: `{cerr}`\n"
                        f"- **Rationale**: {rv1.get('rationale') or item.get('notes') or 'N/A'}"
                    ),
                },
                repo_name=repo_name,
                pinned_rev=pinned_rev,
                src_tree=src_tree,
                dst_sources_root=dst_sources_root,
                file_lines_cache=file_lines_cache,
            )
            v1_items.append(("", Path("/nonexistent"), v_dict))
        v1_count = write_synthetic_open_run(
            dst_runs_root=dst_runs_root,
            proj="v1-deprecated-clustered",
            job="clustered-pool",
            run_id="203-canonical-items",
            model_desc="Deprecated Pre-Review v1 (Post-Hoc Clustered Pool)",
            target_commit=pinned_rev,
            timestamp="2026-10-23T16:56:00Z",
            open_items=v1_items,
            prefix_repo_in_file=False,
            allowed_src_root=eval_root,
        )

    manifest_keys = sorted(
        str(p.relative_to(stage_ai_dir)).replace("\\", "/")
        for p in dst_runs_root.rglob("*")
        if p.is_file()
    )
    (stage_ai_dir / "v1" / "runs_manifest.json").write_text(
        json.dumps({"schema_version": 1, "keys": manifest_keys}, indent=2), encoding="utf-8"
    )
    info = {
        "v2_tier_runs": staged_tier_runs,
        "full_open": len(full_open_24),
        "full_false_disproofs": len(full_false_disproofs),
        "poc_audited": len(poc_all_111),
        "poc_rejected": len(poc_rejected_13),
        "v2_claims_total": len(all_711_claims),
        "v1_clustered_total": v1_count,
    }
    print(f"[ai-eval] Staged standalone AI Pre-Review portal: {info}")
    return info


def assert_zero_provenance_leaks(deck_obj: object) -> None:
    if isinstance(deck_obj, dict):
        leaked = PROHIBITED_PROVENANCE_KEYS.intersection(deck_obj.keys())
        if leaked:
            raise ValueError(
                f"Security/blinding check failed — provenance keys in deck.json: {leaked}"
            )
        for v in deck_obj.values():
            assert_zero_provenance_leaks(v)
    elif isinstance(deck_obj, list):
        for item in deck_obj:
            assert_zero_provenance_leaks(item)


def parse_priority_batches(raw: str) -> list[int]:
    """Parses a comma-separated list of 1-based chunk IDs (1..64), deduplicating while preserving order."""
    seen: set[int] = set()
    ordered: list[int] = []
    for tok in str(raw or "").split(","):
        s = tok.strip()
        if not s:
            continue
        if not re.match(r"^[1-9]\d?$", s):
            raise ValueError(f"Invalid priority batch number '{s}' (expected integer 1..64)")
        val = int(s)
        if not (1 <= val <= 64):
            raise ValueError(f"Priority batch {val} out of allowed range 1..64")
        if val not in seen:
            seen.add(val)
            ordered.append(val)
    return ordered


def _sign_blob_via_gcloud(signer_sa: str, payload: bytes) -> bytes:
    """Signs payload bytes via keyless IAM signBlob using the system-managed SA key."""
    if not VALID_SA_EMAIL_RE.match(signer_sa):
        raise ValueError(f"Invalid service account email: {signer_sa}")
    with tempfile.TemporaryDirectory(prefix="mjolnir_signblob_") as tmpdir:
        in_path = Path(tmpdir) / "policy_b64.txt"
        out_path = Path(tmpdir) / "policy.sig"
        in_path.write_bytes(payload)
        run_checked(
            [
                "/usr/bin/gcloud",
                "iam",
                "service-accounts",
                "sign-blob",
                f"--iam-account={signer_sa}",
                str(in_path),
                str(out_path),
            ]
        )
        sig_bytes = out_path.read_bytes()
        if len(sig_bytes) < 64:
            raise RuntimeError(f"Unexpectedly short signature ({len(sig_bytes)} B) from sign-blob")
        return sig_bytes


def generate_v4_signed_post_policy(
    submissions_bucket: str,
    signer_service_account: str,
    study_key: str,
    study_prefix: str = "v2",
    ttl_seconds: int = DEFAULT_POLICY_TTL_SECONDS,
    max_bytes: int = MAX_POLICY_UPLOAD_BYTES,
    now_utc: datetime | None = None,
    dry_run: bool = False,
    sign_fn=None,
    policy_prefix_only: bool = False,
) -> dict:
    """Builds and signs a GCS V4 HTML Form POST Policy Document (GOOG4-RSA-SHA256)."""
    if not VALID_BUCKET_NAME_RE.match(submissions_bucket):
        raise ValueError(f"Invalid submissions bucket name: {submissions_bucket}")
    if not VALID_SA_EMAIL_RE.match(signer_service_account):
        raise ValueError(f"Invalid signer service account email: {signer_service_account}")
    if not VALID_SLUG_RE.match(study_prefix):
        raise ValueError(f"Invalid study_prefix: {study_prefix}")
    if not VALID_SLUG_RE.match(study_key):
        raise ValueError(f"Invalid study_key: {study_key}")

    clamped_ttl = max(60, min(int(ttl_seconds), 604800))
    now = (now_utc or datetime.now(UTC)).astimezone(UTC)
    exp_dt = now + timedelta(seconds=clamped_ttl)

    datestamp = now.strftime("%Y%m%d")
    x_goog_date = now.strftime("%Y%m%dT%H%M%SZ")
    expiration = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    credential = f"{signer_service_account}/{datestamp}/auto/storage/goog4_request"
    key_prefix = f"{study_prefix}/{study_key}/"
    signed_prefix = f"{study_prefix}/" if policy_prefix_only else key_prefix

    policy_doc = {
        "expiration": expiration,
        "conditions": [
            {"bucket": submissions_bucket},
            ["starts-with", "$key", signed_prefix],
            {"Content-Type": "application/json"},
            {"success_action_status": "201"},
            ["content-length-range", 2, int(max_bytes)],
            {"x-goog-algorithm": "GOOG4-RSA-SHA256"},
            {"x-goog-credential": credential},
            {"x-goog-date": x_goog_date},
        ],
    }
    policy_json_bytes = json.dumps(policy_doc, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    policy_b64 = base64.b64encode(policy_json_bytes).decode("ascii")

    if dry_run and sign_fn is None:
        hex_sig = "0" * 512
    else:
        signer = sign_fn or _sign_blob_via_gcloud
        sig_bytes = signer(signer_service_account, policy_b64.encode("ascii"))
        hex_sig = sig_bytes.hex()

    return {
        "url": f"https://storage.googleapis.com/{submissions_bucket}/",
        "expires_at": expiration,
        "key_prefix": key_prefix,
        "fields": {
            "Content-Type": "application/json",
            "success_action_status": "201",
            "x-goog-algorithm": "GOOG4-RSA-SHA256",
            "x-goog-credential": credential,
            "x-goog-date": x_goog_date,
            "policy": policy_b64,
            "x-goog-signature": hex_sig,
        },
    }


def encode_auth_fragment_token(signed_post: dict) -> str:
    """Packs a V4 signed POST policy + hex signature into compact URL-safe '<policy_b64url>.<sig_b64url>'."""
    fields = signed_post["fields"]
    policy_b64 = str(fields["policy"])
    sig_bytes = bytes.fromhex(str(fields["x-goog-signature"]))
    policy_url = policy_b64.replace("+", "-").replace("/", "_").rstrip("=")
    sig_url = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
    return f"{policy_url}.{sig_url}"


def write_live_urls_markdown(
    signed_invite_links: list[tuple[str, str, str]],
    web_bucket: str,
    submissions_bucket: str,
) -> Path:
    out_path = ensure_within(REPO_ROOT / "live-urls.md", REPO_ROOT)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# Live Signed Blind-Review Invite URLs",
        "",
        f"- **Generated (UTC)**: `{generated_at}`",
        f"- **Static Web Bucket**: `gs://{web_bucket}`",
        f"- **Private Dropbox Bucket**: `gs://{submissions_bucket}`",
        "- **Security Note**: These URLs contain V4 Signed `POST` capabilities in the `#auth=` fragment.",
        "  Never commit this file or upload it to a public bucket (gitignored at `/live-urls.md`).",
        "",
    ]
    for idx, (label, exp_ts, full_url) in enumerate(signed_invite_links, start=1):
        lines.extend(
            [
                f"## {idx}. `{label}`",
                f"- **Expires**: `{exp_ts}`",
                "",
                "```text",
                full_url,
                "```",
                "",
            ]
        )
    content = "\n".join(lines)
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return out_path


def stage_blind_review_deck(
    blind_web_src: Path,
    deck_src: Path,
    stage_dir: Path,
    pass_label: str = "pass1",
    study_key: str = "caliptra-v2",
    priority_batches: list[int] | None = None,
) -> dict:
    stage_dir.mkdir(parents=True, exist_ok=True)
    ensure_within(blind_web_src, REPO_ROOT)
    ensure_within(deck_src, REPO_ROOT)
    if not VALID_SLUG_RE.match(study_key):
        raise ValueError(f"Invalid study_key format: {study_key}")
    if not deck_src.is_file():
        raise FileNotFoundError(
            f"Missing blind-review deck {deck_src}; generate it first "
            f"(e.g. 'mjolnir-eval build-pass2-deck --eval-dir test-out/evaluations/caliptra-sw/pinned')."
        )

    deck_data = json.loads(deck_src.read_text(encoding="utf-8"))
    assert_zero_provenance_leaks(deck_data)

    for asset in ("index.html", "style.css", "app.js"):
        shutil.copy2(blind_web_src / asset, stage_dir / asset)
    shutil.copy2(deck_src, stage_dir / "deck.json")
    clean_prio = [int(b) for b in (priority_batches or []) if 1 <= int(b) <= 64]
    # Security: Public config.json MUST NOT contain signed_post or submissions_bucket credentials.
    config_payload: dict[str, object] = {
        "schema_version": 2,
        "study_prefix": "v2",
        "default_study_key": study_key,
        "priority_batches": clean_prio,
    }
    (stage_dir / "config.json").write_text(
        json.dumps(config_payload, indent=2) + "\n", encoding="utf-8"
    )

    info = {
        "deck_id": deck_data.get("deck_id"),
        "pass": deck_data.get("pass"),
        "card_count": deck_data.get("card_count"),
        "num_batches": deck_data.get("num_batches", 1),
        "has_threat_model": bool(deck_data.get("threat_model_markdown")),
        "priority_batches": clean_prio,
        "study_key": study_key,
    }
    print(f"[blind-review] Staged {pass_label} SPA: {info}")
    return info


def upload_directory_to_gcs(
    local_dir: Path, bucket: str, prefix: str, cache_no_store: bool
) -> None:
    dest_uri = f"gs://{bucket}/{prefix.strip('/')}"
    print(f"[gcs] Uploading {local_dir} -> {dest_uri}/ ...")
    cmd = ["/usr/bin/gcloud", "storage", "rsync", "--recursive"]
    if cache_no_store:
        cmd.extend(["--cache-control=no-cache, no-store, must-revalidate"])
    cmd.extend([str(local_dir), dest_uri])
    run_checked(cmd)

    for wasm_file in sorted(local_dir.rglob("*.wasm")):
        rel_wasm = str(wasm_file.relative_to(local_dir)).replace("\\", "/")
        wasm_uri = f"{dest_uri}/{rel_wasm}"
        run_checked(
            [
                "/usr/bin/gcloud",
                "storage",
                "objects",
                "update",
                wasm_uri,
                "--content-type=application/wasm",
                "--cache-control=no-cache, no-store, must-revalidate",
            ]
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage and deploy Mjolnir evaluation archive, maintainer triage viewer, and blind review SPA."
    )
    parser.add_argument(
        "--bucket",
        default=DEFAULT_BUCKET,
        help="Target GCS bucket name (or set MJOLNIR_EVAL_BUCKET)",
    )
    parser.add_argument(
        "--only",
        choices=["all", "archive", "viewer", "blind", "blind-pass2", "ai-eval"],
        default="all",
        help="Deploy only a specific prefix or all active prefixes",
    )
    parser.add_argument(
        "--submissions-bucket",
        default=DEFAULT_SUBMISSIONS_BUCKET,
        help="Private write-only GCS dropbox bucket for blind-review autosave (or set MJOLNIR_SUBMISSIONS_BUCKET)",
    )
    parser.add_argument(
        "--signer-service-account",
        default=DEFAULT_SIGNER_SA,
        help="Minimal uploader SA email used to sign V4 POST policy via signBlob (or set MJOLNIR_UPLOADER_SA)",
    )
    parser.add_argument(
        "--policy-ttl-seconds",
        type=int,
        default=DEFAULT_POLICY_TTL_SECONDS,
        help=f"V4 POST policy TTL in seconds, max 604800 = 7 days (default: {DEFAULT_POLICY_TTL_SECONDS})",
    )
    parser.add_argument(
        "--priority-batches",
        default=DEFAULT_PRIORITY_BATCHES,
        help="Optional comma-separated chunk IDs (e.g. '4,9') prioritized for new visitors (default: empty)",
    )
    parser.add_argument(
        "--study-key",
        default=DEFAULT_STUDY_KEY,
        help="Default study_key written into blind-review config.json (default: caliptra-v2)",
    )
    parser.add_argument(
        "--archive-filter",
        default="",
        help="Optional comma-separated .tar.zst filenames to build/upload in archive mode",
    )
    parser.add_argument(
        "--sign-only",
        action="store_true",
        help="Only mint and print fresh #auth=... signed invite URLs without staging/uploading static files",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Stage locally and verify without uploading"
    )
    args = parser.parse_args()

    if not args.bucket:
        if args.dry_run:
            args.bucket = "example-eval-bucket"
        else:
            parser.error("Provide --bucket <name> or set MJOLNIR_EVAL_BUCKET")
    if not VALID_BUCKET_NAME_RE.match(args.bucket):
        raise ValueError(f"Invalid GCS bucket name: {args.bucket}")
    if args.submissions_bucket and not VALID_BUCKET_NAME_RE.match(args.submissions_bucket):
        raise ValueError(f"Invalid submissions GCS bucket name: {args.submissions_bucket}")
    if args.sign_only and not args.signer_service_account:
        parser.error("--sign-only requires --signer-service-account and --submissions-bucket")
    if args.signer_service_account:
        if not VALID_SA_EMAIL_RE.match(args.signer_service_account):
            raise ValueError(
                f"Invalid --signer-service-account email: {args.signer_service_account}"
            )
        if not args.submissions_bucket:
            parser.error("--signer-service-account requires --submissions-bucket")
    if not VALID_SLUG_RE.match(args.study_key):
        raise ValueError(f"Invalid study_key: {args.study_key}")
    priority_batches = parse_priority_batches(args.priority_batches)

    eval_root = ensure_within(REPO_ROOT / "test-out" / "evaluations", REPO_ROOT)
    web_src_dir = ensure_within(REPO_ROOT / "web", REPO_ROOT)
    blind_web_src = ensure_within(REPO_ROOT / "web" / "blind_review", REPO_ROOT)
    pass1_deck_src = ensure_within(
        eval_root / "caliptra-sw" / "pinned" / "blind_review" / "pass1_deck.json",
        REPO_ROOT,
    )
    pass2_deck_src = ensure_within(
        eval_root / "caliptra-sw" / "pinned" / "blind_review" / "pass2_poc_deck.json",
        REPO_ROOT,
    )
    one_off_blind_targets: list[tuple[str, Path]] = [
        (
            "caliptra-mcu-sw",
            eval_root / "caliptra-mcu-sw" / "pinned" / "blind_review" / "pass1_deck.json",
        ),
        (
            "openprot",
            eval_root / "openprot" / "pinned" / "blind_review" / "pass1_deck.json",
        ),
        (
            "opentitan-fw",
            eval_root / "opentitan-fw" / "pinned" / "blind_review" / "pass1_deck.json",
        ),
        (
            "opentitan-rtl-v2",
            eval_root / "opentitan-rtl" / "pinned" / "blind_review" / "pass1_deck.json",
        ),
        (
            "opentitan-rtl",
            eval_root / "opentitan-rtl" / "pinned-v1" / "blind_review" / "pass1_deck.json",
        ),
    ]

    signed_invite_links: list[tuple[str, str, str]] = []
    if args.signer_service_account and (
        args.sign_only or args.only in ("all", "blind", "blind-pass2")
    ):
        targets_to_sign: list[tuple[str, str, str]] = []
        if args.only == "blind-pass2":
            targets_to_sign.append(("caliptra-sw-pass2", args.study_key, "blind-review/pass2"))
        else:
            targets_to_sign.append(("caliptra-sw (v2)", args.study_key, "blind-review/v2"))
            for target_slug, target_deck in one_off_blind_targets:
                if target_deck.is_file():
                    targets_to_sign.append(
                        (target_slug, target_slug, f"blind-review/{target_slug}")
                    )

        mode_note = "[dry-run placeholder sig]" if args.dry_run else "[signed via IAM signBlob]"
        for label, s_key, url_subpath in targets_to_sign:
            sp_obj = generate_v4_signed_post_policy(
                submissions_bucket=args.submissions_bucket,
                signer_service_account=args.signer_service_account,
                study_key=s_key,
                study_prefix="v2",
                ttl_seconds=args.policy_ttl_seconds,
                dry_run=args.dry_run,
            )
            tok = encode_auth_fragment_token(sp_obj)
            full_url = (
                f"https://storage.googleapis.com/{args.bucket}/{url_subpath}/index.html#auth={tok}"
            )
            signed_invite_links.append((label, sp_obj["expires_at"], full_url))
            print(
                f"[blind-review] Signed capability {mode_note}: "
                f"target={label} prefix={sp_obj['key_prefix']} expires_at={sp_obj['expires_at']}"
            )

    if args.sign_only:
        print("\n=== Private Signed Invite URLs (NEVER stored in public GCS) ===")
        for label, exp_ts, full_url in signed_invite_links:
            print(f"\n[{label}] (expires {exp_ts}):\n{full_url}")
        if signed_invite_links and not args.dry_run:
            md_path = write_live_urls_markdown(
                signed_invite_links, args.bucket, args.submissions_bucket
            )
            print(f"\n[ok] Wrote live signed invite URLs to {md_path}")
        return

    stage_root = Path(tempfile.mkdtemp(prefix=f"mjolnir_gcs_stage_{os.getpid()}_", dir="/tmp"))
    try:
        if args.only in ("all", "blind"):
            s_blind_top = stage_root / "blind-review"
            stage_blind_review_deck(
                blind_web_src,
                pass1_deck_src,
                s_blind_top,
                pass_label="root",
                study_key=args.study_key,
                priority_batches=priority_batches,
            )
            stage_blind_review_deck(
                blind_web_src,
                pass1_deck_src,
                s_blind_top / "v2",
                pass_label="v2",
                study_key=args.study_key,
                priority_batches=priority_batches,
            )
            s_blind = s_blind_top / "pass1"
            stage_blind_review_deck(
                blind_web_src,
                pass1_deck_src,
                s_blind,
                pass_label="pass1",
                study_key=args.study_key,
                priority_batches=priority_batches,
            )
            for target_slug, target_deck in one_off_blind_targets:
                if target_deck.is_file():
                    ensure_within(target_deck, REPO_ROOT)
                    stage_blind_review_deck(
                        blind_web_src,
                        target_deck,
                        s_blind_top / target_slug,
                        pass_label=target_slug,
                        study_key=target_slug,
                        priority_batches=[],
                    )
            if not args.dry_run:
                upload_directory_to_gcs(
                    s_blind_top, args.bucket, "blind-review", cache_no_store=True
                )

        if args.only == "blind-pass2":
            s_blind2 = stage_root / "blind-review" / "pass2"
            stage_blind_review_deck(
                blind_web_src,
                pass2_deck_src,
                s_blind2,
                pass_label="pass2",
                study_key=args.study_key,
                priority_batches=priority_batches,
            )
            if not args.dry_run:
                upload_directory_to_gcs(
                    s_blind2, args.bucket, "blind-review/pass2", cache_no_store=True
                )

        if args.only in ("all", "viewer"):
            s_viewer = stage_root / "eval-viewer"
            stage_eval_viewer(eval_root, web_src_dir, s_viewer)
            if not args.dry_run:
                upload_directory_to_gcs(s_viewer, args.bucket, "eval-viewer", cache_no_store=True)

        if args.only in ("all", "ai-eval"):
            v2_local = ensure_within(REPO_ROOT / "pre-review-v2", REPO_ROOT)
            v1_local = ensure_within(REPO_ROOT / "pre-review-v1", REPO_ROOT)
            if not v2_local.is_dir():
                if args.only == "ai-eval":
                    raise FileNotFoundError(
                        f"{v2_local} not found locally; restore from "
                        f"gs://{args.bucket}/eval-archive/caliptra-sw-pre-review-v2.tar.zst first."
                    )
                print(
                    "[ai-eval] Skipping (local pre-review-v2/ removed; already deployed to ai-eval/ and archived in eval-archive/)."
                )
            else:
                s_ai = stage_root / "ai-eval"
                stage_ai_eval(
                    eval_root=eval_root,
                    web_src_dir=web_src_dir,
                    reports_src_dir=ensure_within(REPO_ROOT / "web" / "ai_eval_reports", REPO_ROOT),
                    v2_dir=v2_local,
                    v1_dir=v1_local,
                    stage_ai_dir=s_ai,
                )
                if not args.dry_run:
                    upload_directory_to_gcs(s_ai, args.bucket, "ai-eval", cache_no_store=True)

        if args.only in ("all", "archive"):
            s_arch = stage_root / "eval-archive"
            only_arch_set = (
                {s.strip() for s in args.archive_filter.split(",") if s.strip()}
                if args.archive_filter
                else None
            )
            build_cold_archives(
                eval_root,
                s_arch,
                bucket=args.bucket,
                preserve_remote_sums=not args.dry_run,
                only_archives=only_arch_set,
            )
            if not args.dry_run:
                upload_directory_to_gcs(s_arch, args.bucket, "eval-archive", cache_no_store=False)

        print("\n=== Deployment Summary ===")
        print(f"Cold Archive:       gs://{args.bucket}/eval-archive/")
        print(
            f"Eval Triage Viewer: https://storage.googleapis.com/{args.bucket}/eval-viewer/index.html"
        )
        print(
            f"One-Off Open View:  https://storage.googleapis.com/{args.bucket}/eval-viewer/index.html#/run/00-maintainer-reporting/00-all-one-off-targets/open-findings"
        )
        print(
            f"AI Pre-Review UI:   https://storage.googleapis.com/{args.bucket}/ai-eval/index.html"
        )
        print(
            f"AI Written Reports: https://storage.googleapis.com/{args.bucket}/ai-eval/reports.html"
        )
        print(
            f"Blind Review Root:  https://storage.googleapis.com/{args.bucket}/blind-review/index.html"
        )
        print(
            f"Blind Review v2:    https://storage.googleapis.com/{args.bucket}/blind-review/v2/index.html"
        )
        print(
            f"Blind Review Pass1: https://storage.googleapis.com/{args.bucket}/blind-review/pass1/index.html"
        )
        if args.only == "blind-pass2" or pass2_deck_src.is_file():
            print(
                f"Blind Review Pass2: https://storage.googleapis.com/{args.bucket}/blind-review/pass2/index.html"
            )
        for target_slug, target_deck in one_off_blind_targets:
            if target_deck.is_file():
                label = f"Blind ({target_slug}):"
                print(
                    f"{label:<20}https://storage.googleapis.com/{args.bucket}/blind-review/{target_slug}/index.html"
                )
        if signed_invite_links:
            print("\n=== Private Signed Invite URLs (NEVER stored in public GCS) ===")
            for label, exp_ts, full_url in signed_invite_links:
                print(f"\n[{label}] (expires {exp_ts}):\n{full_url}")
            if not args.dry_run:
                md_path = write_live_urls_markdown(
                    signed_invite_links, args.bucket, args.submissions_bucket
                )
                print(f"\n[ok] Wrote live signed invite URLs to {md_path}")
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


if __name__ == "__main__":
    main()
