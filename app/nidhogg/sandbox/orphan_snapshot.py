# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Materializes history-scrubbed single-commit Git snapshots for cheat-proof benchmarking."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from executors.ctags import CtagsRunner
from nidhogg.constants import (
    BENCHMARK_CANARY_GUID,
    ORPHAN_SNAPSHOT_COMMIT_MESSAGE,
    ORPHAN_SNAPSHOT_DATE,
)
from utilities.git import setup_repository
from utilities.logger import logger


def apply_patch_with_fallbacks(repo_dir: Path, patch_text: str) -> tuple[bool, str]:
    """Applies a unified diff using the 4-step fallback sequence from go/mjolnir-plan §2.

    1. git apply --whitespace=fix
    2. git apply --recount --whitespace=fix
    3. git apply --3way
    4. patch -p1 --ignore-whitespace
    """
    if not patch_text.strip():
        return False, "Empty patch text"

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".diff", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write(patch_text if patch_text.endswith("\n") else patch_text + "\n")
        patch_path = Path(tmp.name)

    strategies = [
        ("git apply --whitespace=fix", ["git", "apply", "--whitespace=fix", str(patch_path)]),
        (
            "git apply --recount --whitespace=fix",
            ["git", "apply", "--recount", "--whitespace=fix", str(patch_path)],
        ),
        ("git apply --3way", ["git", "apply", "--3way", str(patch_path)]),
        (
            "patch -p1 --ignore-whitespace",
            ["patch", "-p1", "--ignore-whitespace", "-i", str(patch_path)],
        ),
    ]

    last_err = ""
    try:
        for strategy_name, cmd in strategies:
            res = subprocess.run(
                cmd,
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                logger.debug(f"Applied patch via strategy: {strategy_name}")
                return True, strategy_name
            last_err = f"[{strategy_name}] {res.stderr.strip() or res.stdout.strip()}"
            # Clean any partial state before next fallback
            subprocess.run(
                ["git", "checkout", "--", "."],
                cwd=str(repo_dir),
                capture_output=True,
                check=False,
            )
    finally:
        patch_path.unlink(missing_ok=True)

    return False, last_err


class OrphanSnapshotBuilder:
    """Builds history-scrubbed single-commit Git workspaces so evaluated agents cannot cheat via git history."""

    def __init__(self, cache_root: Path):
        self.cache_root = cache_root.expanduser().resolve()
        self.cache_root.mkdir(parents=True, exist_ok=True)

    def ensure_pinned_baseline(
        self,
        repo_name: str,
        repo_url: str,
        pinned_rev: str,
        nix_source_path: str | None = None,
    ) -> Path:
        """Ensures a clean baseline checkout at pinned_rev exists in the cache."""
        if nix_source_path and Path(nix_source_path).exists():
            return Path(nix_source_path).resolve()

        target_dir = self.cache_root / f"{repo_name}-{pinned_rev[:12]}"
        if not (target_dir / ".git").exists():
            logger.info(
                f"Fetching immutable baseline for {repo_name} at pinned rev {pinned_rev}..."
            )
            setup_repository(
                repo_url,
                str(target_dir),
                pinned_rev,
                str(self.cache_root),
            )
        return target_dir

    def materialize_orphan_snapshot(
        self,
        baseline_dir: Path,
        dest_dir: Path,
        vuln_patches: list[str] | None = None,
    ) -> Path:
        """Copies baseline_dir to dest_dir, applies vuln_patches, and scrubs all Git history into a single commit."""
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.parent.mkdir(parents=True, exist_ok=True)

        # Copy baseline without .git history first, then initialize a temporary git repo to apply patches cleanly
        shutil.copytree(
            baseline_dir,
            dest_dir,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", ".mjolnir_tags*", "poc_worktrees", "target"),
        )

        self._init_single_commit_repo(dest_dir)

        for patch_text in vuln_patches or []:
            ok, detail = apply_patch_with_fallbacks(dest_dir, patch_text)
            if not ok:
                raise RuntimeError(f"Failed to apply synthetic vulnerability patch: {detail}")

        # Re-scrub .git so that the applied patch is squashed into the single initial commit
        shutil.rmtree(dest_dir / ".git")
        self._init_single_commit_repo(dest_dir)
        CtagsRunner().ensure_tags(dest_dir)
        self.verify_snapshot_integrity(dest_dir)
        return dest_dir

    def _init_single_commit_repo(self, repo_dir: Path) -> None:
        env = os.environ.copy()
        env["GIT_AUTHOR_NAME"] = "Source Snapshot"
        env["GIT_AUTHOR_EMAIL"] = "snapshot@local"
        env["GIT_COMMITTER_NAME"] = "Source Snapshot"
        env["GIT_COMMITTER_EMAIL"] = "snapshot@local"
        env["GIT_AUTHOR_DATE"] = ORPHAN_SNAPSHOT_DATE
        env["GIT_COMMITTER_DATE"] = ORPHAN_SNAPSHOT_DATE

        cmds = [
            ["git", "init", "-q"],
            ["git", "add", "-A"],
            ["git", "commit", "-q", "-m", ORPHAN_SNAPSHOT_COMMIT_MESSAGE],
        ]
        for cmd in cmds:
            subprocess.run(cmd, cwd=str(repo_dir), env=env, check=True, capture_output=True)

    def verify_snapshot_integrity(self, repo_dir: Path) -> None:
        """Asserts that the snapshot has exactly 1 commit, 0 remotes, clean status, and no canary leakage."""
        rev_count = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if rev_count != "1":
            raise RuntimeError(
                f"Anti-cheat violation: snapshot has {rev_count} commits instead of 1"
            )

        remotes = subprocess.run(
            ["git", "remote"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if remotes:
            raise RuntimeError(f"Anti-cheat violation: snapshot has git remotes: {remotes}")

        status = subprocess.run(
            ["git", "status", "--porcelain", "--", ":!.mjolnir_tags*", ":!tags*"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if status:
            raise RuntimeError(f"Anti-cheat violation: snapshot working tree is dirty:\n{status}")

        # Verify canary GUID is not present anywhere in the materialized tree
        rg_res = subprocess.run(
            ["rg", "-l", BENCHMARK_CANARY_GUID, str(repo_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        if rg_res.returncode == 0 and rg_res.stdout.strip():
            raise RuntimeError(
                f"Anti-cheat violation: benchmark canary leaked into snapshot: {rg_res.stdout}"
            )
