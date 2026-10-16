# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Materializes clean, single-commit Git snapshots from pinned Nix store sources or cached baselines."""

import os
from pathlib import Path
import shutil
import subprocess

from evaluation.constants import (
    ORPHAN_SNAPSHOT_COMMIT_MESSAGE,
    ORPHAN_SNAPSHOT_DATE,
)
from executors.ctags import CtagsRunner
from utilities.git import setup_repository
from utilities.logger import logger


class OrphanSnapshotBuilder:
    """Builds clean single-commit Git workspaces from pinned Nix store sources or cached baselines."""

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
        """Resolves a clean baseline source tree (preferring immutable Nix store path)."""
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
        skip_ctags: bool = False,
    ) -> Path:
        """Copies baseline_dir to dest_dir and initializes a clean single-commit Git workspace with Ctags."""
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.parent.mkdir(parents=True, exist_ok=True)

        shutil.copytree(
            baseline_dir,
            dest_dir,
            symlinks=True,
            ignore=shutil.ignore_patterns(
                ".git",
                ".mjolnir_tags*",
                "poc_worktrees",
                "target",
                "*threat_model*.md",
                "THREAT_MODEL*.md",
            ),
        )
        # Strip any in-repo mjolnir config directories (e.g. tools/mjolnir in Caliptra repos)
        # so 'no_tm' / 'cli_*_no_tm' ablation tiers cannot read threat_model.md from the workspace
        for rel_mjolnir_dir in ("tools/mjolnir", "mjolnir", ".mjolnir"):
            candidate_dir = dest_dir / rel_mjolnir_dir
            if candidate_dir.exists():
                shutil.rmtree(candidate_dir, ignore_errors=True)
        # Ensure dest_dir itself and all copied files from read-only /nix/store are writable
        dest_dir.chmod(dest_dir.stat().st_mode | 0o700)
        for root, dirs, files in os.walk(dest_dir):
            for d in dirs:
                p = Path(root) / d
                if not p.is_symlink():
                    p.chmod(p.stat().st_mode | 0o700)
            for f in files:
                p = Path(root) / f
                if not p.is_symlink():
                    p.chmod(p.stat().st_mode | 0o600)

        self._init_single_commit_repo(dest_dir)
        if not skip_ctags:
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
        """Asserts that the snapshot has exactly 1 commit, 0 remotes, and a clean working tree."""
        rev_count = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if rev_count != "1":
            raise RuntimeError(
                f"Snapshot integrity error: workspace has {rev_count} commits instead of 1"
            )

        remotes = subprocess.run(
            ["git", "remote"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if remotes:
            raise RuntimeError(f"Snapshot integrity error: workspace has git remotes: {remotes}")

        status = subprocess.run(
            ["git", "status", "--porcelain", "--", ":!.mjolnir_tags*", ":!tags*"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if status:
            raise RuntimeError(
                f"Snapshot integrity error: workspace working tree is dirty:\n{status}"
            )
