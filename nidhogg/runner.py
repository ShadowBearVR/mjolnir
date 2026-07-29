# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

import os
import subprocess
from pathlib import Path
from typing import Tuple, Optional
from nidhogg.config import ROOT_DIR, get_opentitan_code_dir, DEFAULT_NIX_RUNNER_TARGET

class OpenTitanRunner:
    """Manages workspace patch application and build verification via Nix Bazel runner."""

    def __init__(self, code_dir: Optional[Path] = None):
        self.code_dir = code_dir or get_opentitan_code_dir()

    def apply_patch(self, patch_diff: str) -> Tuple[bool, str]:
        """Applies a unified git diff patch with multi-strategy fallback (recount, 3way, patch CLI)."""
        if not self.code_dir.exists():
            return False, f"Code directory {self.code_dir} does not exist."

        # Strategy 1: Standard git apply
        cmd1 = ["git", "apply", "--whitespace=fix", "-"]
        p1 = subprocess.run(cmd1, input=patch_diff, text=True, cwd=str(self.code_dir), capture_output=True)
        if p1.returncode == 0:
            return True, "Patch applied successfully (Standard)."

        # Strategy 2: Git apply --recount (re-evaluates line counts in hunk headers)
        cmd2 = ["git", "apply", "--recount", "--whitespace=fix", "-"]
        p2 = subprocess.run(cmd2, input=patch_diff, text=True, cwd=str(self.code_dir), capture_output=True)
        if p2.returncode == 0:
            return True, "Patch applied successfully (Recount strategy)."

        # Strategy 3: Git apply --3way (3-way merge fallback)
        cmd3 = ["git", "apply", "--3way", "--whitespace=fix", "-"]
        p3 = subprocess.run(cmd3, input=patch_diff, text=True, cwd=str(self.code_dir), capture_output=True)
        if p3.returncode == 0:
            return True, "Patch applied successfully (3-way merge strategy)."

        # Strategy 4: GNU patch fallback
        cmd4 = ["patch", "-p1", "--ignore-whitespace"]
        p4 = subprocess.run(cmd4, input=patch_diff, text=True, cwd=str(self.code_dir), capture_output=True)
        if p4.returncode == 0:
            return True, "Patch applied successfully (GNU patch strategy)."

        # Aggregate error message for LLM feedback loop
        err_msg = (
            f"Standard git apply: {p1.stderr.strip()}\n"
            f"Recount git apply: {p2.stderr.strip()}\n"
            f"3-way git apply: {p3.stderr.strip()}\n"
            f"GNU patch: {p4.stderr.strip()}"
        )
        return False, err_msg

    def revert_workspace(self) -> Tuple[bool, str]:
        """Reverts all local uncommitted modifications in the workspace."""
        if not self.code_dir.exists():
            return False, "Code directory does not exist."

        try:
            subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=str(self.code_dir), capture_output=True, check=True)
            subprocess.run(["git", "clean", "-fd"], cwd=str(self.code_dir), capture_output=True, check=True)
            return True, "Workspace reverted cleanly."
        except Exception as e:
            return False, f"Failed to revert workspace: {str(e)}"

    def run_build_check(self, runner_target: str = DEFAULT_NIX_RUNNER_TARGET, test_target: Optional[str] = None) -> Tuple[bool, str, str]:
        """Executes Bazel directly in the target workspace for fast build & test verification."""
        if test_target is None:
            test_target = "//sw/device/silicon_creator/lib/drivers:uart_unittest"

        output_base = str(self.code_dir.parent / "bazel-out-base")
        shared_disk = "/tmp/opentitan-bazel-shared-disk"
        shared_repo = "/tmp/opentitan-bazel-shared-repo"

        action = "build" if ("..." in test_target or "build" in test_target) else "test"
        cmd = [
            "bazel",
            f"--output_base={output_base}",
            action,
            f"--disk_cache={shared_disk}",
            f"--repository_cache={shared_repo}",
            "--noincompatible_strict_action_env",
            test_target
        ]

        env = os.environ.copy()
        env["MJOLNIR_WORKSPACE"] = str(self.code_dir.parent if self.code_dir.name == "opentitan" else self.code_dir)

        try:
            process = subprocess.run(
                cmd,
                cwd=str(self.code_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=180
            )
            passed = (process.returncode == 0)
            cmd_str = " ".join(cmd)
            output = f"STDOUT:\n{process.stdout}\n\nSTDERR:\n{process.stderr}"
            return passed, cmd_str, output
        except Exception as e:
            return False, f"bazel execution error", str(e)
