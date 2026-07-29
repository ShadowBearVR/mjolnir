# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from typing import Optional, Dict, Any
from nidhogg.runner import OpenTitanRunner

class NidhoggADKTools:
    """Tool execution suite exposed to the ADK ReAct Generator Agent."""

    def __init__(self, runner: OpenTitanRunner):
        self.runner = runner

    def read_source_file(self, file_path: str, start_line: int = 1, end_line: int = 500) -> str:
        """Reads a range of lines from a source file in the target workspace."""
        full_path = self.runner.code_dir / file_path
        if not full_path.exists():
            return f"Error: File {file_path} does not exist at {full_path}"

        try:
            with open(full_path, "r", errors="ignore") as f:
                lines = f.readlines()
            
            total_lines = len(lines)
            start_idx = max(0, start_line - 1)
            end_idx = min(total_lines, end_line)

            selected_lines = lines[start_idx:end_idx]
            formatted = "".join([f"{i + start_idx + 1}: {line}" for i, line in enumerate(selected_lines)])
            return f"File: {file_path} (Lines {start_idx + 1}-{end_idx} of {total_lines}):\n{formatted}"
        except Exception as e:
            return f"Error reading file {file_path}: {str(e)}"

    def apply_patch(self, patch_diff: str) -> str:
        """Applies a unified git diff patch to the workspace. Returns success or detailed error output."""
        success, msg = self.runner.apply_patch(patch_diff)
        if success:
            return f"SUCCESS: {msg}"
        else:
            return f"FAILED to apply patch:\n{msg}"

    def revert_workspace(self) -> str:
        """Reverts all uncommitted changes in the workspace."""
        success, msg = self.runner.revert_workspace()
        return msg

    def run_build_check(self, runner_target: str = "opentitan-runner-host-test") -> str:
        """Runs Bazel build & test check. Returns pass/fail status and exact compiler diagnostics."""
        passed, cmd, output = self.runner.run_build_check(runner_target)
        if passed:
            return f"BUILD/TEST PASSED!\nCommand: {cmd}\nOutput Preview:\n{output[:1000]}"
        else:
            return f"BUILD/TEST FAILED!\nCommand: {cmd}\nCompiler Diagnostics & Error Log:\n{output[:3000]}"
