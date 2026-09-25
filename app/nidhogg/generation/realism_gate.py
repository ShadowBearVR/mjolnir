# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Automated Realism, Lexical Stealth, and Two-Sided Binary PoC Oracle Gate for Nidhogg."""

from pathlib import Path
import shutil
import subprocess
import tempfile

from nidhogg.constants import ADDED_COMMENT_RE, REVEALING_TOKEN_RE
from nidhogg.sandbox.orphan_snapshot import apply_patch_with_fallbacks
from utilities.logger import logger
from utilities.worktree_sandbox import WorktreeSandbox


class WorktreeRealismGate:
    """Enforces lexical stealth, clean compilation/linting, and two-sided PoC oracle verification."""

    def check_lexical_stealth(self, vuln_patch_diff: str) -> tuple[bool, list[str]]:
        """Rejects synthetic vulnerability patches that add comments or revealing tokens."""
        issues: list[str] = []
        if not vuln_patch_diff.strip():
            return False, ["Empty production vulnerability diff"]

        for idx, line in enumerate(vuln_patch_diff.splitlines(), start=1):
            if not line.startswith("+") or line.startswith("+++"):
                continue
            if ADDED_COMMENT_RE.match(line):
                issues.append(f"Line {idx}: Added comment in production diff ('{line.strip()}')")
            for match in REVEALING_TOKEN_RE.finditer(line):
                issues.append(f"Line {idx}: Revealing token '{match.group(0)}' in production diff")
        return len(issues) == 0, issues

    def split_prod_and_test_diffs(
        self, sandbox: WorktreeSandbox
    ) -> tuple[str, str, list[str], list[str]]:
        """Separates modified files in the sandbox into production patch (vuln_patch.diff) and test patch (oracle_poc.diff)."""
        modified = sandbox.get_modified_files()
        prod_files = [f for f in modified if not sandbox.is_test_or_harness_path(f)]
        test_files = [f for f in modified if sandbox.is_test_or_harness_path(f)]

        prod_diff = sandbox._run_git("diff", "HEAD", "--", *prod_files).stdout if prod_files else ""
        test_diff = sandbox._run_git("diff", "HEAD", "--", *test_files).stdout if test_files else ""
        return prod_diff, test_diff, prod_files, test_files

    def verify_two_sided_poc_oracle(
        self,
        baseline_dir: Path,
        vuln_patch: str,
        oracle_poc_patch: str,
        oracle_test_cmd: str,
        lint_cmd: str | None = None,
        is_distractor: bool = False,
    ) -> tuple[bool, str]:
        """Verifies the two-sided binary PoC oracle in an ephemeral worktree:

        1. On (baseline + vuln_patch): lint_cmd (if provided) MUST PASS.
        2. On (baseline + vuln_patch + oracle_poc_patch):
           - If is_distractor=False: oracle_test_cmd MUST FAIL (proving vulnerability is triggered).
           - If is_distractor=True:  oracle_test_cmd MUST PASS (proving decoy is benign).
        3. On (baseline + oracle_poc_patch) [vuln_patch reverted]:
           - oracle_test_cmd MUST PASS (proving test is non-flaky and passes on uninjected code).
        """
        if not oracle_poc_patch.strip():
            return False, "Missing oracle_poc.diff test harness patch"

        tmp_root = Path(tempfile.mkdtemp(prefix="nidhogg-oracle-"))
        try:
            work_dir = tmp_root / "repo"
            shutil.copytree(
                baseline_dir,
                work_dir,
                symlinks=True,
                ignore=shutil.ignore_patterns(".git", ".mjolnir_tags*", "poc_worktrees"),
            )
            subprocess.run(["git", "init", "-q"], cwd=str(work_dir), check=True)
            subprocess.run(["git", "add", "-A"], cwd=str(work_dir), check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "base"],
                cwd=str(work_dir),
                check=True,
            )

            # Step 1: Apply vuln_patch and run linter if configured
            ok, detail = apply_patch_with_fallbacks(work_dir, vuln_patch)
            if not ok:
                return False, f"Failed to apply vuln_patch.diff: {detail}"

            if lint_cmd:
                lint_res = subprocess.run(
                    ["/bin/bash", "-c", lint_cmd],
                    cwd=str(work_dir),
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                if lint_res.returncode != 0:
                    return (
                        False,
                        f"Linter failed on injected code: {lint_res.stderr[-800:] or lint_res.stdout[-800:]}",
                    )

            # Step 2: Apply oracle_poc_patch on top of vuln_patch
            ok_poc, detail_poc = apply_patch_with_fallbacks(work_dir, oracle_poc_patch)
            if not ok_poc:
                return False, f"Failed to apply oracle_poc.diff: {detail_poc}"

            patched_res = subprocess.run(
                ["/bin/bash", "-c", oracle_test_cmd],
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )

            if not is_distractor and patched_res.returncode == 0:
                return (
                    False,
                    "Oracle test PASSED on vulnerable code (expected FAILURE to prove exploitability)",
                )
            if is_distractor and patched_res.returncode != 0:
                return (
                    False,
                    "Oracle test FAILED on distractor injection (distractors must be benign and pass)",
                )

            # Step 3: Reset to clean base and apply ONLY oracle_poc_patch
            subprocess.run(
                ["git", "reset", "--hard", "HEAD"],
                cwd=str(work_dir),
                capture_output=True,
                check=True,
            )
            subprocess.run(
                ["git", "clean", "-fd"],
                cwd=str(work_dir),
                capture_output=True,
                check=True,
            )
            ok_base_poc, detail_base_poc = apply_patch_with_fallbacks(work_dir, oracle_poc_patch)
            if not ok_base_poc:
                return (
                    False,
                    f"Failed to apply oracle_poc.diff cleanly onto unpatched baseline: {detail_base_poc}",
                )

            base_res = subprocess.run(
                ["/bin/bash", "-c", oracle_test_cmd],
                cwd=str(work_dir),
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if base_res.returncode != 0:
                return (
                    False,
                    f"Oracle test FAILED on clean baseline (must PASS when vuln_patch is absent): {base_res.stderr[-800:] or base_res.stdout[-800:]}",
                )

            logger.success(
                f"Two-sided binary PoC oracle verified ({'Distractor' if is_distractor else 'Vulnerability'})."
            )
            return True, "Verified two-sided binary PoC oracle"
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
