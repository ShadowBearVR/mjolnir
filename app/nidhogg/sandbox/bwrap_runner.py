# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Unprivileged Bubblewrap (bwrap) mount-namespace isolation and post-run tamper auditing."""

from pathlib import Path
import shutil
import subprocess

from nidhogg.constants import BENCHMARK_CANARY_GUID
from utilities.logger import logger


class IsolatedProcessRunner:
    """Executes benchmarked agents inside a Linux mount namespace masking ground-truth corpus paths."""

    def __init__(self, masked_paths: list[Path]):
        self.masked_paths = [p.expanduser().resolve() for p in masked_paths if p.exists()]
        self.bwrap_bin = shutil.which("bwrap")

    def run_isolated(
        self,
        cmd: list[str],
        cwd: Path,
        env: dict[str, str] | None = None,
        timeout: int = 3600,
    ) -> subprocess.CompletedProcess:
        """Runs cmd inside bwrap with --tmpfs mounted over all ground-truth corpus and baseline cache directories."""
        full_cmd = self._wrap_command(cmd, cwd)
        return subprocess.run(
            full_cmd,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _wrap_command(self, cmd: list[str], cwd: Path) -> list[str]:
        if not self.bwrap_bin:
            logger.warning(
                "bwrap binary not found in PATH; falling back to host namespace + post-run canary tamper audit."
            )
            return cmd

        # Probe whether unprivileged user namespaces are enabled on this kernel
        probe = subprocess.run(
            [self.bwrap_bin, "--ro-bind", "/", "/", "true"],
            capture_output=True,
            check=False,
        )
        if probe.returncode != 0:
            logger.warning(
                "Kernel restricts unprivileged bwrap namespaces; using post-run canary tamper audit."
            )
            return cmd

        bwrap_cmd = [
            self.bwrap_bin,
            "--dev-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            str(cwd),
            "--die-with-parent",
        ]
        # Mask every sensitive corpus / baseline cache directory with an empty tmpfs
        for masked in self.masked_paths:
            if not str(cwd).startswith(str(masked)):
                bwrap_cmd.extend(["--tmpfs", str(masked)])

        bwrap_cmd.extend(["--", *cmd])
        return bwrap_cmd


def audit_run_for_tampering(run_dir: Path, canary: str = BENCHMARK_CANARY_GUID) -> bool:
    """Scans all logs, JSON outputs, and transcripts in run_dir for the benchmark canary GUID.

    Returns True if tampering/leakage is detected.
    """
    if not run_dir.exists():
        return False

    for path in run_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            if canary in content:
                logger.error(f"ANTI-CHEAT TAMPER ALERT: Benchmark canary GUID found in {path}!")
                return True
        except Exception:
            continue
    return False
