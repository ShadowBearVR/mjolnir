# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Unprivileged Bubblewrap (bwrap) mount-namespace isolation for evaluation trials."""

from pathlib import Path
import shutil
import subprocess

from utilities.logger import logger


class IsolatedProcessRunner:
    """Executes evaluated agents inside a Linux mount namespace masking prior trial outputs and cache paths."""

    def __init__(self, masked_paths: list[Path]):
        self.masked_paths = [p.expanduser().resolve() for p in masked_paths if p.exists()]
        self.bwrap_bin = shutil.which("bwrap")

    def run_isolated(
        self,
        cmd: list[str],
        cwd: Path,
        env: dict[str, str] | None = None,
        timeout: int = 14400,
        stream_output: bool = False,
    ) -> subprocess.CompletedProcess:
        """Runs cmd inside bwrap with --tmpfs mounted over masked cache and output directories."""
        full_cmd = self._wrap_command(cmd, cwd)
        if stream_output:
            res = subprocess.run(
                full_cmd,
                cwd=str(cwd),
                env=env,
                text=True,
                timeout=timeout,
                check=False,
            )
            return subprocess.CompletedProcess(
                args=res.args,
                returncode=res.returncode,
                stdout="",
                stderr="",
            )
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
            logger.warning("bwrap binary not found in PATH; running in host namespace.")
            return cmd

        probe = subprocess.run(
            [self.bwrap_bin, "--ro-bind", "/", "/", "true"],
            capture_output=True,
            check=False,
        )
        if probe.returncode != 0:
            logger.warning(
                "Kernel restricts unprivileged bwrap namespaces; running in host namespace."
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
        # Mask any non-standard top-level root directories that do not contain cwd or HOME
        standard_root_dirs = {
            "bin",
            "dev",
            "etc",
            "lib",
            "lib64",
            "nix",
            "opt",
            "proc",
            "run",
            "sbin",
            "sys",
            "tmp",
            "usr",
            "var",
        }
        home_str = str(Path.home().resolve())
        cwd_str = str(cwd.resolve())
        for entry in sorted(Path("/").iterdir()):
            if not entry.is_dir() or entry.is_symlink():
                continue
            if entry.name in standard_root_dirs:
                continue
            entry_str = str(entry.resolve())
            if cwd_str.startswith(entry_str + "/") or home_str.startswith(entry_str + "/"):
                continue
            bwrap_cmd.extend(["--tmpfs", str(entry)])

        for masked in self.masked_paths:
            if not str(cwd).startswith(str(masked)):
                bwrap_cmd.extend(["--tmpfs", str(masked)])

        bwrap_cmd.extend(["--", *cmd])
        return bwrap_cmd
