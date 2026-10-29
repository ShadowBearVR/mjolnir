# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Unit tests verifying codebase audit remediations C1, C2, C3, and C5."""

import asyncio
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "app"))
sys.path.insert(0, str(ROOT_DIR / "app" / "mjolnir"))

from data.exploit_finding import ExploitFinding  # noqa: E402
from providers.adk.agents.auditor import build_auditor_instruction  # noqa: E402
from providers.adk.phases.poc_creation import _assemble_ground_truth_poc_bundle  # noqa: E402
from utilities.worktree_sandbox import (  # noqa: E402
    CommandRecord,
    WorktreeSandbox,
    rust_non_test_code_unchanged,
)


class TestCodebaseAuditConcerns(unittest.TestCase):
    def test_c1_integration_guide_hardens_ci_fork_pr_workflow(self) -> None:
        guide = (ROOT_DIR / "INTEGRATION_GUIDE.md").read_text(encoding="utf-8")
        yaml_block = guide.split("```yaml", 1)[1].split("```", 1)[0]
        self.assertNotIn("nix run path:.", yaml_block)
        self.assertIn("pull_request_target:", yaml_block)
        self.assertIn("mjolnir:run-audit", yaml_block)
        self.assertIn("MJOLNIR_FLAKE", yaml_block)

    def test_c1_sandbox_network_isolation_and_path_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_dir = tmp_path / "repo"
            repo_dir.mkdir()
            (repo_dir / "lib.rs").write_text("pub fn ok() -> bool { true }\n", encoding="utf-8")
            ws_dir = tmp_path / "ws"

            sb = WorktreeSandbox(repo_dir, ws_dir, "VULN-C1")
            sb.setup()
            try:
                # 1. Path traversal in write_file must fail closed
                with self.assertRaises(ValueError):
                    sb.write_file("../escaped.txt", "bad")

                # 2. Explicit network CLI tools are blocked by validate_harness_command
                for net_cmd in ("curl https://example.com", "wget https://example.com", "ssh host"):
                    rec = asyncio.run(sb.run_harness_command_async(net_cmd))
                    self.assertEqual(rec.returncode, 126)
                    self.assertIn("Access denied", rec.output)

                # 3. Kernel netns (--unshare-net) blocks outbound socket connections on Linux
                if WorktreeSandbox._probe_bwrap_netns():
                    probe_cmd = (
                        "python3 -c 'import socket; s=socket.socket(); "
                        's.settimeout(1.0); s.connect(("8.8.8.8", 53))\''
                    )
                    rec = asyncio.run(sb.run_harness_command_async(probe_cmd))
                    self.assertNotEqual(rec.returncode, 0)
            finally:
                sb.cleanup()

    def test_c2_auditor_prompt_removes_opentitan_hardcoded_filters(self) -> None:
        auditor_md = (
            ROOT_DIR / "app" / "mjolnir" / "providers" / "adk" / "prompts" / "auditor.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn("The UART Reachability Filter", auditor_md)
        self.assertNotIn("Watchdog Crash Exclusion", auditor_md)
        self.assertIn("Root-of-Trust (RoT) firmware and hardware RTL", auditor_md)
        self.assertIn("Project-Mandated Fault-Injection & Hardware Countermeasures", auditor_md)

    def test_c3_language_skill_routing_for_rust_c_and_sv(self) -> None:
        rust_inst = build_auditor_instruction(extensions=["rs"])
        self.assertIn("# Rust Security Audit Guidelines", rust_inst)
        self.assertNotIn("# C/C++ Security Audit Guidelines", rust_inst)
        self.assertNotIn("# SystemVerilog / RTL Security Audit Guidelines", rust_inst)

        c_inst = build_auditor_instruction(extensions=[".c", ".h"])
        self.assertIn("# C/C++ Security Audit Guidelines", c_inst)
        self.assertNotIn("# Rust Security Audit Guidelines", c_inst)
        self.assertNotIn("# SystemVerilog / RTL Security Audit Guidelines", c_inst)

        sv_inst = build_auditor_instruction(extensions=["sv"])
        self.assertIn("# SystemVerilog / RTL Security Audit Guidelines", sv_inst)
        self.assertNotIn("# Rust Security Audit Guidelines", sv_inst)
        self.assertNotIn("# C/C++ Security Audit Guidelines", sv_inst)

        fallback_inst = build_auditor_instruction(extensions=None)
        self.assertIn("# Rust Security Audit Guidelines", fallback_inst)
        self.assertIn("# C/C++ Security Audit Guidelines", fallback_inst)
        self.assertIn("# SystemVerilog / RTL Security Audit Guidelines", fallback_inst)

    def test_c5_rust_inline_test_lexical_gate_catches_sneaky_prod_edits(self) -> None:
        baseline = (
            "pub struct Buf<'a> { pub data: &'a [u8] }\n"
            "/* nested /* comment */ ok */\n"
            'pub fn check_tag(tag: &str) -> bool { tag == r#"expected"# }\n'
        )
        legit_mod = (
            baseline
            + "\n#[cfg(test)]\n#[allow(unused_imports)]\nmod tests {\n"
            + "    use super::{Buf, check_tag};\n"
            + "    #[test]\n"
            + '    fn poc_case() { assert!(!check_tag("bad")); }\n'
            + "}\n"
        )
        self.assertTrue(rust_non_test_code_unchanged(baseline, legit_mod))

        sneaky_mod = (
            baseline
            + "\npub fn injected_helper() -> bool { true }\n"
            + "#[cfg(test)]\nmod tests {\n    #[test]\n    fn poc() { assert!(super::injected_helper()); }\n}\n"
        )
        self.assertFalse(rust_non_test_code_unchanged(baseline, sneaky_mod))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_dir = tmp_path / "repo"
            (repo_dir / "src").mkdir(parents=True)
            (repo_dir / "src" / "auth.rs").write_text(baseline, encoding="utf-8")
            ws_dir = tmp_path / "ws"

            sb = WorktreeSandbox(repo_dir, ws_dir, "VULN-C5-RS", isolate_network=False)
            sb.setup()
            try:
                sb.write_file("src/auth.rs", legit_mod)
                self.assertFalse(sb.has_production_code_modifications())

                sb.write_file("src/auth.rs", sneaky_mod)
                self.assertTrue(sb.has_production_code_modifications())
            finally:
                sb.cleanup()

    def test_c5_scoped_cargo_toml_and_bazel_build_checks(self) -> None:
        cargo_base = (
            '[package]\nname = "demo"\nversion = "0.1.0"\n\n[dependencies]\nzeroize = "1"\n'
        )
        bazel_base = (
            'load("@rules_rust//rust:defs.bzl", "rust_library")\n\n'
            'rust_library(\n    name = "demo",\n    srcs = ["src/lib.rs"],\n)\n'
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_dir = tmp_path / "repo"
            (repo_dir / "src").mkdir(parents=True)
            (repo_dir / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
            (repo_dir / "Cargo.toml").write_text(cargo_base, encoding="utf-8")
            (repo_dir / "BUILD.bazel").write_text(bazel_base, encoding="utf-8")
            ws_dir = tmp_path / "ws"

            sb = WorktreeSandbox(repo_dir, ws_dir, "VULN-C5-BUILD", isolate_network=False)
            sb.setup()
            try:
                # 1. Safe [dev-dependencies] + [[test]] in Cargo.toml and rust_test in BUILD.bazel
                sb.write_file(
                    "Cargo.toml",
                    cargo_base + '\n[dev-dependencies]\nproptest = "1"\n',
                )
                sb.write_file(
                    "BUILD.bazel",
                    'load("@rules_rust//rust:defs.bzl", "rust_test")\n'
                    + bazel_base
                    + '\nrust_test(\n    name = "poc_test",\n    srcs = ["tests/poc.rs"],\n)\n',
                )
                self.assertFalse(sb.has_production_code_modifications())

                # 2. Unsafe [features] addition in Cargo.toml -> rejected
                sb.write_file(
                    "Cargo.toml",
                    cargo_base + "\n[features]\nbypass_auth = []\n",
                )
                self.assertTrue(sb.has_production_code_modifications())

                # 3. Reset Cargo.toml and test unsafe modification inside rust_library in BUILD.bazel -> rejected
                sb.write_file("Cargo.toml", cargo_base)
                sb.write_file(
                    "BUILD.bazel",
                    'load("@rules_rust//rust:defs.bzl", "rust_library")\n\n'
                    'rust_library(\n    name = "demo",\n    srcs = ["src/lib.rs"],\n    rustc_flags = ["--cfg=test"],\n)\n',
                )
                self.assertTrue(sb.has_production_code_modifications())
            finally:
                sb.cleanup()

    def test_c5_poc_bundle_enforces_exit_zero_and_non_vacuous_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_dir = tmp_path / "repo"
            (repo_dir / "tests").mkdir(parents=True)
            (repo_dir / "tests" / "poc_test.rs").write_text(
                "#[test]\nfn base() {}\n", encoding="utf-8"
            )
            ws_dir = tmp_path / "ws"

            sb = WorktreeSandbox(repo_dir, ws_dir, "VULN-C5-EXIT", isolate_network=False)
            sb.setup()
            try:
                sb.write_file(
                    "tests/poc_test.rs",
                    "#[test]\nfn base() {}\n#[test]\n#[should_panic]\nfn poc() { panic!(); }\n",
                )

                # Case 1: Exit 0 with 1 passed lib test + 0 passed doc-tests -> ACCEPTED
                sb.command_history = [
                    CommandRecord(
                        command="cargo test poc",
                        returncode=0,
                        output=(
                            "running 1 test\ntest poc ... ok\n"
                            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out\n"
                            "Doc-tests demo\nrunning 0 tests\n"
                            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
                        ),
                    )
                ]
                f_ok = ExploitFinding(
                    poc="valid",
                    test_command="cargo test poc",
                    test_output="",
                    poc_verified=True,
                    justification="Demonstrated panic cleanly via #[should_panic].",
                )
                bundle_ok = _assemble_ground_truth_poc_bundle(f_ok, sb)
                self.assertTrue(f_ok.poc_verified)
                self.assertIn("**Mechanical Gate Rejected**: `False`", bundle_ok)

                # Case 2: Non-zero exit code -> REJECTED
                sb.command_history = [
                    CommandRecord(
                        command="cargo test poc",
                        returncode=101,
                        output="error: test failed",
                    )
                ]
                f_nonzero = ExploitFinding(
                    poc="failed",
                    test_command="cargo test poc",
                    test_output="",
                    poc_verified=True,
                    justification="Claimed verified despite exit 101.",
                )
                bundle_nz = _assemble_ground_truth_poc_bundle(f_nonzero, sb)
                self.assertFalse(f_nonzero.poc_verified)
                self.assertIn("**Mechanical Gate Rejected**: `True`", bundle_nz)

                # Case 3: Exit 0 but vacuous 0-test filter across all targets -> REJECTED
                sb.command_history = [
                    CommandRecord(
                        command="cargo test nonexistent_filter",
                        returncode=0,
                        output=(
                            "running 0 tests\n"
                            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out\n"
                        ),
                    )
                ]
                f_vacuous = ExploitFinding(
                    poc="vacuous",
                    test_command="cargo test nonexistent_filter",
                    test_output="",
                    poc_verified=True,
                    justification="Claimed verified on 0-test filter.",
                )
                bundle_vac = _assemble_ground_truth_poc_bundle(f_vacuous, sb)
                self.assertFalse(f_vacuous.poc_verified)
                self.assertIn("**Vacuous Test Filter (`0` Tests Executed)**: `True`", bundle_vac)
            finally:
                sb.cleanup()

    def test_tmp_git_worktree_resolves_inside_bwrap_netns(self) -> None:
        """Verifies git worktrees rooted under /tmp resolve `.git/worktrees/scratch` inside bwrap --tmpfs /tmp."""
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="mjolnir-test-tmpwt-") as td:
            src_dir = Path(td) / "workspace"
            out_dir = Path(td) / "output"
            src_dir.mkdir(parents=True)
            out_dir.mkdir(parents=True)
            (src_dir / "lib.rs").write_text("pub fn v() -> u8 { 1 }\n", encoding="utf-8")
            for git_cmd in (
                ["init"],
                ["config", "user.email", "test@local"],
                ["config", "user.name", "Test"],
                ["add", "-A"],
                ["commit", "-m", "init"],
            ):
                subprocess.run(
                    ["git", "-C", str(src_dir), *git_cmd],
                    capture_output=True,
                    check=True,
                )

            sb = WorktreeSandbox(src_dir, out_dir, "vuln-tmp-git")
            sb.setup()
            try:
                if sb._probe_bwrap_netns():
                    env = sb._build_env()
                    wrapped = sb._wrap_bwrap_command(["git", "rev-parse", "HEAD"], env)
                    res = subprocess.run(
                        wrapped,
                        cwd=str(sb.worktree_dir),
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(res.returncode, 0, msg=res.stderr)
                    self.assertEqual(len(res.stdout.strip()), 40)
            finally:
                sb.cleanup()

    def test_timeout_default_12h_and_partial_trial_salvage(self) -> None:
        """Verifies 12-hour default trial timeout and failed_trials salvage on TimeoutExpired."""
        from evaluation.runner import EvaluationRunner
        from evaluation.sandbox.bwrap_runner import DEFAULT_TRIAL_TIMEOUT_SECONDS
        from unittest.mock import patch

        self.assertEqual(DEFAULT_TRIAL_TIMEOUT_SECONDS, 43200)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src_repo = root / "src_repo"
            src_repo.mkdir()
            (src_repo / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

            runner = EvaluationRunner(
                spec={
                    "project": {
                        "name": "TestProj",
                        "repoName": "test-proj",
                        "repoUrl": "https://github.com/chipsalliance/caliptra-sw.git",
                        "pinnedRev": "HEAD",
                        "targetDir": ".",
                    }
                },
                output_root=root / "eval_out",
                cache_root=root / "eval_cache",
                mjolnir_bin="/bin/false",
            )
            eval_out_dir = root / "eval_out" / "test-proj" / "pinned"
            eval_out_dir.mkdir(parents=True)

            def fake_mjolnir_timeout(snapshot_dir, trial_out_dir, **_kwargs):
                run_dir = trial_out_dir / "run_20261027_000000"
                poc_dir = run_dir / "poc_artifacts" / "vuln-1"
                poc_dir.mkdir(parents=True)
                (run_dir / "finding_phase_initial_review.json").write_text(
                    '[{"id": "vuln-1", "status": "Open"}]', encoding="utf-8"
                )
                (poc_dir / "poc_patch.diff").write_text("diff\n", encoding="utf-8")
                raise subprocess.TimeoutExpired(cmd=["mjolnir-run"], timeout=10)

            with (
                patch.object(
                    runner.snapshot_builder,
                    "materialize_orphan_snapshot",
                    side_effect=lambda baseline_dir, dest_dir, **_kw: shutil.copytree(
                        baseline_dir, dest_dir
                    ),
                ),
                patch.object(runner, "_run_mjolnir_tier", side_effect=fake_mjolnir_timeout),
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    runner._execute_single_trial(
                        baseline_dir=src_repo,
                        tier_key="full",
                        tier_cfg={
                            "name": "Full",
                            "runner": "mjolnir",
                            "mode": "full",
                            "phases": [],
                        },
                        repetition=1,
                        isolated_runner=None,
                        eval_out_dir=eval_out_dir,
                    )

            salvaged = list((eval_out_dir / "failed_trials" / "full").glob("rep_1_*"))
            self.assertEqual(len(salvaged), 1)
            self.assertTrue(
                (
                    salvaged[0] / "run_20261027_000000" / "finding_phase_initial_review.json"
                ).is_file()
            )
            self.assertTrue(
                (
                    salvaged[0]
                    / "run_20261027_000000"
                    / "poc_artifacts"
                    / "vuln-1"
                    / "poc_patch.diff"
                ).is_file()
            )


if __name__ == "__main__":
    unittest.main()
