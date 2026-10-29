# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Isolated scratch worktree sandbox for Proof-of-Concept synthesis and verification.

Security Architecture Note:
- Executes child build/test commands via explicit argument lists (`subprocess.run(..., shell=False)`
  wrapping `bwrap --ro-bind / / --tmpfs /tmp --unshare-net --die-with-parent -- bash -c ...` on Linux)
  with host cloud/SSH credential directories masked by `--tmpfs` and outbound network disabled.
- Canonicalizes and boundary-checks all worktree file writes (`Path.resolve().is_relative_to(...)`)
  and validates harness command tokens against path escapes and disallowed binaries.
- TODO(security): Web-specific controls (HTTP cookies, sessions, OAuth/MFA, CSRF, CSP, SQL
  parameterization, and multipart file-upload scanning) are intentionally omitted because this
  module is a purely local offline CLI sandbox utility with no HTTP, session, or DB surface.
"""

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from constants import (
    BUILD_CONFIGURATION_FILES,
    CARGO_TARGET_CACHE_SUBDIR,
    HARNESS_COMMAND_TIMEOUT_SECONDS,
    POC_ARTIFACTS_SUBDIR,
    POC_WORKTREES_SUBDIR,
    SANDBOX_ALLOWED_ENV_VARS,
    SANDBOX_GIT_DIFF_EXCLUDES,
    TEST_PATH_TOKENS,
)
from utilities.command import run_command_capture
from utilities.logger import logger

# Splits path segments and filename stems into individual word tokens across
# non-alphanumeric delimiters ('_', '-', '.'), CamelCase, and acronym boundaries:
#   - [A-Z]?[a-z]+       : lowercase or TitleCase words (e.g. "test", "Foo", "Test")
#   - [A-Z]+(?=[A-Z]|$)  : uppercase acronyms before another Capitalized word or end (e.g. "HTTP" in "HTTPTest")
#   - [0-9]+             : numeric runs (e.g. "10" in "ast10x0")
PATH_WORD_TOKEN_RE = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|[0-9]+")

_LIBTEST_SUMMARY_RE = re.compile(r"test result:\s*\w+\.\s*(\d+)\s+passed;\s*(\d+)\s+failed;")
_NEXTEST_SUMMARY_RE = re.compile(r"Summary\s*\[[^\]]*\]\s*(\d+)\s+tests?\s+run:")
_GTEST_PASSED_RE = re.compile(r"\[\s*PASSED\s*\]\s*(\d+)\s+tests?")
_GTEST_ZERO_RUN_RE = re.compile(r"\[\==========\]\s*Running\s+0\s+tests?\s+from\s+0\s+test")
_BAZEL_ZERO_TESTS_RE = re.compile(r"Executed\s+0\s+out\s+of\s+0\s+tests|\bNO STATUS\b")

_LOCKFILE_NAMES = frozenset({"cargo.lock", "module.bazel.lock"})
_BAZEL_BUILD_NAMES = frozenset({"build", "build.bazel"})
_ALLOWED_BAZEL_CALL_RE = re.compile(
    r"^(?:load|[A-Za-z0-9_]*(?:_test|_tests|_unittest|_unittests|_sim|_tb|_fuzz)|test_suite)\s*\(",
    re.DOTALL,
)
_TOML_HEADER_RE = re.compile(r"^\s*(\[\[?[^\[\]]+\]?\]?)\s*(?:#.*)?$")
_SAFE_CARGO_SECTION_RE = re.compile(
    r"^(?:\[dev-dependencies\]|\[target\.[^\]]+\.dev-dependencies\]|\[\[test\]\]|\[\[bench\]\])$",
    re.IGNORECASE,
)


def _tokenize_rust(src: str) -> list[str] | None:
    """Lexically tokenizes Rust source, stripping comments and whitespace while failing closed on unclosed literals."""
    tokens: list[str] = []
    n = len(src)
    i = 0

    while i < n:
        ch = src[i]
        if ch in " \t\r\n":
            i += 1
            continue

        # Line comment
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            nl = src.find("\n", i + 2)
            i = n if nl == -1 else nl + 1
            continue

        # Nested block comment /* ... */
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth != 0:
                return None
            continue

        # Raw string literal: r"...", r#"..."#, br#"..."#, cr#"..."#
        prefix_len = 0
        if ch == "r":
            prefix_len = 1
        elif ch in ("b", "c") and i + 1 < n and src[i + 1] == "r":
            prefix_len = 2
        if prefix_len > 0:
            k = i + prefix_len
            hashes = 0
            while k < n and src[k] == "#":
                hashes += 1
                k += 1
            if k < n and src[k] == '"':
                closing = '"' + ("#" * hashes)
                end_pos = src.find(closing, k + 1)
                if end_pos == -1:
                    return None
                end_idx = end_pos + len(closing)
                tokens.append(src[i:end_idx])
                i = end_idx
                continue

        # Byte / C string or byte-char prefix
        if ch in ("b", "c") and i + 1 < n and src[i + 1] in ('"', "'"):
            quote = src[i + 1]
            if quote == '"':
                k = i + 2
                while k < n:
                    if src[k] == "\\":
                        k += 2
                        continue
                    if src[k] == '"':
                        tokens.append(src[i : k + 1])
                        i = k + 1
                        break
                    k += 1
                else:
                    return None
                continue
            if ch == "b" and quote == "'":
                k = i + 2
                if k < n and src[k] == "\\":
                    end_q = src.find("'", k + 2)
                else:
                    end_q = k + 1 if k + 1 < n and src[k + 1] == "'" else -1
                if end_q == -1:
                    return None
                tokens.append(src[i : end_q + 1])
                i = end_q + 1
                continue

        # Standard string literal "..."
        if ch == '"':
            k = i + 1
            while k < n:
                if src[k] == "\\":
                    k += 2
                    continue
                if src[k] == '"':
                    tokens.append(src[i : k + 1])
                    i = k + 1
                    break
                k += 1
            else:
                return None
            continue

        # Char literal ('x', '\n', '\u{...}') vs Rust lifetime ('a, 'static, '_)
        if ch == "'":
            if i + 1 < n and src[i + 1] == "\\":
                end_q = src.find("'", i + 3)
                if end_q == -1:
                    return None
                tokens.append(src[i : end_q + 1])
                i = end_q + 1
                continue
            if i + 2 < n and src[i + 2] == "'" and src[i + 1] not in ("'", "\n", "\r"):
                tokens.append(src[i : i + 3])
                i += 3
                continue
            if i + 1 < n and (src[i + 1].isalpha() or src[i + 1] == "_"):
                k = i + 2
                while k < n and (src[k].isalnum() or src[k] == "_"):
                    k += 1
                tokens.append(src[i:k])
                i = k
                continue
            tokens.append("'")
            i += 1
            continue

        # Two-character path separator '::' (needed for #[tokio::test] and use foo::{...};)
        if ch == ":" and i + 1 < n and src[i + 1] == ":":
            tokens.append("::")
            i += 2
            continue

        # Identifiers & numbers
        if ch.isalnum() or ch == "_":
            k = i + 1
            while k < n and (src[k].isalnum() or src[k] == "_"):
                k += 1
            tokens.append(src[i:k])
            i = k
            continue

        tokens.append(ch)
        i += 1

    return tokens


def _is_rust_test_attribute(attr_inner: list[str]) -> bool:
    """Returns True if an outer Rust attribute #[...] gates test-only compilation or a test function."""
    if attr_inner == ["cfg", "(", "test", ")"]:
        return True
    paren_idx = attr_inner.index("(") if "(" in attr_inner else len(attr_inner)
    path = attr_inner[:paren_idx]
    if path == ["test"]:
        return True
    if len(path) >= 3 and path[-2:] == ["::", "test"]:
        return True
    return False


def _consume_rust_attributed_item_end(tokens: list[str], start: int) -> int | None:
    """Finds the token index immediately after the Rust item starting at `start`."""
    n = len(tokens)
    if start >= n:
        return None

    # Identify the primary item keyword to distinguish `;`-terminated items (use/const/static/type)
    # from brace-or-semicolon items (mod/fn/struct/enum/union/trait/impl/extern/macro_rules).
    probe = start
    item_kw = ""
    while probe < n:
        tok = tokens[probe]
        if tok == "pub":
            probe += 1
            if probe < n and tokens[probe] == "(":
                depth = 1
                probe += 1
                while probe < n and depth > 0:
                    if tokens[probe] == "(":
                        depth += 1
                    elif tokens[probe] == ")":
                        depth -= 1
                    probe += 1
            continue
        if tok in ("async", "unsafe", "default"):
            probe += 1
            continue
        if tok == "extern":
            if probe + 1 < n and tokens[probe + 1].startswith('"'):
                if probe + 2 < n and tokens[probe + 2] == "fn":
                    item_kw = "fn"
                    break
            item_kw = "extern"
            break
        if tok == "const":
            if probe + 1 < n and tokens[probe + 1] in ("fn", "unsafe"):
                probe += 1
                continue
            item_kw = "const"
            break
        item_kw = tok
        break

    semicolon_only = item_kw in {"use", "const", "static", "type"}
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0
    saw_item_brace = False

    j = start
    while j < n:
        tok = tokens[j]
        if tok == "{":
            if brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
                prev_tok = tokens[j - 1] if j > start else ""
                if prev_tok != "::":
                    saw_item_brace = True
            brace_depth += 1
        elif tok == "}":
            brace_depth -= 1
            if brace_depth < 0:
                return None
            if (
                brace_depth == 0
                and paren_depth == 0
                and bracket_depth == 0
                and saw_item_brace
                and not semicolon_only
            ):
                return j + 1
        elif tok == "(":
            paren_depth += 1
        elif tok == ")":
            paren_depth -= 1
            if paren_depth < 0:
                return None
        elif tok == "[":
            bracket_depth += 1
        elif tok == "]":
            bracket_depth -= 1
            if bracket_depth < 0:
                return None
        elif tok == ";" and brace_depth == 0 and paren_depth == 0 and bracket_depth == 0:
            return j + 1
        j += 1

    return None


def _strip_rust_test_tokens(tokens: list[str]) -> list[str] | None:
    """Strips #[cfg(test)] and #[test] attributed items recursively while preserving all production tokens."""
    out: list[str] = []
    n = len(tokens)
    i = 0

    while i < n:
        # Check for contiguous outer attribute group: #[ ... ] #[ ... ]
        if tokens[i] == "#" and i + 1 < n and tokens[i + 1] == "[":
            attr_start = i
            j = i
            has_test_attr = False
            while j < n and tokens[j] == "#" and j + 1 < n and tokens[j + 1] == "[":
                depth = 1
                k = j + 2
                while k < n and depth > 0:
                    if tokens[k] == "[":
                        depth += 1
                    elif tokens[k] == "]":
                        depth -= 1
                    k += 1
                if depth != 0:
                    return None
                inner = tokens[j + 2 : k - 1]
                if _is_rust_test_attribute(inner):
                    has_test_attr = True
                j = k

            if has_test_attr:
                item_end = _consume_rust_attributed_item_end(tokens, j)
                if item_end is None:
                    return None
                i = item_end
                continue

            out.extend(tokens[attr_start:j])
            i = j
            continue

        # Recurse into inline `mod <name> { ... }` bodies so adding #[test] inside an existing module works
        if (
            tokens[i] == "mod"
            and i + 2 < n
            and (tokens[i + 1].isalnum() or "_" in tokens[i + 1])
            and tokens[i + 2] == "{"
        ):
            depth = 1
            k = i + 3
            while k < n and depth > 0:
                if tokens[k] == "{":
                    depth += 1
                elif tokens[k] == "}":
                    depth -= 1
                k += 1
            if depth != 0:
                return None
            stripped_inner = _strip_rust_test_tokens(tokens[i + 3 : k - 1])
            if stripped_inner is None:
                return None
            out.extend([tokens[i], tokens[i + 1], "{"])
            out.extend(stripped_inner)
            out.append("}")
            i = k
            continue

        out.append(tokens[i])
        i += 1

    # Verify balanced delimiters across non-test tokens
    b_d = p_d = k_d = 0
    for tok in out:
        if tok == "{":
            b_d += 1
        elif tok == "}":
            b_d -= 1
        elif tok == "(":
            p_d += 1
        elif tok == ")":
            p_d -= 1
        elif tok == "[":
            k_d += 1
        elif tok == "]":
            k_d -= 1
        if b_d < 0 or p_d < 0 or k_d < 0:
            return None
    if b_d != 0 or p_d != 0 or k_d != 0:
        return None
    return out


def rust_non_test_code_unchanged(baseline_src: str, modified_src: str) -> bool:
    """Returns True iff `modified_src` and `baseline_src` have identical Rust tokens outside #[cfg(test)] / #[test] items."""
    base_tokens = _tokenize_rust(baseline_src)
    mod_tokens = _tokenize_rust(modified_src)
    if base_tokens is None or mod_tokens is None:
        return False
    # Ensure modified_src actually added at least one test-attributed item if tokens changed
    if base_tokens == mod_tokens:
        return False
    stripped_base = _strip_rust_test_tokens(base_tokens)
    stripped_mod = _strip_rust_test_tokens(mod_tokens)
    if stripped_base is None or stripped_mod is None:
        return False
    return stripped_base == stripped_mod


def _strip_safe_cargo_toml_sections(toml_text: str) -> list[str]:
    """Returns normalized non-empty, non-comment lines outside [dev-dependencies], [[test]], and [[bench]]."""
    kept: list[str] = []
    in_safe_section = False
    for raw_line in toml_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _TOML_HEADER_RE.match(stripped)
        if m:
            header = m.group(1).strip()
            in_safe_section = bool(_SAFE_CARGO_SECTION_RE.match(header))
            if not in_safe_section:
                kept.append(stripped)
            continue
        if not in_safe_section:
            kept.append(stripped)
    return kept


def _split_top_level_starlark_statements(src: str) -> list[str] | None:
    """Splits a BUILD / BUILD.bazel file into normalized top-level statements, failing closed on unbalanced parens."""
    stmts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_quote: str | None = None
    triple = False
    n = len(src)
    i = 0

    while i < n:
        ch = src[i]
        if in_quote is not None:
            cur.append(ch)
            if ch == "\\":
                if i + 1 < n:
                    cur.append(src[i + 1])
                    i += 2
                    continue
            if triple:
                if src[i : i + 3] == in_quote * 3:
                    cur.extend([in_quote, in_quote])
                    i += 3
                    in_quote = None
                    triple = False
                    continue
            elif ch == in_quote:
                in_quote = None
            i += 1
            continue

        if ch == "#":
            nl = src.find("\n", i + 1)
            i = n if nl == -1 else nl
            continue

        if ch in ('"', "'"):
            if src[i : i + 3] == ch * 3:
                in_quote = ch
                triple = True
                cur.extend([ch, ch, ch])
                i += 3
                continue
            in_quote = ch
            triple = False
            cur.append(ch)
            i += 1
            continue

        if ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return None
            cur.append(ch)
        elif ch == "\n" and depth == 0:
            stmt = "".join(cur).strip()
            if stmt:
                stmts.append(stmt)
            cur = []
        else:
            cur.append(ch)
        i += 1

    if depth != 0 or in_quote is not None:
        return None
    tail = "".join(cur).strip()
    if tail:
        stmts.append(tail)
    return stmts


def _bazel_build_only_adds_test_targets(baseline_src: str, modified_src: str) -> bool:
    """Returns True iff every baseline top-level statement is preserved verbatim and new ones are load() or *_test()."""
    base_stmts = _split_top_level_starlark_statements(baseline_src)
    mod_stmts = _split_top_level_starlark_statements(modified_src)
    if base_stmts is None or mod_stmts is None or len(mod_stmts) < len(base_stmts):
        return False

    # Verify baseline statements appear in order unchanged as a subsequence of mod_stmts
    b_idx = 0
    added_stmts: list[str] = []
    for stmt in mod_stmts:
        if b_idx < len(base_stmts) and stmt == base_stmts[b_idx]:
            b_idx += 1
        else:
            added_stmts.append(stmt)
    if b_idx != len(base_stmts) or not added_stmts:
        return False

    return all(bool(_ALLOWED_BAZEL_CALL_RE.match(s)) for s in added_stmts)


@dataclass
class CommandRecord:
    """Ground-truth record of a command executed inside the sandbox."""

    command: str
    returncode: int
    output: str


current_worktree_sandbox: ContextVar["WorktreeSandbox | None"] = ContextVar(
    "current_worktree_sandbox", default=None
)

REPRODUCE_SCRIPT_TEMPLATE = """#!/usr/bin/env bash
# Standalone Mjolnir PoC Reproducer for {vuln_id}
set -e
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
if [[ "$1" == "--revert" ]]; then
  cd "${{2:-.}}"
  [[ -f "$SCRIPT_DIR/poc_patch.diff" ]] && patch -R -p1 < "$SCRIPT_DIR/poc_patch.diff" || true
  exit 0
fi
TARGET_DIR="${{1:-.}}"
cd "$TARGET_DIR"

[[ -f "$SCRIPT_DIR/poc_patch.diff" ]] && patch -p1 --forward < "$SCRIPT_DIR/poc_patch.diff"
echo "[Mjolnir PoC] Executing: {last_cmd}"
set +e
{last_cmd}
CMD_EXIT_CODE=$?
set -e
echo "=================================================================="
if [[ $CMD_EXIT_CODE -ne 0 ]]; then
  echo "[Mjolnir PoC] COMMAND FAILED (exit code $CMD_EXIT_CODE)"
else
  echo "[Mjolnir PoC] COMMAND RETURNED 0"
fi
echo "=================================================================="
exit $CMD_EXIT_CODE
"""


class WorktreeSandbox:
    """Manages an isolated scratch worktree for PoC synthesis and verification."""

    _bwrap_netns_supported: bool | None = None
    _bwrap_bin_cached: str | None = None

    def __init__(
        self,
        source_code_dir: Path,
        workspace_dir: Path,
        vuln_id: str,
        keep_worktree: bool = False,
        extra_test_path_tokens: list[str] | set[str] | None = None,
        isolate_network: bool = True,
    ) -> None:
        self.source_code_dir = source_code_dir.resolve()
        self.workspace_dir = workspace_dir.resolve()
        self.vuln_id = vuln_id
        self.keep_worktree = keep_worktree
        self.isolate_network = isolate_network
        self.test_path_tokens = TEST_PATH_TOKENS | {
            tok.lower()
            for raw in (extra_test_path_tokens or ())
            for tok in PATH_WORD_TOKEN_RE.findall(str(raw))
        }
        self.worktree_dir = self.workspace_dir / POC_WORKTREES_SUBDIR / "scratch"
        self.artifact_dir = self.workspace_dir / POC_ARTIFACTS_SUBDIR / vuln_id
        self.command_history: list[CommandRecord] = []
        self._ctx_token = None

    async def __aenter__(self) -> "WorktreeSandbox":
        await asyncio.to_thread(self.setup)
        self._ctx_token = current_worktree_sandbox.set(self)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._ctx_token is not None:
            current_worktree_sandbox.reset(self._ctx_token)
            self._ctx_token = None
        await asyncio.to_thread(self.cleanup)

    def _run_git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(self.worktree_dir), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def _read_baseline_file(self, rel_path: str) -> str | None:
        """Reads the committed HEAD baseline contents of `rel_path`, or None if newly added."""
        res = self._run_git("show", f"HEAD:{rel_path}")
        if res.returncode != 0:
            return None
        return res.stdout

    def _init_local_git_repo(self) -> None:
        """Copies source tree and initializes a lightweight local git repo for non-git directories."""
        shutil.copytree(self.source_code_dir, self.worktree_dir, symlinks=True, dirs_exist_ok=True)
        for cmd in (
            ["init"],
            ["config", "user.email", "mjolnir@local"],
            ["config", "user.name", "Mjolnir"],
            ["add", "-A"],
            ["commit", "-m", "baseline"],
        ):
            self._run_git(*cmd)

    def setup(self) -> None:
        """Initializes the single scratch worktree and resets it to clean baseline."""
        self.worktree_dir.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.command_history.clear()

        if not self.worktree_dir.exists():
            if (self.source_code_dir / ".git").exists():
                res = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(self.source_code_dir),
                        "worktree",
                        "add",
                        "--detach",
                        "-f",
                        str(self.worktree_dir),
                        "HEAD",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode != 0:
                    self._init_local_git_repo()
            else:
                self._init_local_git_repo()

            # Link tags index if present
            src_tags = self.source_code_dir / ".git" / "tags"
            if not src_tags.exists():
                src_tags = self.source_code_dir / ".mjolnir_tags"
            dst_tags = self.worktree_dir / ".mjolnir_tags"
            if src_tags.exists() and not dst_tags.exists():
                try:
                    dst_tags.symlink_to(src_tags)
                except OSError:
                    pass

            # Exclude build caches, tags, and artifact directories from git tracking
            try:
                exclude_path = None
                git_entry = self.worktree_dir / ".git"
                if git_entry.is_dir():
                    exclude_path = git_entry / "info" / "exclude"
                elif git_entry.is_file():
                    content = git_entry.read_text(encoding="utf-8").strip()
                    if content.startswith("gitdir:"):
                        gd = Path(content.split(":", 1)[1].strip())
                        exclude_path = gd / "info" / "exclude"
                if exclude_path:
                    exclude_path.parent.mkdir(parents=True, exist_ok=True)
                    existing = (
                        exclude_path.read_text(encoding="utf-8") if exclude_path.exists() else ""
                    )
                    patterns = [
                        ".mjolnir_tags*",
                        "tags*",
                        "MODULE.bazel.lock",
                        "target/",
                        CARGO_TARGET_CACHE_SUBDIR + "/",
                        POC_WORKTREES_SUBDIR + "/",
                        POC_ARTIFACTS_SUBDIR + "/",
                    ]
                    to_add = [p for p in patterns if p not in existing]
                    if to_add:
                        with open(exclude_path, "a", encoding="utf-8") as f:
                            f.write("\n" + "\n".join(to_add) + "\n")
            except Exception:
                pass
        else:
            self._sync_to_source_head()
            self.reset()

        self._apply_sandbox_shell_hook()
        self._prewarm_cargo_dependencies()

    def _prewarm_cargo_dependencies(self) -> None:
        """Fetches Cargo crate dependencies once on the clean baseline before network-isolated PoC runs."""
        if not self.isolate_network or not (self.worktree_dir / "Cargo.toml").exists():
            return
        marker = self.workspace_dir / ".mjolnir_cargo_fetched"
        if marker.exists() or not shutil.which("cargo"):
            return
        env = self._build_env()
        res = subprocess.run(
            ["cargo", "fetch", "--locked"],
            cwd=str(self.worktree_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if res.returncode != 0:
            subprocess.run(
                ["cargo", "fetch"],
                cwd=str(self.worktree_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        try:
            marker.write_text("ok\n", encoding="utf-8")
        except OSError:
            pass

    def _sync_to_source_head(self) -> None:
        """Ensures an existing worktree is aligned with source_code_dir's current HEAD."""
        if not (self.source_code_dir / ".git").exists():
            return
        src_res = subprocess.run(
            ["git", "-C", str(self.source_code_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        if src_res.returncode != 0 or not src_res.stdout.strip():
            return
        src_head = src_res.stdout.strip()
        wt_head = self._run_git("rev-parse", "HEAD").stdout.strip()
        wt_parent = self._run_git("rev-parse", "HEAD~1").stdout.strip()
        wt_subject = self._run_git("log", "-1", "--pretty=%s").stdout.strip()
        if wt_head == src_head or (
            wt_subject == "mjolnir-sandbox-env-baseline" and wt_parent == src_head
        ):
            return
        self._run_git("checkout", "--detach", "--force", src_head)

    def _apply_sandbox_shell_hook(self) -> None:
        """Executes MJOLNIR_SHELL_HOOK inside the sandbox worktree and commits any build patches to baseline."""
        hook = os.environ.get("MJOLNIR_SHELL_HOOK", "").strip()
        if not hook or not self.worktree_dir.exists():
            return
        cmd = ["bash", hook] if Path(hook).is_file() else ["bash", "-c", hook]
        subprocess.run(
            cmd,
            cwd=str(self.worktree_dir),
            env=self._build_env(),
            capture_output=True,
            text=True,
            check=False,
        )
        if self.get_modified_files():
            self._run_git("config", "user.email", "mjolnir@local")
            self._run_git("config", "user.name", "Mjolnir")
            self._run_git("add", "-A")
            self._run_git("commit", "-m", "mjolnir-sandbox-env-baseline")

    def cleanup(self) -> None:
        """Persists unified diff, command execution logs, and reproduce.sh, then resets worktree."""
        try:
            diff_text = self.get_diff()
            if diff_text.strip():
                (self.artifact_dir / "poc_patch.diff").write_text(diff_text, encoding="utf-8")
            if self.command_history:
                log_lines = [
                    f"=== Command #{i}: {r.command} (exit={r.returncode}) ===\n{r.output}\n"
                    for i, r in enumerate(self.command_history, start=1)
                ]
                (self.artifact_dir / "harness_commands.log").write_text(
                    "\n".join(log_lines), encoding="utf-8"
                )
            if diff_text.strip() or self.command_history:
                last_cmd = (
                    self.command_history[-1].command
                    if self.command_history
                    else "echo 'No command recorded'"
                )
                reproduce_script = REPRODUCE_SCRIPT_TEMPLATE.format(
                    vuln_id=self.vuln_id, last_cmd=last_cmd
                )
                reproduce_path = self.artifact_dir / "reproduce.sh"
                reproduce_path.write_text(reproduce_script, encoding="utf-8")
                reproduce_path.chmod(0o755)
        except Exception as err:
            logger.debug(f"Failed to persist PoC artifacts for {self.vuln_id}: {err}")
        finally:
            self.reset()

    def write_file(self, rel_path: str, content: str) -> None:
        """Writes content to a file inside the worktree after verifying workspace path boundaries."""
        if "\x00" in rel_path:
            raise ValueError("Invalid null byte in worktree file path.")
        wt_root = self.worktree_dir.resolve()
        target_path = (wt_root / rel_path).resolve()
        if target_path == wt_root or not target_path.is_relative_to(wt_root):
            raise ValueError(f"Path '{rel_path}' escapes sandbox worktree '{wt_root}'.")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding="utf-8")

    def get_diff(self) -> str:
        """Computes unified diff across all modified or added files using git."""
        self._run_git("add", "-N", ".")
        res = self._run_git("diff", "HEAD", "--", *SANDBOX_GIT_DIFF_EXCLUDES)
        return res.stdout if res.returncode == 0 else ""

    def get_modified_files(self) -> list[str]:
        """Returns list of relative paths for all modified or newly created files."""
        self._run_git("add", "-N", ".")
        res = self._run_git("diff", "--name-only", "HEAD", "--", *SANDBOX_GIT_DIFF_EXCLUDES)
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    def _has_test_path_token(self, rel_path: str) -> bool:
        p = Path(rel_path)
        tokens = {
            tok.lower()
            for part in (*p.parts[:-1], p.stem)
            for tok in PATH_WORD_TOKEN_RE.findall(part)
        }
        return bool(tokens & self.test_path_tokens)

    def is_test_or_harness_path(self, rel_path: str) -> bool:
        """Checks if a file path belongs directly to a dedicated test/harness directory or lockfile."""
        p = Path(rel_path)
        lower_name = p.name.lower()
        if lower_name.startswith((".mjolnir_tags", "tags")):
            return True
        if lower_name in _LOCKFILE_NAMES:
            return True
        return self._has_test_path_token(rel_path)

    def _is_safe_build_config_modification(self, rel_path: str) -> bool:
        """Verifies that edits to non-test build manifests only add dev-dependencies or test rules."""
        p = Path(rel_path)
        lower_name = p.name.lower()
        if lower_name not in BUILD_CONFIGURATION_FILES:
            return False
        if lower_name in _LOCKFILE_NAMES or self._has_test_path_token(rel_path):
            return True

        diff = self._run_git("diff", "HEAD", "--", rel_path).stdout
        if any(line.startswith("-") and not line.startswith("---") for line in diff.splitlines()):
            return False

        mod_file = self.worktree_dir / rel_path
        if not mod_file.is_file():
            return False
        baseline_src = self._read_baseline_file(rel_path)
        if baseline_src is None:
            return False
        modified_src = mod_file.read_text(encoding="utf-8", errors="replace")

        if lower_name == "cargo.toml":
            return _strip_safe_cargo_toml_sections(baseline_src) == _strip_safe_cargo_toml_sections(
                modified_src
            )

        if lower_name in _BAZEL_BUILD_NAMES:
            return _bazel_build_only_adds_test_targets(baseline_src, modified_src)

        return False

    def has_production_code_modifications(self) -> bool:
        """Returns True if any non-test production source or build target was modified or added."""
        for rel in self.get_modified_files():
            if self.is_test_or_harness_path(rel):
                continue

            lower_name = Path(rel).name.lower()
            if lower_name in BUILD_CONFIGURATION_FILES:
                if self._is_safe_build_config_modification(rel):
                    continue
                return True

            # Reject if any existing baseline lines were deleted or altered
            diff = self._run_git("diff", "HEAD", "--", rel).stdout
            if any(
                line.startswith("-") and not line.startswith("---") for line in diff.splitlines()
            ):
                return True

            # For Rust files with inline #[cfg(test)] / #[test] additions, verify lexical
            # token-level invariance of all code outside test-attributed items.
            if lower_name.endswith(".rs"):
                baseline_src = self._read_baseline_file(rel)
                mod_path = self.worktree_dir / rel
                if baseline_src is not None and mod_path.is_file():
                    modified_src = mod_path.read_text(encoding="utf-8", errors="replace")
                    if rust_non_test_code_unchanged(baseline_src, modified_src):
                        continue

            return True
        return False

    def count_removed_baseline_lines(self) -> int:
        """Counts existing baseline lines deleted or modified in non-test production/build files."""
        prod_files = [f for f in self.get_modified_files() if not self.is_test_or_harness_path(f)]
        if not prod_files:
            return 0
        res = self._run_git("diff", "HEAD", "--", *prod_files)
        return sum(
            1
            for line in res.stdout.splitlines()
            if line.startswith("-") and not line.startswith("---")
        )

    @staticmethod
    def is_vacuous_test_output(output: str) -> bool:
        """Returns True when a test runner succeeded while executing 0 test cases (vacuous filter)."""
        text = output or ""
        if not text.strip():
            return False

        libtest_matches = _LIBTEST_SUMMARY_RE.findall(text)
        if libtest_matches:
            total_ran = sum(int(passed) + int(failed) for passed, failed in libtest_matches)
            if total_ran == 0:
                return True

        nextest_matches = _NEXTEST_SUMMARY_RE.findall(text)
        if nextest_matches and sum(int(n) for n in nextest_matches) == 0:
            return True

        if _GTEST_ZERO_RUN_RE.search(text):
            gtest_passed = [int(n) for n in _GTEST_PASSED_RE.findall(text)]
            if sum(gtest_passed) == 0:
                return True

        lower = text.lower()
        if "collected 0 items" in lower or "no tests ran in " in lower:
            return True
        if "no tests were found!!!" in lower:
            return True
        if _BAZEL_ZERO_TESTS_RE.search(text):
            return True

        return False

    def reset(self) -> str:
        """Restores worktree back to clean HEAD, preserving build target caches."""
        self._run_git("checkout", "--force", "HEAD")
        self._run_git(
            "clean", "-fd", "-e", "target", "-e", CARGO_TARGET_CACHE_SUBDIR, "-e", ".mjolnir_tags"
        )
        return "Sandbox reset to clean baseline."

    def _build_env(self) -> dict[str, str]:
        """Builds sanitized environment whitelisting build toolchains while scrubbing secrets."""
        env = {
            k: v
            for k, v in os.environ.items()
            if k in SANDBOX_ALLOWED_ENV_VARS or k.startswith(("CARGO_", "RUST_"))
        }
        env.setdefault("RUSTUP_AUTO_INSTALL", "0")
        if "CARGO_TARGET_DIR" not in env:
            src_target = self.source_code_dir / "target"
            if src_target.is_dir() and os.access(src_target, os.W_OK):
                env["CARGO_TARGET_DIR"] = str(src_target)
            else:
                cache_target = self.workspace_dir / CARGO_TARGET_CACHE_SUBDIR
                cache_target.mkdir(parents=True, exist_ok=True)
                env["CARGO_TARGET_DIR"] = str(cache_target)
        return env

    @classmethod
    def _probe_bwrap_netns(cls) -> str | None:
        """Probes once whether `bwrap --ro-bind / / --unshare-net` is available on this host."""
        bwrap_bin = shutil.which("bwrap")
        if not bwrap_bin:
            cls._bwrap_netns_supported = False
            cls._bwrap_bin_cached = None
            return None
        if cls._bwrap_netns_supported is not None and cls._bwrap_bin_cached == bwrap_bin:
            return bwrap_bin if cls._bwrap_netns_supported else None
        probe = subprocess.run(
            [bwrap_bin, "--ro-bind", "/", "/", "--unshare-net", "true"],
            capture_output=True,
            check=False,
        )
        cls._bwrap_bin_cached = bwrap_bin
        cls._bwrap_netns_supported = probe.returncode == 0
        if not cls._bwrap_netns_supported:
            logger.warning(
                "bwrap --unshare-net unavailable on this host kernel; running harness command without netns."
            )
            return None
        return bwrap_bin

    def _wrap_bwrap_command(self, cmd: list[str], env: dict[str, str]) -> list[str]:
        """Wraps a harness command inside a read-only root + `--unshare-net` Bubblewrap sandbox."""
        if not self.isolate_network:
            return cmd
        bwrap_bin = self._probe_bwrap_netns()
        if not bwrap_bin:
            return cmd

        wt_resolved = self.worktree_dir.resolve()
        src_resolved = self.source_code_dir.resolve()
        home_dir = Path.home().resolve()

        bwrap_cmd: list[str] = [
            bwrap_bin,
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "TMP",
            "/tmp",
            "--setenv",
            "TEMP",
            "/tmp",
        ]

        # Re-expose baseline source_code_dir read-only when located under /tmp (e.g., evaluation
        # snapshots) so git worktree metadata (.git/worktrees/scratch) and tag symlinks resolve.
        if src_resolved.exists() and src_resolved != wt_resolved:
            bwrap_cmd.extend(["--ro-bind", str(src_resolved), str(src_resolved)])

        # Mask host cloud/SSH/VCS credential directories & files from PoC child processes
        for cred_rel in (".config/gcloud", ".aws", ".ssh", ".gnupg", ".kube"):
            cred_dir = home_dir / cred_rel
            if cred_dir.is_dir() and not wt_resolved.is_relative_to(cred_dir.resolve()):
                bwrap_cmd.extend(["--tmpfs", str(cred_dir.resolve())])
        for cred_file_rel in (".netrc", ".git-credentials"):
            cred_file = home_dir / cred_file_rel
            if cred_file.is_file():
                bwrap_cmd.extend(["--ro-bind", "/dev/null", str(cred_file.resolve())])

        # Mount only the scratch worktree and build/package caches writable
        candidate_writable: list[Path] = [
            wt_resolved,
            Path(env["CARGO_TARGET_DIR"]).resolve(),
            Path(env.get("CARGO_HOME") or (home_dir / ".cargo")),
            home_dir / ".cache" / "bazel",
            home_dir / ".cache" / "bazelisk",
        ]
        for env_key in ("BAZELISK_HOME", "SHARED_DISK_CACHE", "SHARED_REPO_CACHE"):
            if env.get(env_key):
                candidate_writable.append(Path(env[env_key]))

        seen_mounts: set[Path] = set()
        writable_mounts: list[Path] = []
        for raw_p in candidate_writable:
            if not raw_p.exists():
                continue
            rp = raw_p.resolve()
            if rp not in seen_mounts:
                seen_mounts.add(rp)
                writable_mounts.append(rp)

        for mp in sorted(writable_mounts, key=lambda p: len(p.parts)):
            bwrap_cmd.extend(["--bind", str(mp), str(mp)])

        bwrap_cmd.extend(
            [
                "--chdir",
                str(wt_resolved),
                "--unshare-net",
                "--die-with-parent",
                "--",
                *cmd,
            ]
        )
        return bwrap_cmd

    def validate_harness_command(self, command: str) -> str | None:
        """Validates that a harness command only executes build/test tools within the sandbox workspace.

        Returns an error message if out-of-workspace path traversal or disallowed shell/network
        exploration is detected, or None if the command is permitted.
        """
        stripped = command.strip()
        if not stripped:
            return "Empty harness command."

        disallowed_bins = {
            "find",
            "locate",
            "mlocate",
            "plocate",
            "grep",
            "egrep",
            "fgrep",
            "rg",
            "ag",
            "ack",
            "cat",
            "head",
            "tail",
            "less",
            "more",
            "ls",
            "tree",
            "du",
            "df",
            "curl",
            "wget",
            "nc",
            "ncat",
            "netcat",
            "socat",
            "ssh",
            "scp",
            "sftp",
            "ftp",
            "telnet",
            "ping",
            "dig",
            "nslookup",
        }
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            tokens = stripped.split()

        # 1. Check command verbs at the start of the command and after shell control operators
        expect_cmd = True
        for tok in tokens:
            if tok in (";", "&&", "||", "|", "&"):
                expect_cmd = True
                continue
            if expect_cmd:
                if "=" in tok and not tok.startswith(("/", ".", "-")):
                    continue
                cmd_name = Path(tok).name.lower()
                if cmd_name in disallowed_bins:
                    return (
                        f"Access denied: '{cmd_name}' is not permitted in run_harness_command. "
                        "Use workspace-scoped tools (read_file, grep_files, list_files, query_symbols) "
                        "to inspect source files, and use run_harness_command strictly for offline "
                        "build/test execution (e.g., cargo test, bazel test, verilator, make)."
                    )
                expect_cmd = False

        # 2. Check all tokens for paths escaping the sandbox workspace
        allowed_roots = (
            self.worktree_dir.resolve(),
            self.workspace_dir.resolve(),
            self.source_code_dir.resolve(),
            Path("/nix/store"),
            Path("/dev"),
        )
        for tok in tokens:
            candidate = tok.split("=", 1)[1] if "=" in tok and tok.startswith("-") else tok
            if not candidate or candidate.startswith("//"):
                continue
            if (
                candidate.startswith(("/", "~", "../"))
                or "/../" in candidate
                or candidate == ".."
                or candidate.endswith("/..")
            ):
                expanded = Path(os.path.expanduser(candidate))
                resolved = (
                    expanded.resolve()
                    if expanded.is_absolute()
                    else (self.worktree_dir / expanded).resolve()
                )
                if not any(
                    resolved == root or resolved.is_relative_to(root) for root in allowed_roots
                ):
                    return (
                        f"Access denied: Path '{tok}' resolves outside the isolated repository "
                        f"workspace ({self.worktree_dir}). All harness commands must remain "
                        "strictly within the repository workspace."
                    )
        return None

    async def run_harness_command_async(
        self, command: str, timeout_seconds: int = HARNESS_COMMAND_TIMEOUT_SECONDS
    ) -> CommandRecord:
        """Executes a test harness command inside the isolated sandbox and records its output."""
        violation = self.validate_harness_command(command)
        if violation is not None:
            logger.warning(f"      [PoC Sandbox] Blocked command: {command} ({violation})")
            return CommandRecord(
                command=command,
                returncode=126,
                output=violation,
            )

        effective_timeout = max(5, min(timeout_seconds, HARNESS_COMMAND_TIMEOUT_SECONDS))
        env = self._build_env()
        wrapped_cmd = self._wrap_bwrap_command(["bash", "-c", command], env=env)

        res = await asyncio.to_thread(
            run_command_capture,
            wrapped_cmd,
            cwd=str(self.worktree_dir),
            timeout=effective_timeout,
            env=env,
        )

        combined = res.stdout or ""
        if res.stderr:
            combined = (
                combined + "\n" if combined and not combined.endswith("\n") else combined
            ) + res.stderr

        record = CommandRecord(
            command=command,
            returncode=res.returncode,
            output=combined.strip() or "(no output)",
        )
        self.command_history.append(record)
        return record
