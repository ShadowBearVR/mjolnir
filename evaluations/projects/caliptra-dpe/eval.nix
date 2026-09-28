# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs }:
let
  pinnedRev = "7c210f1217479040c966ecadead837b0432fa83a";
  src = pkgs.fetchFromGitHub {
    owner = "chipsalliance";
    repo = "caliptra-dpe";
    rev = pinnedRev;
    hash = "sha256-jsdkbCYXS3pTk5FMpg9Z3U7GCQv77tD00yT30Dc6pCk=";
  };
in
{
  name = "Caliptra DPE";
  repoName = "caliptra-dpe";
  repoUrl = "https://github.com/chipsalliance/caliptra-dpe.git";
  inherit pinnedRev src;
  targetDir = "dpe/src";
  threatModel = ../caliptra-sw/threat_model.md;

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "rs" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test -p dpe";
  lintCmd = "cargo clippy --workspace -- -D warnings";

  cliTemplates = {
    gemini = "gemini -p {prompt} --yolo";
    antigravity = "agentapi new-conversation {prompt}";
    claude = "claude -p {prompt} --dangerously-skip-permissions";
    codex = "codex exec --full-auto {prompt}";
  };
}
