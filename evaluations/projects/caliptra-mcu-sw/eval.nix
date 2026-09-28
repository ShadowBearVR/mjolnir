# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs }:
let
  pinnedRev = "21d2654c095048072bd07c9dbb2b3fa9528fa94d";
  src = pkgs.fetchFromGitHub {
    owner = "chipsalliance";
    repo = "caliptra-mcu-sw";
    rev = pinnedRev;
    hash = "sha256-V4JamwXSfgVgch4BXwsVap9uOHhtnBzfcXhsoCyBqB4=";
  };
in
{
  name = "Caliptra MCU SW";
  repoName = "caliptra-mcu-sw";
  repoUrl = "https://github.com/chipsalliance/caliptra-mcu-sw.git";
  inherit pinnedRev src;
  targetDir = "rom/src";
  threatModel = ../caliptra-sw/threat_model.md;

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "rs" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test --workspace --lib";
  lintCmd = "cargo clippy --workspace --lib -- -D warnings";

  cliTemplates = {
    gemini = "gemini -p {prompt} --yolo";
    antigravity = "agentapi new-conversation {prompt}";
    claude = "claude -p {prompt} --dangerously-skip-permissions";
    codex = "codex exec --full-auto {prompt}";
  };
}
