# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs }:
let
  pinnedRev = "262470b019905e8ea307be63860730d64c35d436";
  src = pkgs.fetchFromGitHub {
    owner = "chipsalliance";
    repo = "caliptra-sw";
    rev = pinnedRev;
    hash = "sha256-2bXzlbPTvQsN0qE+xXHGHd+uxHlY0PMU9VcJu8lgW1E=";
  };
in
{
  name = "Caliptra SW";
  repoName = "caliptra-sw";
  repoUrl = "https://github.com/chipsalliance/caliptra-sw.git";
  inherit pinnedRev src;
  targetDir = "rom/dev/src";
  threatModel = ./threat_model.md;

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "rs" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test -p caliptra-rom --lib";
  lintCmd = "cargo clippy -p caliptra-rom --lib -- -D warnings";

  cliTemplates = {
    gemini = "gemini -p {prompt} --yolo";
    antigravity = "agentapi new-conversation {prompt}";
    claude = "claude -p {prompt} --dangerously-skip-permissions";
    codex = "codex exec --full-auto {prompt}";
  };
}
