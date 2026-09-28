# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs }:
let
  pinnedRev = "c5a58fb8ad7b9e6c19164546a5e492975a77c464";
  src = pkgs.fetchFromGitHub {
    owner = "lowrisc";
    repo = "opentitan";
    rev = pinnedRev;
    hash = "sha256-uuno8UPg2jbn/a0ZEszWDjyce4wsla4eD8ft/udWPcQ=";
  };
in
{
  name = "OpenTitan";
  repoName = "opentitan";
  repoUrl = "https://github.com/lowrisc/opentitan.git";
  inherit pinnedRev src;
  targetDir = "sw/device/silicon_creator/rom_ext";
  threatModel = ../../../projects/opentitan/threat_model.md;

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "c" "h" "rs" ];

  buildCmd = null;
  testCmd = null;
  lintCmd = null;

  cliTemplates = {
    gemini = "gemini -p {prompt} --yolo";
    antigravity = "agentapi new-conversation {prompt}";
    claude = "claude -p {prompt} --dangerously-skip-permissions";
    codex = "codex exec --full-auto {prompt}";
  };
}
