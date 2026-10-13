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
    curlOptsList = [ "--ipv4" ];
  };
  prodProject = import "${src}/tools/mjolnir/project.nix";
in
{
  inherit (prodProject) name repoName repoUrl;
  inherit pinnedRev src;
  targetDir = "rom/src";
  threatModel = "${src}/tools/mjolnir/threat_model.md";

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  minPocSeverity = "Informational";
  batchSize = prodProject.defaultBatchSize or 64;
  extensions = [ "rs" ];
  sastTiers = [ "semgrep" "clippy" ];
  excludeDirs = [
    "tests"
    "test"
    "benches"
    "fuzz"
    "testdata"
    "testing"
    "emulator"
    "registers"
    "platforms"
    "xtask"
    "builder"
    "tools"
    "hw"
    "caliptra-util-host"
  ];
  excludePatterns = [ "*_test.rs" "test_*.rs" "tests.rs" ];
  testPathTokens = [ "tests" "test" "benches" "fuzz" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test -p caliptra-mcu-rom-common -p mcu-mbox-common -p pldm-common -p flash-image -p mctp-vdm-common --lib -- --test-threads=1";
  lintCmd = "cargo clippy -p caliptra-mcu-rom-common -p mcu-mbox-common -p pldm-common -p flash-image -p mctp-vdm-common --lib -- -D warnings";

  scopes = [
    {
      name = "default";
      srcDirs = [
        "rom/src"
        "common/mcu-mbox/src"
        "common/pldm/src"
        "common/flash-image/src"
        "common/mctp-vdm/src"
      ];
    }
    {
      name = "full-repo";
      srcDirs = [ "." ];
    }
    {
      name = "smoke";
      srcDirs = [ "rom/src/lifecycle.rs" ];
    }
  ];

  cliTemplates = {
    antigravity = "${pkgs.antigravity}/bin/antigravity -p {prompt} --dangerously-skip-permissions";
  };
}
