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
    curlOptsList = [ "--ipv4" ];
  };
  prodProject = import "${src}/tools/mjolnir/project.nix";
in
{
  inherit (prodProject) name repoName repoUrl;
  inherit pinnedRev src;
  targetDir = ".";
  threatModel = "${src}/tools/mjolnir/threat_model.md";

  evaluatorModel = "gemini-3.8-flash";
  minPocSeverity = "Informational";
  batchSize = prodProject.defaultBatchSize or 64;
  extensions = [ "rs" ];
  excludeDirs = [
    "tests"
    "test"
    "benches"
    "fuzz"
    "testdata"
    "xtask"
    "tools"
    "simulator"
    "test-artifacts"
  ];
  excludePatterns = [ "*_test.rs" "test_*.rs" "tests.rs" ];
  testPathTokens = [ "tests" "test" "benches" "fuzz" ];

  scopes = [
    {
      name = "default";
      srcDirs = [ "." ];
    }
    {
      name = "smoke";
      srcDirs = [ "dpe/src/commands/rotate_context.rs" ];
    }
  ];
}
