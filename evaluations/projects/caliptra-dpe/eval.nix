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
    "xtask"
    "tools"
    "simulator"
    "test-artifacts"
  ];
  excludePatterns = [ "*_test.rs" "test_*.rs" "tests.rs" ];
  testPathTokens = [ "tests" "test" "benches" "fuzz" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test --workspace --lib -- --test-threads=1";
  lintCmd = "cargo clippy --workspace --lib -- -D warnings";

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

  cliTemplates = {
    antigravity = "${pkgs.antigravity}/bin/antigravity -p {prompt} --dangerously-skip-permissions";
  };
}
