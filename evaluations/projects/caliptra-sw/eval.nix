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
    curlOptsList = [ "--ipv4" ];
  };
  prodProject = import "${src}/tools/mjolnir/project.nix";
in
{
  inherit (prodProject) name repoName repoUrl;
  inherit pinnedRev src;
  targetDir = "runtime/src";
  threatModel = "${src}/tools/mjolnir/threat_model.md";

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  minPocSeverity = "Informational";
  batchSize = prodProject.defaultBatchSize or 64;
  extensions = [ "rs" ];
  sastTiers = [ "semgrep" "clippy" ];
  excludeDirs = [ "tests" "test" "benches" "fuzz" "testdata" ];
  excludePatterns = [ "*_test.rs" "test_*.rs" "tests.rs" ];
  testPathTokens = [ "tests" "test" "benches" "fuzz" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test -p caliptra-runtime --lib -- --test-threads=1";
  lintCmd = "cargo clippy -p caliptra-runtime --lib -- -D warnings";

  scopes = [
    {
      name = "default";
      srcDirs = [ "runtime/src" ];
    }
    {
      name = "rom";
      srcDirs = [ "rom/dev/src" ];
    }
    {
      name = "smoke";
      srcDirs = [ "runtime/src/invoke_dpe.rs" ];
    }
  ];

  cliTemplates = {
    antigravity = "antigravity -p {prompt} --dangerously-skip-permissions";
  };
}
