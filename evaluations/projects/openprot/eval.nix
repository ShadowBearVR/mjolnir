# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs }:
let
  pinnedRev = "34d82b1f2360bcc43986f5a9846e5b85de94ba98";
  src = pkgs.fetchFromGitHub {
    owner = "OpenPRoT";
    repo = "openprot";
    rev = pinnedRev;
    hash = "sha256-2IN32AxBXHRr53EBD82Bum/QwXrhJATiP4GgtIPCRb8=";
    curlOptsList = [ "--ipv4" ];
  };
  prodProject = import ../../../projects/openprot/project.nix;
in
{
  inherit (prodProject) name repoName repoUrl threatModel;
  inherit pinnedRev src;
  targetDir = "services";

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  minPocSeverity = "Informational";
  batchSize = prodProject.defaultBatchSize or 64;
  extensions = [ "rs" ];
  excludeDirs = [ "tests" "test" "benches" "fuzz" "testdata" ];
  excludePatterns = [ "*_test.rs" "test_*.rs" "tests.rs" ];
  testPathTokens = [ "tests" "test" "benches" "fuzz" ];

  scopes = [
    {
      name = "default";
      srcDirs = [ "services" ];
    }
    {
      name = "smoke";
      srcDirs = [ "services/mctp/api/src/wire.rs" ];
    }
  ];
}
