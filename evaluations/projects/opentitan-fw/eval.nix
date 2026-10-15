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
    curlOptsList = [ "--ipv4" ];
  };
  prodProject = import ../../../projects/opentitan/project.nix;
in
{
  name = "OpenTitan FW";
  repoName = "opentitan-fw";
  inherit (prodProject) repoUrl threatModel;
  inherit pinnedRev src;
  targetDir = "sw/device/silicon_creator/rom_ext";

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  minPocSeverity = "Informational";
  batchSize = 64;
  extensions = [ "c" "h" "rs" ];
  sastTiers = [ "semgrep" ];
  excludeDirs = [
    "e2e"
    "test"
    "tests"
    "testdata"
    "sigverify_tests"
    "dv"
    "fuzz"
    "fpv"
  ];
  excludePatterns = [
    "*_test.c"
    "*_test.h"
    "*_test.rs"
    "*_functest.c"
    "*_functest.h"
    "*_unittest.c"
    "*_unittest.h"
    "*_cryptotest.c"
    "*_test_*.c"
    "*_test_*.h"
    "*_unittest_*.h"
    "*_fuzzer_*.h"
    "*_testlib.h"
    "mock_*.c"
    "mock_*.h"
    "test_*.c"
    "test_*.h"
  ];
  testPathTokens = [
    "dv"
    "tb"
    "e2e"
    "fpv"
    "functest"
    "cryptotest"
    "testlib"
    "testdata"
  ];

  buildCmd = "bazel build //sw/device/silicon_creator/rom_ext/...";
  testCmd = "bazel test --test_tag_filters=-verilator,-dv,-fpga //sw/device/silicon_creator/rom_ext/...";
  lintCmd = null;

  scopes = [
    {
      name = "default";
      srcDirs = [ "sw/device/silicon_creator/rom_ext" ];
    }
    {
      name = "smoke";
      srcDirs = [ "sw/device/silicon_creator/rom_ext/rom_ext_manifest.c" ];
    }
  ];

  cliTemplates = {
    antigravity = "antigravity -p {prompt} --dangerously-skip-permissions";
  };
}
