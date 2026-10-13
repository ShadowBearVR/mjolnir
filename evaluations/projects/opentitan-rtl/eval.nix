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
  name = "OpenTitan RTL";
  repoName = "opentitan-rtl";
  inherit (prodProject) repoUrl threatModel;
  inherit pinnedRev src;
  targetDir = "hw/top_earlgrey";

  evaluatorModel = "gemini-3.8-flash";
  judgeModel = "gemini-3.8-flash";
  minPocSeverity = "Informational";
  batchSize = 64;
  extensions = [ "sv" ];
  sastTiers = [ "semgrep" ];
  excludeDirs = [
    "dv"
    "fpv"
    "test"
    "tests"
    "testdata"
    "fuzz"
  ];
  excludePatterns = [
    "*_test.sv"
    "*_reg_top.sv"
    "*_reg_pkg.sv"
  ];
  testPathTokens = [
    "dv"
    "tb"
    "fpv"
    "testdata"
  ];

  buildCmd = "verilator --lint-only -Wno-fatal -Ihw/ip/prim/rtl -Ihw/top_earlgrey/rtl hw/top_earlgrey/rtl/top_pkg.sv hw/ip/prim/rtl/prim_util_pkg.sv hw/ip/prim/rtl/prim_mubi_pkg.sv hw/ip/prim/rtl/prim_secded_pkg.sv hw/ip/prim/rtl/prim_count_pkg.sv hw/ip/tlul/rtl/tlul_pkg.sv";
  testCmd = "verilator --cc --exe --build -Wno-WIDTHTRUNC --Mdir /tmp/obj_dir -Ihw/ip/prim/rtl -Ihw/top_earlgrey/rtl";
  lintCmd = "verilator --lint-only -Wall -Wno-fatal -Ihw/ip/prim/rtl -Ihw/top_earlgrey/rtl hw/top_earlgrey/rtl/top_pkg.sv";

  scopes = [
    {
      name = "default";
      srcDirs = [ "hw/top_earlgrey" ];
    }
    {
      name = "smoke";
      srcDirs = [ "hw/top_earlgrey/rtl/padring.sv" ];
    }
  ];

  cliTemplates = {
    antigravity = "${pkgs.antigravity}/bin/antigravity -p {prompt} --dangerously-skip-permissions";
  };
}
