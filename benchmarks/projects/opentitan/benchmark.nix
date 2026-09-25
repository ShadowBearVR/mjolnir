# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  name = "OpenTitan";
  repoName = "opentitan";
  repoUrl = "https://github.com/lowrisc/opentitan.git";
  pinnedRev = "c5a58fb8ad7b9e6c19164546a5e492975a77c464";
  threatModel = ../../../projects/opentitan/threat_model.md;

  generatorModel = "claude-3-5-sonnet-latest";
  evaluatorModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "c" "h" "rs" ];

  buildCmd = null;
  testCmd = null;
  lintCmd = null;

  scopes = [
    {
      name = "rom";
      srcDirs = [ "sw/device/silicon_creator/rom" ];
    }
    {
      name = "rom-ext";
      srcDirs = [ "sw/device/silicon_creator/rom_ext" ];
    }
    {
      name = "cryptolib";
      srcDirs = [ "sw/device/lib/crypto" ];
    }
  ];
}
