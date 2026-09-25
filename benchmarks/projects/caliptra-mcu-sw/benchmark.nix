# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  name = "Caliptra MCU SW";
  repoName = "caliptra-mcu-sw";
  repoUrl = "https://github.com/chipsalliance/caliptra-mcu-sw.git";
  pinnedRev = "21d2654c095048072bd07c9dbb2b3fa9528fa94d";
  threatModel = ../caliptra-sw/threat_model.md;

  generatorModel = "claude-3-5-sonnet-latest";
  evaluatorModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "rs" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test --workspace --lib";
  lintCmd = "cargo clippy --workspace --lib -- -D warnings";

  scopes = [
    {
      name = "rom";
      srcDirs = [ "rom/src" ];
      testCmd = "cargo test --workspace --lib";
    }
    {
      name = "runtime";
      srcDirs = [ "runtime" ];
      testCmd = "cargo test --workspace --lib";
    }
  ];
}
