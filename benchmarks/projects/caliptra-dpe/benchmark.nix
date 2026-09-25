# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  name = "Caliptra DPE";
  repoName = "caliptra-dpe";
  repoUrl = "https://github.com/chipsalliance/caliptra-dpe.git";
  pinnedRev = "7c210f1217479040c966ecadead837b0432fa83a";
  threatModel = ../caliptra-sw/threat_model.md;

  generatorModel = "claude-3-5-sonnet-latest";
  evaluatorModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "rs" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test --workspace";
  lintCmd = "cargo clippy --workspace -- -D warnings";

  scopes = [
    {
      name = "dpe";
      srcDirs = [ "dpe/src" ];
      testCmd = "cargo test -p dpe";
    }
    {
      name = "crypto";
      srcDirs = [ "crypto/src" ];
      testCmd = "cargo test -p crypto";
    }
  ];
}
