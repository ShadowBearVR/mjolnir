# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  name = "Caliptra SW";
  repoName = "caliptra-sw";
  repoUrl = "https://github.com/chipsalliance/caliptra-sw.git";
  pinnedRev = "262470b019905e8ea307be63860730d64c35d436";
  threatModel = ./threat_model.md;

  generatorModel = "claude-3-5-sonnet-latest";
  evaluatorModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "rs" ];

  buildCmd = "cargo check --workspace --tests";
  testCmd = "cargo test --workspace --lib";
  lintCmd = "cargo clippy --workspace --lib -- -D warnings";

  scopes = [
    {
      name = "drivers";
      srcDirs = [ "drivers/src" ];
      testCmd = "cargo test -p caliptra-drivers --lib";
    }
    {
      name = "fmc";
      srcDirs = [ "fmc/src" ];
      testCmd = "cargo test -p caliptra-fmc --lib";
    }
    {
      name = "runtime";
      srcDirs = [ "runtime/src" ];
      testCmd = "cargo test -p caliptra-runtime --lib";
    }
    {
      name = "rom";
      srcDirs = [ "rom/dev/src" ];
      testCmd = "cargo test -p caliptra-rom --lib";
    }
    {
      name = "image-verify";
      srcDirs = [ "image/verify/src" ];
      testCmd = "cargo test -p caliptra-image-verify --lib";
    }
    {
      name = "kat";
      srcDirs = [ "kat/src" ];
      testCmd = "cargo test -p caliptra-kat --lib";
    }
  ];
}
