# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs }:
let
  # Canonical fw-2.1.0 release tag (2026-03-10), predating all 5 2026 GHSAs/CVEs:
  # CVE-2026-5818, CVE-2026-6458, CVE-2026-7328, CVE-2026-11835, CVE-2026-11836.
  pinnedRev = "7da3b01b8b1806af0ec491c5e3e3e7cac91a3561";
  src = pkgs.fetchFromGitHub {
    owner = "chipsalliance";
    repo = "caliptra-sw";
    rev = pinnedRev;
    hash = "sha256-v7lmpp/6qF4mia1bEiHklaFmrUCNqKoXQz8FsEV2zzc=";
    curlOptsList = [ "--ipv4" ];
  };
  modernSpec = import ../caliptra-sw/eval.nix { inherit pkgs; };
  onTargetFirmwareDirs = [
    "rom/dev/src"
    "fmc/src"
    "runtime/src"
    "drivers/src"
    "common/src"
    "image/verify/src"
    "auth-manifest/types/src"
    "cfi/lib/src"
    "cpu/src"
    "error/src"
  ];
in
{
  name = "Caliptra SW (fw-2.1.0)";
  repoName = "caliptra-sw-v210";
  repoUrl = "https://github.com/chipsalliance/caliptra-sw.git";
  inherit pinnedRev src;
  targetDir = "runtime/src";
  threatModel = modernSpec.threatModel;
  cveGroundTruth = ./cve_ground_truth.json;

  defaultTiers = "full";
  defaultRepetitions = 1;
  evaluatorModel = "gemini-3.8-flash";
  minPocSeverity = "Informational";
  batchSize = 64;
  extensions = [ "rs" ];
  excludeDirs = [ "tests" "test" "benches" "fuzz" "testdata" ];
  excludePatterns = [ "*_test.rs" "test_*.rs" "tests.rs" ];
  testPathTokens = [ "tests" "test" "benches" "fuzz" ];

  scopes = [
    {
      name = "default";
      srcDirs = onTargetFirmwareDirs;
    }
    {
      name = "runtime";
      srcDirs = [ "runtime/src" ];
    }
    {
      name = "rom";
      srcDirs = [ "rom/dev/src" ];
    }
    {
      name = "smoke";
      srcDirs = [ "common/src/debug_unlock.rs" ];
    }
  ];
}
