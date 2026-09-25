# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs, benchmark, nidhogg-app, mjolnir-app, devShell ? null, ... }:
let
  spec = {
    project = {
      inherit (benchmark) name repoName repoUrl pinnedRev;
      threatModel = benchmark.threatModel or null;
      generatorModel = benchmark.generatorModel or "claude-3-5-sonnet-latest";
      evaluatorModel = benchmark.evaluatorModel or "gemini-3.8-flash";
      batchSize = benchmark.batchSize or 64;
      extensions = benchmark.extensions or [ "rs" "c" "h" ];
      excludeDirs = benchmark.excludeDirs or [ ];
      excludePatterns = benchmark.excludePatterns or [ ];
      buildCmd = benchmark.buildCmd or null;
      testCmd = benchmark.testCmd or null;
      lintCmd = benchmark.lintCmd or null;
      scopes = benchmark.scopes or [
        {
          name = "default";
          srcDirs = [ "." ];
        }
      ];
    };

    config = {
      corpusDir = benchmark.corpusDir or "./benchmarks/corpus";
      outputDir = benchmark.outputDir or "./test-out/benchmarks";
      cacheDir = benchmark.cacheDir or "./test-out/nidhogg-cache";
      mjolnirBin = "${mjolnir-app}/bin/mjolnir-run";
    };
  };

  specFile = pkgs.writeText "nidhogg-spec-${benchmark.repoName}.json" (builtins.toJSON spec);

  shellInputs = if devShell != null then
    (devShell.nativeBuildInputs or []) ++
    (devShell.buildInputs or []) ++
    (devShell.propagatedBuildInputs or []) ++
    (if devShell ? outPath then [ devShell ] else [])
  else [];

  shellBinPath = pkgs.lib.makeBinPath shellInputs;
  shellHook = if devShell != null && devShell ? shellHook then devShell.shellHook else "";

  launcher = pkgs.writeShellScriptBin "nidhogg-${benchmark.repoName}" ''
    set -e

    ${pkgs.lib.optionalString (shellBinPath != "") ''
      export PATH="${shellBinPath}:$PATH"
    ''}

    ${pkgs.lib.optionalString (shellHook != "") ''
      ${shellHook}
    ''}

    exec ${nidhogg-app}/bin/nidhogg-run --spec "${specFile}" "$@"
  '';
in
  launcher
