# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs, evaluation, evaluation-app, mjolnir-app, devShell ? null, ... }:
let
  evalCfg = if builtins.isFunction evaluation then evaluation { inherit pkgs; } else evaluation;

  spec = {
    project = {
      inherit (evalCfg) name repoName repoUrl pinnedRev;
      nixSourcePath = if evalCfg ? src && evalCfg.src != null then "${evalCfg.src}" else null;
      targetDir = evalCfg.targetDir or null;
      threatModel = evalCfg.threatModel or null;
      evaluatorModel = evalCfg.evaluatorModel or "gemini-3.8-flash";
      minPocSeverity = evalCfg.minPocSeverity or "Informational";
      batchSize = evalCfg.batchSize or 64;
      extensions = evalCfg.extensions or [ "rs" "c" "h" ];
      excludeDirs = evalCfg.excludeDirs or [ ];
      excludePatterns = evalCfg.excludePatterns or [ ];
      testPathTokens = evalCfg.testPathTokens or [ ];
      scopes = evalCfg.scopes or [
        {
          name = "default";
          srcDirs = [ (evalCfg.targetDir or ".") ];
        }
      ];
    };

    config = {
      outputDir = evalCfg.outputDir or "./test-out/evaluations";
      cacheDir = evalCfg.cacheDir or "./test-out/eval-cache";
      mjolnirBin = "${mjolnir-app}/bin/mjolnir-run";
    };
  };

  specFile = pkgs.writeText "mjolnir-eval-spec-${evalCfg.repoName}.json" (builtins.toJSON spec);

  shellInputs = if devShell != null then
    (devShell.nativeBuildInputs or []) ++
    (devShell.buildInputs or []) ++
    (devShell.propagatedBuildInputs or []) ++
    (if devShell ? outPath then [ devShell ] else [])
  else [];

  shellBinPath = pkgs.lib.makeBinPath shellInputs;
  shellHook = if devShell != null && devShell ? shellHook then devShell.shellHook else "";
  shellHookScript = if shellHook != "" then
    pkgs.writeShellScript "mjolnir-eval-shell-hook-${evalCfg.repoName}" shellHook
  else null;

  launcher = pkgs.writeShellScriptBin "mjolnir-eval-${evalCfg.repoName}" ''
    set -e

    ${pkgs.lib.optionalString (shellBinPath != "") ''
      export PATH="${shellBinPath}:$PATH"
    ''}

    ${pkgs.lib.optionalString (shellHookScript != null) ''
      export MJOLNIR_SHELL_HOOK="${shellHookScript}"
      source "${shellHookScript}"
    ''}

    if [ "$#" -eq 0 ]; then
      set -- run --tiers "${evalCfg.defaultTiers or (if evalCfg.repoName == "caliptra-sw" then "no_tm,no_expert,full" else "full")}" --repetitions ${toString (evalCfg.defaultRepetitions or (if evalCfg.repoName == "caliptra-sw" then 3 else 1))} --run-label pinned
    fi

    exec ${evaluation-app}/bin/mjolnir-eval --spec "${specFile}" "$@"
  '';
in
  launcher
