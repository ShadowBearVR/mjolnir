# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs, project, job, runner, nidhogg-app }:

let
  lib = pkgs.lib;

  # Assert mandatory attributes
  commit = if (job ? commit && job.commit != "") then job.commit else throw "Nidhogg Job error: 'commit' attribute is mandatory for job '${job.name}'!";
  profileName = if (job ? profile && job.profile != "") then job.profile else "smoke";

  # Combine project and job metadata
  jobSpec = {
    projectName = project.name;
    repoName = project.repoName;
    repoUrl = project.repoUrl;
    commit = commit;
    threatModelPath = toString project.threatModel;
    jobName = job.name;
    srcDirs = job.srcDirs;
    profile = profileName;
    datasetId = if (job ? datasetId) then job.datasetId else "default-dataset";
    runnerTarget = if (job ? runnerTarget) then job.runnerTarget else "opentitan-runner-host-test";
  };

  # Serialize job spec to JSON
  jobSpecJson = pkgs.writeText "nidhogg-job-spec-${lib.strings.sanitizeDerivationName job.name}.json" (builtins.toJSON jobSpec);
in
pkgs.writeShellApplication {
  name = "nidhogg-run-${lib.strings.sanitizeDerivationName job.name}";
  runtimeInputs = [ nidhogg-app runner pkgs.git pkgs.nix ];
  text = ''
    echo "=================================================="
    echo " Nidhogg Job Launcher: ${job.name}"
    echo " Project: ${project.name} (Commit: ${commit})"
    echo " Profile: ${profileName}"
    echo "=================================================="
    
    export MJOLNIR_ROOT="''${MJOLNIR_ROOT:-$PWD}"
    nidhogg-generate --spec "${jobSpecJson}" "$@"
  '';
}
