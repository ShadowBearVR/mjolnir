# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs, makeNidhoggJob, runners, nidhogg-app }:

let
  lib = pkgs.lib;
  projectsDir = ../../projects;

  # Read all subdirectories under projects/
  projectDirs = builtins.attrNames (
    lib.filterAttrs (name: type: type == "directory" && name != "benchmarks") (builtins.readDir projectsDir)
  );

  # Discover all nidhogg-*.nix files under projects/<project>/jobs/
  discoverProjectJobs = projName:
    let
      projPath = projectsDir + "/${projName}";
      projectFile = projPath + "/project.nix";
      jobsDir = projPath + "/jobs";

      hasProject = builtins.pathExists projectFile;
      hasJobsDir = builtins.pathExists jobsDir;

      project = if hasProject then import projectFile else null;

      nidhoggJobFiles = if hasJobsDir then
        lib.filterAttrs (name: type:
          type == "regular" &&
          lib.hasPrefix "nidhogg-" name &&
          lib.hasSuffix ".nix" name
        ) (builtins.readDir jobsDir)
      else {};

      runner = if runners ? ${projName} then runners.${projName} else null;

      jobs = lib.mapAttrs' (fileName: _:
        let
          job = import (jobsDir + "/${fileName}");
          attrName = "nidhogg-gen-${projName}-${lib.removeSuffix ".nix" (lib.removePrefix "nidhogg-" fileName)}";
          drv = makeNidhoggJob {
            inherit project job runner nidhogg-app;
          };
        in
          lib.nameValuePair attrName drv
      ) nidhoggJobFiles;
    in
      if (hasProject && project != null) then jobs else {};

  allDiscoveredJobs = lib.foldl' (acc: projName: acc // (discoverProjectJobs projName)) {} projectDirs;
in
allDiscoveredJobs
