# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  name = "OpenPRoT";
  repoName = "openprot";
  repoUrl = "https://github.com/OpenPRoT/openprot.git";
  pinnedRev = "ef0607aebb36b67c3b8876cb3b609af55c2012ce";
  threatModel = ../../../projects/openprot/threat_model.md;

  generatorModel = "claude-3-5-sonnet-latest";
  evaluatorModel = "gemini-3.8-flash";
  batchSize = 64;
  extensions = [ "rs" "c" "h" ];

  buildCmd = "bazel build //...";
  testCmd = "bazel test //services/...";
  lintCmd = null;

  scopes = [
    {
      name = "orchestrator-sm";
      srcDirs = [ "services/orchestrator/sm/src" ];
      testCmd = "bazel test //services/orchestrator/sm:orchestrator_sm_test";
    }
    {
      name = "orchestrator-driver";
      srcDirs = [ "services/orchestrator/driver/src" ];
      testCmd = "bazel test //services/orchestrator/driver:orchestrator_driver_test";
    }
  ];
}
