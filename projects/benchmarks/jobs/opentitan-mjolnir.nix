# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  type = "nidhogg-benchmark";
  name = "OpenTitan ROM Mjolnir Audit Benchmark";
  corpus = ../../../nidhogg/corpus/opentitan-rom-v1;
  auditor = "mjolnir-adk";
  runnerTarget = "opentitan-runner-host-test";
}
