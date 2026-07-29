# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  name = "balanced";
  description = "Balanced profile: 2 vulnerabilities per NCM bucket (54 total vulns)";
  strategy = "per_bucket";
  samples_per_bucket = 2;
}
