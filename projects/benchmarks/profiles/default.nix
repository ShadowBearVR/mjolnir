# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{
  trivial = import ./trivial.nix;
  smoke = import ./smoke.nix;
  balanced = import ./balanced.nix;
  rot-hardened = import ./rot-hardened.nix;
}
