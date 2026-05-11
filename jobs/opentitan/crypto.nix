{ pkgs }:
import ./base.nix { inherit pkgs; } {
  subjobName = "CRYPTO";
  subdir = "crypto";
  searchPaths = [
    "sw/device/lib/base"
    "sw/device/lib/crypto"
    "sw/otbn/crypto"
  ];
}
