{ pkgs }:
import ./base.nix { inherit pkgs; } {
  subjobName = "ROM";
  subdir = "rom";
  searchPath = "sw/device/silicon_creator/rom";
}
