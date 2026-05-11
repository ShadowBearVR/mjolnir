{ pkgs }:
import ./base.nix { inherit pkgs; } {
  subjobName = "LIB";
  subdir = "lib";
  searchPath = "sw/device/silicon_creator/lib";
}
