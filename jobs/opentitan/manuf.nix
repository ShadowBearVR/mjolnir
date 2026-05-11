{ pkgs }:
import ./base.nix { inherit pkgs; } {
  subjobName = "MANUF";
  subdir = "manuf";
  searchPath = "sw/device/silicon_creator/manuf";
}
