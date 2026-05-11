{ pkgs }:
import ./base.nix { inherit pkgs; } {
  subjobName = "ROM_EXT";
  subdir = "rom_ext";
  searchPath = "sw/device/silicon_creator/rom_ext";
}
