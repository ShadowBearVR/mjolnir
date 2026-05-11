{ pkgs, path }:
{
  name = "local";
  upload =
    { runDir }:
    ''
      echo "Results are already in local path ${runDir} (target base: ${path})"
    '';
}
