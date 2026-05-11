# NOTE: This backend is currently a PLACEHOLDER and is NOT YET WORKING OR TESTED.
{ pkgs }:
{
  name = "claude";
  run =
    {
      systemPrompt,
      src,
      output,
    }:
    ''
      echo "Running Claude backend on ${src}..."
      echo "# Claude Audit Report" > "${output}"
      echo "Simulated Claude analysis complete." >> "${output}"
    '';
}
