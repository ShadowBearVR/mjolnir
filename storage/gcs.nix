{
  pkgs,
  bucket ? "caliptra-github-ci-caliptra-reports",
  path ? "",
}:
{
  name = "gcs";
  upload =
    { runDir }:
    ''
      echo "Uploading run directory to GCS bucket ${bucket}..."
      RUN_DIR_NAME=$(basename "${runDir}")
      DEST="gs://${bucket}/v0/${path}/$RUN_DIR_NAME"

      # Use gsutil to copy the contents of the directory
      ${pkgs.google-cloud-sdk}/bin/gsutil cp -r "${runDir}/." "$DEST/"
      echo "Uploaded to $DEST"
    '';
}
