# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

import io
import json
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from nidhogg.config import DATA_DIR, CWE_DATASET_PATH

MITRE_CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

def download_and_parse_mitre_cwes():
    """Downloads official MITRE CWE XML zip, parses Weaknesses, and saves static JSON dataset."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading official MITRE CWE catalog from {MITRE_CWE_ZIP_URL}...")

    req = urllib.request.Request(
        MITRE_CWE_ZIP_URL,
        headers={"User-Agent": "Mozilla/5.0 (Mjolnir-Nidhogg-Security-Research)"}
    )
    with urllib.request.urlopen(req) as response:
        zip_bytes = response.read()

    print(f"Downloaded {len(zip_bytes)} bytes. Unzipping in-memory...")
    cwes_list = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        xml_filenames = [f for f in z.namelist() if f.endswith(".xml")]
        if not xml_filenames:
            raise ValueError("No XML file found inside MITRE CWE zip!")

        target_xml = xml_filenames[0]
        print(f"Parsing XML content from {target_xml}...")
        with z.open(target_xml) as xml_file:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # Handle XML namespaces dynamically
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            weaknesses_node = root.find(f"{ns}Weaknesses")
            if weaknesses_node is not None:
                for weakness in weaknesses_node.findall(f"{ns}Weakness"):
                    cwe_id = weakness.attrib.get("ID")
                    name = weakness.attrib.get("Name")
                    status = weakness.attrib.get("Status")

                    desc_node = weakness.find(f"{ns}Description")
                    description = desc_node.text.strip() if desc_node is not None and desc_node.text else ""

                    extended_desc_node = weakness.find(f"{ns}Extended_Description")
                    if extended_desc_node is not None and extended_desc_node.text:
                        description += " " + extended_desc_node.text.strip()

                    # Extract abstraction/structure
                    abstraction = weakness.attrib.get("Abstraction", "")
                    structure = weakness.attrib.get("Structure", "")

                    cwes_list.append({
                        "id": f"CWE-{cwe_id}",
                        "name": name,
                        "abstraction": abstraction,
                        "structure": structure,
                        "status": status,
                        "description": description[:1000]  # Limit length for prompt efficiency
                    })

    dataset = {
        "source": MITRE_CWE_ZIP_URL,
        "fetched_date": "2026-07-20",
        "total_count": len(cwes_list),
        "cwes": cwes_list
    }

    with open(CWE_DATASET_PATH, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"Successfully downloaded and saved {len(cwes_list)} official MITRE CWE definitions to {CWE_DATASET_PATH}")

if __name__ == "__main__":
    download_and_parse_mitre_cwes()
