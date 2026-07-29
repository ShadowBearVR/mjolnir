# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path

NIDHOGG_DIR = Path(__file__).parent.resolve()
ROOT_DIR = Path(os.environ.get("MJOLNIR_ROOT", os.environ.get("PWD", os.getcwd()))).resolve()

DATA_DIR = ROOT_DIR / "nidhogg" / "data"
CORPUS_DIR = ROOT_DIR / "nidhogg" / "corpus"
CWE_DATASET_PATH = DATA_DIR / "cwes_2026_07_20.json"

# OpenTitan Defaults
OPENTITAN_WORKSPACE_DIR = ROOT_DIR / "workspace" / "opentitan"
OPENTITAN_PROJECT_DIR = ROOT_DIR / "projects" / "opentitan"
OPENTITAN_THREAT_MODEL_PATH = OPENTITAN_PROJECT_DIR / "threat_model.md"

def get_opentitan_code_dir() -> Path:
    """Dynamically resolves the checked-out OpenTitan source repository directory."""
    base = OPENTITAN_WORKSPACE_DIR
    if (base / "sw").exists():
        return base
    for pref in ["Crypto_Lib_Earlgrey", "Runner_Host_Test", "Silicon_Creator_ROM_EXT_Earlgrey"]:
        cand = base / pref / "opentitan"
        if (cand / "sw").exists() and (cand / "third_party" / "system_libs" / "extensions.bzl").exists():
            return cand
    for sub in base.glob("*/opentitan"):
        if (sub / "sw").exists() and (sub / "third_party" / "system_libs" / "extensions.bzl").exists():
            return sub
    for sub in base.glob("*/opentitan"):
        if (sub / "sw").exists():
            return sub
    return base

DEFAULT_TARGET_FILES = [
    "sw/device/silicon_creator/lib/drivers/uart.c",
]

DEFAULT_NIX_RUNNER_TARGET = "opentitan-runner-host-test"

# Complexity Matrix Levels
SPATIAL_SCOPES = ["INTRA_PROCEDURAL", "INTER_PROCEDURAL", "CROSS_COMPONENT"]
TEMPORAL_DEPTHS = ["STATELESS", "SHALLOW_STATE", "DEEP_STATE_RACE"]
DOMAIN_SUBTLETY_LEVELS = ["STANDARD_CWE", "LOGIC_SPEC_MISMATCH", "HW_FW_INTERFACE"]
