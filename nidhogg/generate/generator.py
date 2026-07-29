# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path

# Ensure app/mjolnir is in python path for client import
mjolnir_app_dir = Path(__file__).parent.parent.parent / "app" / "mjolnir"
if str(mjolnir_app_dir) not in sys.path:
    sys.path.insert(0, str(mjolnir_app_dir))

from nidhogg.generate.adk_generator import run_adk_react_generator

def generate_vulnerability(
    target_project: str = "opentitan",
    dataset_id: str = "opentitan_v01",
    model_name: str = "gemini-2.5-flash"
) -> bool:
    """Entrypoint forwarding to ADK ReAct Generator Engine."""
    return run_adk_react_generator(
        target_project=target_project,
        dataset_id=dataset_id,
        model_name=model_name
    )

if __name__ == "__main__":
    generate_vulnerability()
