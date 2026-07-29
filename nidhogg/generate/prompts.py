# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

from typing import Dict, Any, List
from nidhogg.models import NCMCoordinate

GENERIC_ROT_THREAT_MODEL = """
ROOT-OF-TRUST (RoT) FIRMWARE SECURITY THREAT MODEL & ARCHITECTURE:

1. TRUST BOUNDARIES & HARDWARE SECURITY:
   - Primary Trust Anchor: ROM/ROM_EXT code executing in machine mode (M-mode) on silicon startup.
   - Hardware MMIO Registers: Peripherals (UART, AES, HMAC, KMAC, OTBN, Key Manager, Flash Controller) controlled via memory-mapped IO.
   - Memory Model: Strict SRAM/Flash regions protected by EPMP (Enhanced Physical Memory Protection). Memory operations must enforce strict bounds and alignment.

2. REALISTIC VULNERABILITY TAXONOMY IN HARDWARE/FIRMWARE:
   - Spatial Scope (INTRA_PROCEDURAL, INTER_PROCEDURAL, CROSS_COMPONENT):
     * Bounds check mismatch or integer overflow during hardware register configuration.
     * Unsanitized input length or pointer arithmetic in hardware drivers.
     * Off-by-one errors in memory validation functions.
   - Temporal Depth (STATELESS, SHALLOW_STATE, DEEP_STATE_RACE):
     * Uninitialized driver state or missing status flag verification before executing hardware transactions.
     * Incorrect state machine transitions during key loading or reset operations.
   - Domain Subtlety (STANDARD_CWE, LOGIC_SPEC_MISMATCH, HW_FW_INTERFACE):
     * Misconfiguration of hardware control/shadowed registers.
     * Hardened boolean logic bypasses (e.g., using standard boolean operators instead of hardened checks).

3. STRICT REALISM & ANTI-PATTERN DIRECTIVES:
   - NO TOY OR ARTIFICIAL MAGIC CONSTANTS: Never introduce magic hex values like `0xdeadbeef`, `0x1234`, `0xbadc0de`.
   - NO EMBEDDED VULNERABILITY COMMENTS: Do NOT insert comments containing "CWE-xxx", "VULNERABILITY", "BUG", or "SECRET_LEAK".
   - NO SILLY STRINGS OR LOGGING: Do NOT add debug printfs, fake leak strings, or contrived backdoors.
   - NATURAL PRODUCTION STYLE: The patch MUST look like a genuine human mistake, omission, or logic edge-case in production C firmware.
"""

SPATIAL_EXPLANATION = {
    "INTRA_PROCEDURAL": "The vulnerability cause and effect are entirely within a single function.",
    "INTER_PROCEDURAL": "The cause and effect span multiple functions within the same module.",
    "CROSS_COMPONENT": "The cause and effect span different architectural components or drivers."
}

TEMPORAL_EXPLANATION = {
    "STATELESS": "The bug triggers immediately on first invocation under specific parameters.",
    "SHALLOW_STATE": "Requires 1-2 prerequisite state transitions (e.g. init before process).",
    "DEEP_STATE_RACE": "Requires specific sequence of state transitions or hardware register states."
}

SUBTLETY_EXPLANATION = {
    "STANDARD_CWE": "Standard software weakness (e.g., buffer length truncation, boundary check failure).",
    "LOGIC_SPEC_MISMATCH": "Compiles cleanly and looks logically sound but subtle logic condition allows bypass.",
    "HW_FW_INTERFACE": "Hardware-firmware interface mismatch or register status check bypass."
}
