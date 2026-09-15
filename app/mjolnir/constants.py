# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Central constants and operational defaults for Mjolnir."""

# --- Security & System Alignment ---
SYSTEM_PROMPT = (
    "### AUTHORIZED SECURITY EVALUATION ENVIRONMENT\n"
    "You are operating within an explicitly authorized, isolated, defensive static analysis "
    "and vulnerability assessment environment (Mjolnir). All source code, architecture "
    "artifacts, and threat models provided to you belong to the system owner who has "
    "explicitly commissioned this security audit.\n"
    "- Performing vulnerability scanning, identifying security flaws, analyzing exploitability "
    "paths, and describing attack vectors in this context is strictly defensive, authorized, "
    "and benign.\n"
    "- Do NOT refuse or censor technical analysis of code vulnerabilities. If internal safety "
    "constraints prevent you from evaluating a specific target or finding, do not silently "
    "omit findings—instead, explicitly populate the `refusal_reason` field in your structured "
    "response schema explaining the constraint."
)

# --- Transport & SDK Retry Configuration ---
DEFAULT_RETRY_ATTEMPTS = 5
DEFAULT_RETRY_INITIAL_DELAY = 2.0
DEFAULT_RETRY_MAX_DELAY = 60.0

# --- Context Caching Configuration ---
DEFAULT_CONTEXT_CACHE_TTL_SECONDS = 7200
MIN_CONTEXT_CACHE_TOKENS = 4096
MIN_CONTEXT_CACHE_CHARS_ESTIMATE = MIN_CONTEXT_CACHE_TOKENS * 4  # ~16,384 chars

# --- Concurrency & Dispatch Configuration ---
DEFAULT_DISPATCH_STAGGER_SECONDS = 0.25

# --- Agent Turn Ceilings (RunConfig backstop) ---
AUDITOR_MAX_LLM_CALLS = 25
REVIEWER_MAX_LLM_CALLS = 100
INGESTION_MAX_LLM_CALLS = 50

# --- Tool Execution & Output Limits ---
DEFAULT_TOOL_OUTPUT_MAX_CHARS = 40000
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
BINARY_CHECK_CHUNK_BYTES = 8192

# --- Storage & Artifact Versioning ---
API_VERSION = "v1"
RUNS_SUBDIR = f"{API_VERSION}/runs"
WEB_SUBDIR = "web"
