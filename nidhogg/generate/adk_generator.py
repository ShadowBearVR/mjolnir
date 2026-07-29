# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import json
import random
import argparse
import asyncio
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Ensure app/mjolnir is in python path
mjolnir_app_dir = Path(__file__).parent.parent.parent / "app" / "mjolnir"
if str(mjolnir_app_dir) not in sys.path:
    sys.path.insert(0, str(mjolnir_app_dir))

from google.adk import Agent, Context
from google.adk.agents.run_config import RunConfig

from nidhogg.config import (
    ROOT_DIR,
    CORPUS_DIR,
    CWE_DATASET_PATH,
    OPENTITAN_THREAT_MODEL_PATH,
    DEFAULT_TARGET_FILES,
    DEFAULT_NIX_RUNNER_TARGET,
    SPATIAL_SCOPES,
    TEMPORAL_DEPTHS,
    DOMAIN_SUBTLETY_LEVELS,
    get_opentitan_code_dir,
)
from nidhogg.models import (
    NCMCoordinate,
    VulnerabilitySpec,
    DatasetManifest,
    DatasetMetadata,
    VulnerabilityItemStatus,
)
from nidhogg.runner import OpenTitanRunner
from nidhogg.generate.adk_tools import NidhoggADKTools
from nidhogg.generate.prompts import (
    SPATIAL_EXPLANATION,
    TEMPORAL_EXPLANATION,
    SUBTLETY_EXPLANATION,
    GENERIC_ROT_THREAT_MODEL,
)
from providers.adk.agents.isolated_agent import IsolatedAgent, make_tool_budget_callback


def log(msg: str):
    """Flushes output immediately to avoid terminal buffering delays."""
    print(msg, flush=True)


def load_cwes() -> List[Dict[str, Any]]:
    """Loads the parsed MITRE CWE dataset."""
    if not CWE_DATASET_PATH.exists():
        raise FileNotFoundError(f"CWE dataset missing at {CWE_DATASET_PATH}. Run fetch_cwes.py first.")
    with open(CWE_DATASET_PATH, "r") as f:
        data = json.load(f)
    return data.get("cwes", [])


def load_profile(profile_name: str) -> Dict[str, Any]:
    """Loads profile definition from nidhogg/profiles/<profile_name>.json."""
    profile_path = ROOT_DIR / "nidhogg" / "profiles" / f"{profile_name}.json"
    if profile_path.exists():
        with open(profile_path, "r") as f:
            return json.load(f)
    return {"name": profile_name, "strategy": "uniform"}


def clean_diff_output(raw_text: str) -> str:
    """Strips markdown code fences from generated unified git diff."""
    text = raw_text.strip()
    if text.startswith("```diff"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip() + "\n"


async def run_adk_react_generator_async(
    target_project: str = "opentitan",
    dataset_id: str = "opentitan_v01",
    model_name: str = "gemini-2.5-flash",
    target_files: Optional[List[str]] = None,
    runner_target: str = DEFAULT_NIX_RUNNER_TARGET,
    profile_name: str = "trivial",
    overwrite_existing: bool = False
) -> bool:
    """True ADK 2.0 Agent ReAct Generator Loop with real-time metadata updates & collision abort checks."""
    log("==================================================")
    log(" Nidhogg True ADK 2.0 ReAct Generator Engine")
    log(f" Target Project: {target_project}")
    log(f" Dataset ID:     {dataset_id}")
    log("==================================================")

    dataset_dir = CORPUS_DIR / dataset_id
    metadata_file = dataset_dir / "metadata.json"

    # Collision Warning & Early Abort
    if metadata_file.exists() and not overwrite_existing:
        log(f"\n[!] WARNING: Target corpus dataset '{dataset_id}' already exists at:")
        log(f"    {metadata_file}")
        log("[!] ABORTING execution to prevent accidental overwrite of existing dataset.")
        log("[!] To force overwrite, remove the corpus directory or set overwrite_existing=True.\n")
        return False

    # Initialize Dataset Metadata at start
    dataset_dir.mkdir(parents=True, exist_ok=True)
    start_time_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    metadata = DatasetMetadata(
        dataset_id=dataset_id,
        target_project=target_project,
        profile=profile_name,
        status="IN_PROGRESS",
        started_at=start_time_str,
        updated_at=start_time_str,
        total_requested=1,
        completed_count=0,
        failed_count=0,
        vulnerabilities=[]
    )
    with open(metadata_file, "w") as f:
        json.dump(metadata.to_dict(), f, indent=2)
    log(f"[+] Initialized target dataset tracking file: {metadata_file}")

    code_dir = get_opentitan_code_dir()
    runner = OpenTitanRunner(code_dir)
    adk_tools = NidhoggADKTools(runner)

    if not code_dir.exists():
        log(f"Error: OpenTitan workspace code dir missing at {code_dir}")
        metadata.status = "FAILED"
        metadata.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(metadata_file, "w") as f:
            json.dump(metadata.to_dict(), f, indent=2)
        return False

    log(f"[+] Using OpenTitan source directory: {code_dir}")

    resolved_files = []
    if target_files:
        for tf in target_files:
            full_p = code_dir / tf
            if full_p.is_file():
                resolved_files.append(tf)
            elif full_p.is_dir():
                for c_file in full_p.glob("*.c"):
                    resolved_files.append(str(c_file.relative_to(code_dir)))
    if not resolved_files:
        resolved_files = DEFAULT_TARGET_FILES

    target_files = resolved_files
    log(f"[+] Target Source Files: {', '.join(target_files)}")

    # Load inputs & profile
    cwes = load_cwes()
    profile_data = load_profile(profile_name)

    log(f"[+] Loaded NCM Profile: '{profile_name}' ({profile_data.get('description', '')})")

    # Select NCM coordinates based on profile
    if profile_data.get("strategy") == "fixed" and "fixed_ncm" in profile_data:
        fixed = profile_data["fixed_ncm"]
        ncm = NCMCoordinate(
            spatial_scope=fixed.get("spatial_scope", "INTRA_PROCEDURAL"),
            temporal_depth=fixed.get("temporal_depth", "STATELESS"),
            domain_subtlety=fixed.get("domain_subtlety", "STANDARD_CWE")
        )
    else:
        ncm = NCMCoordinate(
            spatial_scope=random.choice(SPATIAL_SCOPES),
            temporal_depth=random.choice(TEMPORAL_DEPTHS),
            domain_subtlety=random.choice(DOMAIN_SUBTLETY_LEVELS)
        )

    # Sample random CWE
    cwe = random.choice(cwes)

    log(f"\n[+] Selected CWE: {cwe['id']} - {cwe['name']}")
    log(f"[+] NCM Coordinates: Spatial={ncm.spatial_scope}, Temporal={ncm.temporal_depth}, Subtlety={ncm.domain_subtlety}")
    log(f"[+] Target Files: {', '.join(target_files)}")

    # Record item status as IN_PROGRESS in metadata.json
    vuln_id = "VULN-001"
    item_status = VulnerabilityItemStatus(
        id=vuln_id,
        cwe_id=cwe["id"],
        cwe_name=cwe["name"],
        status="IN_PROGRESS",
        updated_at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    metadata.vulnerabilities.append(item_status.to_dict())
    with open(metadata_file, "w") as f:
        json.dump(metadata.to_dict(), f, indent=2)

    # Initial source inspection
    log("[+] Inspecting target source file headers...")
    initial_sources = ""
    for tf in target_files:
        initial_sources += f"\n--- File: {tf} ---\n" + adk_tools.read_source_file(tf, 1, 120) + "\n"

    # Construct System Instructions
    sys_instruction = f"""You are a principal security research engineer specializing in Root-of-Trust (RoT) firmware security.

Your goal is to introduce a REALISTIC, subtle vulnerability into target C firmware code.

CWE TARGET: {cwe['id']} ({cwe['name']})
CWE DESCRIPTION: {cwe.get('description', '')}

NCM CONSTRAINTS:
- Spatial Scope: {ncm.spatial_scope} ({SPATIAL_EXPLANATION.get(ncm.spatial_scope, '')})
- Temporal Depth: {ncm.temporal_depth} ({TEMPORAL_EXPLANATION.get(ncm.temporal_depth, '')})
- Domain Subtlety: {ncm.domain_subtlety} ({SUBTLETY_EXPLANATION.get(ncm.domain_subtlety, '')})

STRICT REALISM & PRODUCTION QUALITY RULES:
1. NO TOY/MAGIC CONSTANTS: Never use magic values like `0xdeadbeef`, `0x12345678`, or `0xbadc0de`.
2. NO VULNERABILITY COMMENTS: Do NOT insert comments mentioning "CWE", "VULNERABILITY", "BUG", "SECRET_LEAK", or any artificial tags.
3. NATURAL CODE MODIFICATIONS: The bug MUST be introduced by subtly altering valid control flow, miscalculating buffer sizes, modifying comparison operators, omitting necessary validation steps, or misinterpreting hardware register states.
4. STRICT COMPILATION: The code MUST compile cleanly under strict C -Werror flags. Do not leave unused helper functions or unhandled variables.
5. ALL EXISTING UNIT TESTS MUST PASS: The modified code MUST pass all existing unit tests in the build target suite (`run_build_check`). A patch that breaks existing unit tests or causes test assertions to fail is INVALID. If tests fail, read the test failure diagnostics, revert the workspace, fix your patch, and re-test!

MANDATORY REACT PROTOCOL:
1. Analyze the target code and construct a clean unified git diff with `--- a/path` and `+++ b/path` headers.
2. YOU MUST CALL `apply_patch(patch_diff)` tool first to test your patch application.
3. If `apply_patch` fails, call `read_source_file` to inspect exact line numbers, fix line counts in hunk headers, and call `apply_patch` again.
4. YOU MUST CALL `run_build_check(runner_target="{runner_target}")` tool to verify that the patch compiles under strict -Werror.
5. If `run_build_check` fails with compiler errors or warnings, call `revert_workspace()`, fix the syntax/logic in your diff, and re-test via `apply_patch` and `run_build_check`.
6. DO NOT output your final text response containing ```diff until `run_build_check` returns BUILD/TEST PASSED!
"""

    prompt = f"""ROOT-OF-TRUST SECURITY THREAT MODEL:
{GENERIC_ROT_THREAT_MODEL}

TARGET SOURCE FILES INITIAL INSPECTION:
{initial_sources}

Synthesize a realistic, production-quality patch diff modifying the target files, verify application and build via tools, and output the final verified diff block.
"""

    # Plain python functions as ADK tools
    adk_tools_list = [
        adk_tools.read_source_file,
        adk_tools.apply_patch,
        adk_tools.revert_workspace,
        adk_tools.run_build_check,
    ]

    # Instantiate Mjolnir's IsolatedAgent wrapper
    generator_agent = IsolatedAgent(
        name="NidhoggGeneratorAgent",
        model=model_name,
        instruction=sys_instruction,
        tools=adk_tools_list,
        before_tool_callback=make_tool_budget_callback(100),
        run_config=RunConfig(max_llm_calls=100),
    )

    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    session_service = InMemorySessionService()
    runner_engine = Runner(
        agent=generator_agent,
        app_name="nidhogg",
        session_service=session_service,
    )

    session = await session_service.create_session(
        app_name="nidhogg",
        user_id="nidhogg_user",
    )

    user_msg = types.Content(
        role="user",
        parts=[types.Part.from_text(text=prompt)],
    )

    log(f"\n[+] Launching ADK ReAct Generator Loop via Runner Engine...")

    final_diff = ""
    build_passed = False
    build_output = ""
    max_outer_retries = 5

    for outer_attempt in range(1, max_outer_retries + 1):
        log(f"\n--- ADK ReAct Engine Iteration {outer_attempt}/{max_outer_retries} ---")
        if outer_attempt == 1:
            curr_msg = types.Content(
                role="user",
                parts=[types.Part.from_text(text=prompt)],
            )
        else:
            feedback_prompt = f"""Your previous patch attempt failed unit tests or build checks.

LAST BUILD/TEST ERROR DIAGNOSTICS:
{build_output[:2500]}

INSTRUCTIONS FOR RETRY ATTEMPT {outer_attempt}:
1. If your patch is still applied, call `revert_workspace()`.
2. Inspect the file again using `read_source_file` to find a different function or subtle logic modification.
3. Apply a NEW patch for CWE-{cwe['id']} using `apply_patch`.
4. Run `run_build_check(runner_target="{runner_target}")` to verify that all unit tests pass!
"""
            curr_msg = types.Content(
                role="user",
                parts=[types.Part.from_text(text=feedback_prompt)],
            )

        try:
            # Run ADK Runner event stream loop
            for event in runner_engine.run(
                user_id="nidhogg_user",
                session_id=session.id,
                new_message=curr_msg,
            ):
                if hasattr(event, "content") and event.content and hasattr(event.content, "parts"):
                    for part in event.content.parts:
                        if hasattr(part, "text") and part.text:
                            text_val = part.text
                            log(f"[+] Agent Stream Message:\n{text_val[:250]}...")
                            if "```diff" in text_val or "--- a/" in text_val:
                                final_diff = clean_diff_output(text_val)

                        if hasattr(part, "function_call") and part.function_call:
                            log(f"[>] Tool Call: {part.function_call.name}({getattr(part.function_call, 'args', {})})")

                        if hasattr(part, "function_response") and part.function_response:
                            resp = part.function_response.response
                            resp_str = str(resp.get("result", "")) if isinstance(resp, dict) else str(resp)
                            log(f"[<] Tool Response ({part.function_response.name}):\n{resp_str[:300]}...")
                            if "BUILD/TEST PASSED!" in resp_str:
                                build_passed = True
                                build_output = resp_str
                                log("[+] Bazel build check PASSED!")
                            else:
                                build_output = resp_str
        except Exception as e:
            log(f"[-] ADK Engine Exception: {e}")

        if build_passed and final_diff:
            log(f"[+] Successfully generated and verified patch on iteration {outer_attempt}!")
            break

    # Revert workspace modifications
    runner.revert_workspace()

    # Update metadata status
    now_updated = datetime.datetime.now(datetime.timezone.utc).isoformat()
    metadata.updated_at = now_updated

    if build_passed and final_diff:
        metadata.completed_count += 1
        metadata.status = "COMPLETED"
        metadata.vulnerabilities[0]["status"] = "SUCCESS"
        metadata.vulnerabilities[0]["build_passed"] = True
    else:
        metadata.failed_count += 1
        metadata.status = "FAILED"
        metadata.vulnerabilities[0]["status"] = "FAILED"
        metadata.vulnerabilities[0]["build_passed"] = False
        metadata.vulnerabilities[0]["error_message"] = "ReAct agent failed to produce a passing patch diff."

    with open(metadata_file, "w") as f:
        json.dump(metadata.to_dict(), f, indent=2)

    if not final_diff or not build_passed:
        log("[-] ReAct agent did not produce a finalized passing patch diff.")
        return False

    # Serialize corpus item
    vuln_dir = dataset_dir / "vulns" / vuln_id
    vuln_dir.mkdir(parents=True, exist_ok=True)

    spec = VulnerabilitySpec(
        id=vuln_id,
        cwe_id=cwe["id"],
        cwe_name=cwe["name"],
        title=f"Synthetic {cwe['id']} in OpenTitan {target_files[0]}",
        description=f"Synthetic bug generated for {cwe['id']}: {cwe['name']}",
        ncm=ncm,
        target_files=target_files,
        patch_diff=final_diff,
        build_passed=build_passed,
        build_command=f"nix run ./projects/opentitan/nix -- test //sw/device/silicon_creator/lib/drivers:uart_unittest",
        build_output=build_output[:2000]
    )

    with open(vuln_dir / "vuln_manifest.json", "w") as f:
        json.dump(spec.to_dict(), f, indent=2)

    with open(vuln_dir / "patch.diff", "w") as f:
        f.write(final_diff)

    dataset_manifest = DatasetManifest(
        dataset_id=dataset_id,
        target_project=target_project,
        created_at=start_time_str,
        vulnerabilities=[vuln_id]
    )
    with open(dataset_dir / "dataset_manifest.json", "w") as f:
        json.dump(dataset_manifest.to_dict(), f, indent=2)

    log(f"\n[+] Saved reproducible synthetic vulnerability corpus item to:")
    log(f"    {vuln_dir / 'vuln_manifest.json'}")
    log(f"    {vuln_dir / 'patch.diff'}")
    log(f"    {metadata_file}")

    return build_passed


def run_adk_react_generator(
    target_project: str = "opentitan",
    dataset_id: str = "opentitan_v01",
    model_name: str = "gemini-2.5-flash",
    target_files: Optional[List[str]] = None,
    runner_target: str = DEFAULT_NIX_RUNNER_TARGET,
    profile_name: str = "trivial",
    overwrite_existing: bool = False
) -> bool:
    """Synchronous wrapper for run_adk_react_generator_async."""
    return asyncio.run(
        run_adk_react_generator_async(
            target_project=target_project,
            dataset_id=dataset_id,
            model_name=model_name,
            target_files=target_files,
            runner_target=runner_target,
            profile_name=profile_name,
            overwrite_existing=overwrite_existing
        )
    )


def main():
    parser = argparse.ArgumentParser(description="Nidhogg ADK ReAct Generator")
    parser.add_argument("--spec", type=str, help="Path to materialized nidhogg-job-spec.json")
    parser.add_argument("--overwrite", action="store_true", help="Force overwrite existing corpus metadata")
    args = parser.parse_args()

    if args.spec and os.path.exists(args.spec):
        with open(args.spec, "r") as f:
            spec_data = json.load(f)
        run_adk_react_generator(
            target_project=spec_data.get("projectName", "opentitan"),
            dataset_id=spec_data.get("datasetId", "opentitan_v01"),
            target_files=spec_data.get("srcDirs"),
            runner_target=spec_data.get("runnerTarget", DEFAULT_NIX_RUNNER_TARGET),
            profile_name=spec_data.get("profile", "trivial"),
            overwrite_existing=args.overwrite
        )
    else:
        run_adk_react_generator(overwrite_existing=args.overwrite)

if __name__ == "__main__":
    main()
