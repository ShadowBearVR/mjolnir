# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Phase 0: Project-wide Exploration by the Project Expert Agent."""

import asyncio
from pathlib import Path
from typing import Any

from google.adk import Context
from google.adk.workflow import node

from providers.adk.agents.project_expert import get_project_expert_agent
from providers.adk.utilities.async_runner import run_agent_node
from utilities.logger import logger


@node(rerun_on_resume=True)
async def project_exploration_phase(ctx: Context, node_input: Any) -> Any:
    """Phase 0: Project-wide Exploration.

    Initializes the Project Expert Agent, performs initial high-level reconnaissance
    over the target codebase, and stores the exploration summary in session state for
    downstream agents and the `ask_project_expert` tool.
    """
    logger.info("Starting Phase 0: Project-wide Exploration (Project Expert)...")

    model = ctx.state["model"]
    code_dir = ctx.state["code_dir"]
    threat_model = ctx.state["threat_model_context"]

    expert_agent = get_project_expert_agent(model, threat_model)

    exploration_prompt = (
        f"Project Root Directory: {code_dir}\n\n"
        "Please perform an initial architectural reconnaissance of this project:\n"
        "1. Inspect the top-level directory structure, READMEs, architecture documents, and build files.\n"
        "2. Identify the major subsystems, execution phases (e.g. boot, ROM, runtime), and hardware interfaces.\n"
        "3. Review the project threat model boundaries against the codebase layout.\n"
        "4. Synthesize a concise architectural overview summarizing the system design, key invariants, "
        "and intended security controls.\n\n"
        "This summary will be cached and used to provide context to specialized auditor and reviewer agents."
    )

    try:
        res = await run_agent_node(
            ctx,
            expert_agent,
            node_input=exploration_prompt,
            run_id="project_exploration",
        )
        summary = (
            getattr(res, "output", None)
            or getattr(res, "text", None)
            or (str(res) if res is not None else "")
        )
        ctx.state["project_expert_summary"] = summary.strip()
        logger.info("Project-wide exploration complete. Architectural context cached.")

        run_dir = ctx.state.get("run_dir")
        if run_dir and summary:
            summary_path = Path(run_dir) / "project_expert_summary.md"
            await asyncio.to_thread(summary_path.write_text, summary.strip(), encoding="utf-8")
            logger.info(f"Saved project expert summary to {summary_path}")
    except Exception as e:
        logger.warning(
            f"Project-wide exploration encountered an error ({e}). Proceeding with baseline state."
        )
        ctx.state["project_expert_summary"] = ""

    # Pass through the node_input (e.g. list of files or ingest path) to the next phase
    return node_input
