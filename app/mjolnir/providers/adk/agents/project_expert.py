# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
"""Project Expert Agent definition for ADK."""

from google.adk import Agent
from google.adk.agents.run_config import RunConfig
from google.genai import types

from agent_tools.ast_search import ast_search
from agent_tools.ctags_search import ctags_search
from agent_tools.glob import glob
from agent_tools.grep_search import grep_search
from agent_tools.read_file import read_file
from constants import PROJECT_EXPERT_MAX_LLM_CALLS
from providers.adk.agents.isolated_agent import IsolatedAgent
from utilities.prompt_loader import prompt_registry


def build_project_expert_instruction(threat_model_context: str = "") -> str:
    """Builds the system instruction for the ProjectExpertAgent."""
    instruction = prompt_registry.load_prompt("project_expert") + "\n\n"

    if threat_model_context:
        instruction += threat_model_context
    return instruction


def get_project_expert_agent(
    model: str,
    threat_model_context: str = "",
    cached_content: str | None = None,
) -> Agent:
    """Factory to create a ProjectExpertAgent with read-only tools and optional cached content."""
    instruction = build_project_expert_instruction(threat_model_context)
    generate_content_config = (
        types.GenerateContentConfig(cached_content=cached_content) if cached_content else None
    )

    return IsolatedAgent(
        name="ProjectExpertAgent",
        model=model,
        instruction=instruction,
        generate_content_config=generate_content_config,
        tools=[read_file, glob, grep_search, ctags_search, ast_search],
        run_config=RunConfig(max_llm_calls=PROJECT_EXPERT_MAX_LLM_CALLS),
    )
