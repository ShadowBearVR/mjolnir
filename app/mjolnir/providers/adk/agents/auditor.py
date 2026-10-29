# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
import os
import pathlib

from google.adk import Agent
from google.adk.agents.run_config import RunConfig

from google.genai import types

from agent_tools import format_tool_guidance
from agent_tools.ast_search import ast_search
from agent_tools.ctags_search import ctags_search
from agent_tools.glob import glob
from agent_tools.grep_search import grep_search
from agent_tools.project_expert import ask_project_expert
from agent_tools.read_file import read_file
from agent_tools.search_cwe import search_cwe
from constants import AUDITOR_MAX_LLM_CALLS, PROJECT_ARCHITECTURE_SECTION_TEMPLATE
from data.security_report import SecurityReport
from providers.adk.agents.isolated_agent import IsolatedAgent
from utilities.prompt_loader import prompt_registry

AUDITOR_TOOLS = [ctags_search, ast_search, grep_search, glob, read_file, search_cwe]

_EXTENSION_TO_SKILL: dict[str, str] = {
    "c": "c-audit-skill",
    "h": "c-audit-skill",
    "cc": "c-audit-skill",
    "cpp": "c-audit-skill",
    "cxx": "c-audit-skill",
    "hpp": "c-audit-skill",
    "hh": "c-audit-skill",
    "rs": "rust-audit-skill",
    "sv": "sv-audit-skill",
    "svh": "sv-audit-skill",
    "v": "sv-audit-skill",
    "vh": "sv-audit-skill",
}

_ALL_SKILL_NAMES: tuple[str, ...] = (
    "c-audit-skill",
    "rust-audit-skill",
    "sv-audit-skill",
)


def _resolve_skill_names(extensions: set[str] | list[str] | tuple[str, ...] | None) -> list[str]:
    """Resolves ordered, deduplicated language skill directory names for the active file extensions."""
    if not extensions:
        return list(_ALL_SKILL_NAMES)
    normalized = {str(ext).lstrip(".").lower() for ext in extensions if str(ext).strip()}
    if not normalized:
        return list(_ALL_SKILL_NAMES)
    selected: list[str] = []
    for ext in sorted(normalized):
        skill_name = _EXTENSION_TO_SKILL.get(ext)
        if skill_name and skill_name not in selected:
            selected.append(skill_name)
    return selected


def get_auditor_tools(enable_project_expert: bool = False) -> list:
    """Builds the toolset for AuditorAgent, appending optional capability tools as enabled."""
    tools = list(AUDITOR_TOOLS)
    if enable_project_expert:
        tools.append(ask_project_expert)
    return tools


def build_auditor_instruction(
    threat_model_context: str = "",
    project_expert_summary: str = "",
    tools: list | None = None,
    extensions: set[str] | list[str] | tuple[str, ...] | None = None,
) -> str:
    """Builds the full, deterministic system instruction for the AuditorAgent."""
    active_tools = tools if tools is not None else AUDITOR_TOOLS
    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw_prompt = prompt_registry.load_prompt("auditor")
    instruction = raw_prompt.replace("{tool_guidance}", format_tool_guidance(active_tools)) + "\n\n"

    if threat_model_context:
        instruction += threat_model_context

    if project_expert_summary:
        instruction += PROJECT_ARCHITECTURE_SECTION_TEMPLATE.format(
            project_expert_summary=project_expert_summary
        )

    skills_dir = pathlib.Path(current_dir) / "skills"
    for skill_name in _resolve_skill_names(extensions):
        skill_path = skills_dir / skill_name / "SKILL.md"
        if skill_path.exists():
            instruction += f"\n\n{skill_path.read_text(encoding='utf-8')}\n"
    return instruction


def get_auditor_agent(
    model: str,
    threat_model_context: str = "",
    project_expert_summary: str = "",
    cached_content: str | None = None,
    enable_project_expert: bool = False,
    extensions: set[str] | list[str] | tuple[str, ...] | None = None,
) -> Agent:
    """Factory to create an AuditorAgent with appropriate system prompts and optional cached content."""
    tools = get_auditor_tools(enable_project_expert=enable_project_expert)
    instruction = build_auditor_instruction(
        threat_model_context,
        project_expert_summary,
        tools=tools,
        extensions=extensions,
    )
    generate_content_config = (
        types.GenerateContentConfig(cached_content=cached_content) if cached_content else None
    )

    return IsolatedAgent(
        name="AuditorAgent",
        model=model,
        instruction=instruction,
        tools=tools,
        output_schema=SecurityReport,
        generate_content_config=generate_content_config,
        run_config=RunConfig(max_llm_calls=AUDITOR_MAX_LLM_CALLS),
    )
