# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
import asyncio
from functools import cached_property
import json
import os
import random
import re
from typing import Any, Optional
from google.adk import Agent
from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.agents.invocation_context import (
    InvocationContext,
    _InvocationCostManager,
)
from google.adk.agents.run_config import RunConfig
from google.adk.models import BaseLlm, LLMRegistry, LlmRequest
from google.adk.models.anthropic_llm import Claude
from google.adk.models.google_llm import Gemini
from google.adk.tools.set_model_response_tool import SetModelResponseTool
from google.genai import types

LLMRegistry.register(Claude)
try:
    from google.adk.telemetry import _otel_compat

    if not hasattr(_otel_compat.GenAiSystemValues, "ANTHROPIC"):
        _otel_compat.GenAiSystemValues.ANTHROPIC = _otel_compat.DummyAttr("anthropic")
except Exception:
    pass

from constants import (
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_INITIAL_DELAY,
    DEFAULT_RETRY_MAX_DELAY,
)
from providers.adk.utilities.cache_manager import PhaseContextCache
from utilities.logger import logger

# Default transport-level retry configuration for LLM calls (exponential backoff with jitter)
DEFAULT_HTTP_RETRY_OPTIONS = types.HttpRetryOptions(
    attempts=DEFAULT_RETRY_ATTEMPTS,
    initial_delay=DEFAULT_RETRY_INITIAL_DELAY,
    max_delay=DEFAULT_RETRY_MAX_DELAY,
)


class CachedGemini(Gemini):
    """ADK Gemini model wrapper that correctly handles Vertex AI explicit cached content and enables thinking trace visibility."""

    async def _preprocess_request(self, llm_request: LlmRequest) -> None:
        await super()._preprocess_request(llm_request)
        if llm_request.config:
            if cc := getattr(llm_request.config, "cached_content", None):
                llm_request.config.cached_content = PhaseContextCache._replacements.get(cc, cc)
            resp_schema = getattr(llm_request.config, "response_schema", None)
            if resp_schema and "set_model_response" not in llm_request.tools_dict:
                llm_request.tools_dict["set_model_response"] = SetModelResponseTool(resp_schema)
            if getattr(llm_request.config, "thinking_config", None) is None:
                llm_request.config.thinking_config = types.ThinkingConfig(include_thoughts=True)
            if getattr(llm_request.config, "cached_content", None):
                llm_request.config.system_instruction = None
                llm_request.config.tools = None
                llm_request.config.tool_config = None
            else:
                if getattr(llm_request.config, "safety_settings", None) is None:
                    llm_request.config.safety_settings = [
                        types.SafetySetting(
                            category=cat,
                            threshold=types.HarmBlockThreshold.OFF,
                        )
                        for cat in (
                            types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                            types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                            types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                            types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                        )
                    ]
                if getattr(llm_request.config, "tools", None):
                    # Ensure function declarations (such as set_model_response) are never duplicated by name
                    for tool_entry in llm_request.config.tools:
                        if fns := getattr(tool_entry, "function_declarations", None):
                            tool_entry.function_declarations = list(
                                {getattr(f, "name", id(f)): f for f in fns}.values()
                            )

    @staticmethod
    def _has_declared_tool(llm_request: LlmRequest, tool_name: str) -> bool:
        cfg = getattr(llm_request, "config", None)
        for tool_entry in getattr(cfg, "tools", None) or []:
            for fn in getattr(tool_entry, "function_declarations", None) or []:
                if getattr(fn, "name", None) == tool_name:
                    return True
        return False

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False):
        cfg = llm_request.config
        orig_si = getattr(cfg, "system_instruction", None)
        orig_tools = getattr(cfg, "tools", None)
        orig_tool_cfg = getattr(cfg, "tool_config", None)
        has_smr_decl = self._has_declared_tool(llm_request, "set_model_response")
        try:
            async for resp in super().generate_content_async(llm_request, stream=stream):
                err_code = str(getattr(resp, "error_code", "") or "")
                if (
                    "SAFETY" in err_code
                    and isinstance(getattr(llm_request, "contents", None), list)
                    and len(llm_request.contents) >= 3
                ):
                    logger.warning(
                        f"Mid-session SAFETY block ({err_code}); stripping last tool turn and requesting immediate final report."
                    )
                    while len(llm_request.contents) > 1 and getattr(
                        llm_request.contents[-1], "role", None
                    ) in ("user", "model"):
                        last_role = getattr(llm_request.contents[-1], "role", None)
                        llm_request.contents.pop()
                        if last_role == "model":
                            break
                    llm_request.contents.append(
                        types.Content(
                            role="user",
                            parts=[
                                types.Part.from_text(
                                    text=(
                                        "IMPORTANT: The previous file read triggered a content filter and was omitted. "
                                        "Do NOT call `glob`, `grep_search`, or `read_file` again. "
                                        "Immediately output your final structured JSON `SecurityReport` containing all vulnerabilities identified so far."
                                    )
                                )
                            ],
                        )
                    )
                    if not getattr(llm_request.config, "cached_content", None):
                        if has_smr_decl:
                            llm_request.config.tool_config = types.ToolConfig(
                                function_calling_config=types.FunctionCallingConfig(
                                    mode="ANY",
                                    allowed_function_names=["set_model_response"],
                                )
                            )
                        else:
                            llm_request.config.tool_config = types.ToolConfig(
                                function_calling_config=types.FunctionCallingConfig(
                                    mode="NONE",
                                )
                            )
                    async for retry_resp in super().generate_content_async(
                        llm_request, stream=stream
                    ):
                        yield retry_resp
                    return
                resp_parts = getattr(getattr(resp, "content", None), "parts", None) or []
                has_fc = any(getattr(p, "function_call", None) for p in resp_parts)
                if (
                    not stream
                    and not err_code
                    and not getattr(resp, "partial", False)
                    and not has_fc
                    and has_smr_decl
                    and isinstance(getattr(llm_request, "contents", None), list)
                ):
                    logger.warning(
                        "Tool-equipped agent stopped without calling set_model_response; forcing set_model_response tool call."
                    )
                    if resp_parts:
                        llm_request.contents.append(resp.content)
                    llm_request.contents.append(
                        types.Content(
                            role="user",
                            parts=[
                                types.Part.from_text(
                                    text=(
                                        "IMPORTANT: You must provide your final structured response by calling the "
                                        "`set_model_response` tool. Immediately call `set_model_response` with all "
                                        "vulnerabilities identified in your audit."
                                    )
                                )
                            ],
                        )
                    )
                    if not getattr(llm_request.config, "cached_content", None):
                        llm_request.config.tool_config = types.ToolConfig(
                            function_calling_config=types.FunctionCallingConfig(
                                mode="ANY",
                                allowed_function_names=["set_model_response"],
                            )
                        )
                    async for retry_resp in super().generate_content_async(
                        llm_request, stream=stream
                    ):
                        yield retry_resp
                    return
                yield resp
        except Exception as e:
            cache_id = getattr(cfg, "cached_content", None)
            if not cache_id or "is expired" not in str(e).lower():
                raise
            cache = PhaseContextCache._instances.get(cache_id)
            new_cache_id = cache.create() if cache else None
            PhaseContextCache._replacements[cache_id] = new_cache_id
            logger.warning(
                f"Context cache {cache_id} expired; "
                + (
                    f"re-initialized as {new_cache_id}"
                    if new_cache_id
                    else "falling back to uncached inference"
                )
            )
            cfg.cached_content = new_cache_id
            cfg.system_instruction = orig_si
            cfg.tools = orig_tools
            cfg.tool_config = orig_tool_cfg
            async for resp in super().generate_content_async(llm_request, stream=stream):
                yield resp


class CachedClaude(Claude):
    """ADK Claude-on-Vertex wrapper with automatic ADC project resolution, prompt caching, adaptive thinking, and retry backoff."""

    max_tokens: int = 16384

    @cached_property
    def _anthropic_client(self):
        if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
            try:
                import google.auth

                _, proj = google.auth.default()
                if proj:
                    os.environ["GOOGLE_CLOUD_PROJECT"] = proj
            except Exception:
                pass
        if not os.environ.get("GOOGLE_CLOUD_LOCATION"):
            os.environ["GOOGLE_CLOUD_LOCATION"] = "global"
        return super()._anthropic_client

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False):
        if llm_request.cache_config is None:
            llm_request.cache_config = ContextCacheConfig(min_tokens=1024, ttl_seconds=300)
        if llm_request.config:
            llm_request.config.cached_content = None
            resp_schema = getattr(llm_request.config, "response_schema", None)
            if resp_schema and "set_model_response" not in llm_request.tools_dict:
                llm_request.tools_dict["set_model_response"] = SetModelResponseTool(resp_schema)
            if getattr(llm_request.config, "thinking_config", None) is None:
                llm_request.config.thinking_config = types.ThinkingConfig(
                    include_thoughts=True, thinking_budget=-1
                )
            if getattr(llm_request.config, "tools", None):
                for tool_entry in llm_request.config.tools:
                    if fns := getattr(tool_entry, "function_declarations", None):
                        tool_entry.function_declarations = list(
                            {getattr(f, "name", id(f)): f for f in fns}.values()
                        )

        delay = float(DEFAULT_RETRY_INITIAL_DELAY)
        for attempt in range(1, DEFAULT_RETRY_ATTEMPTS + 1):
            try:
                async for resp in super().generate_content_async(llm_request, stream=stream):
                    um = getattr(resp, "usage_metadata", None)
                    parts = getattr(getattr(resp, "content", None), "parts", None) or []
                    if (
                        um is not None
                        and not getattr(resp, "partial", False)
                        and getattr(um, "thoughts_token_count", None) is None
                        and (um.candidates_token_count or 0) > 0
                    ):
                        thought_chars = sum(
                            len(getattr(p, "text", "") or "")
                            for p in parts
                            if getattr(p, "thought", False)
                        )
                        if thought_chars > 0:
                            out_chars = sum(
                                len(getattr(p, "text", "") or "")
                                + (
                                    len(json.dumps(p.function_call.args or {}))
                                    + len(p.function_call.name or "")
                                    if getattr(p, "function_call", None)
                                    else 0
                                )
                                for p in parts
                                if not getattr(p, "thought", False)
                            )
                            tot_out = int(um.candidates_token_count or 0)
                            tot_chars = thought_chars + out_chars
                            est_think = (
                                max(1, int(round(tot_out * (thought_chars / tot_chars))))
                                if tot_chars > 0
                                else 0
                            )
                            est_think = min(tot_out, est_think)
                            um.thoughts_token_count = est_think
                            um.candidates_token_count = tot_out - est_think
                    yield resp
                return
            except Exception as e:
                status = getattr(e, "status_code", None)
                retryable = status in (408, 429, 500, 502, 503, 504, 529) or any(
                    tok in str(e).lower()
                    for tok in ("rate limit", "overloaded", "timeout", "connection", "529", "429")
                )
                if not retryable or attempt >= DEFAULT_RETRY_ATTEMPTS:
                    raise
                sleep_s = min(float(DEFAULT_RETRY_MAX_DELAY), delay) * (
                    0.75 + 0.5 * random.random()
                )
                logger.warning(
                    f"Claude API transient error (attempt {attempt}/{DEFAULT_RETRY_ATTEMPTS}): {e}; retrying in {sleep_s:.1f}s"
                )
                await asyncio.sleep(sleep_s)
                delay *= 2.0


def resolve_model_with_retries(model: str | BaseLlm) -> BaseLlm:
    """Polymorphically ensures any model (string name or instantiated BaseLlm) has transport-level retry options configured."""
    # 1. If passed an already-instantiated BaseLlm
    if isinstance(model, BaseLlm):
        if hasattr(model, "retry_options") and getattr(model, "retry_options", None) is None:
            model.retry_options = DEFAULT_HTTP_RETRY_OPTIONS
        return model

    # 2. If passed a string model name, resolve class dynamically via ADK registry
    if isinstance(model, str) and model.startswith("vertex_ai/claude-"):
        model = model.split("/", 1)[1]
    llm_class = LLMRegistry.resolve(model)
    if issubclass(llm_class, Gemini):
        return CachedGemini(model=model, retry_options=DEFAULT_HTTP_RETRY_OPTIONS)
    if issubclass(llm_class, Claude):
        return CachedClaude(model=model)

    # 3. Duck-type check if this provider class accepts `retry_options`
    if "retry_options" in getattr(llm_class, "model_fields", {}):
        return llm_class(model=model, retry_options=DEFAULT_HTTP_RETRY_OPTIONS)

    # 4. Fallback for non-retry-options providers
    return llm_class(model=model)


class IsolatedAgent(Agent):
    """An ADK Agent that isolates its LLM call counter and cost manager from the parent workflow session."""

    run_config: Optional[RunConfig] = None

    def __init__(self, **kwargs):
        if "model" in kwargs:
            kwargs["model"] = resolve_model_with_retries(kwargs["model"])
        super().__init__(**kwargs)

    def _create_invocation_context(self, parent_context: InvocationContext) -> InvocationContext:
        ctx = super()._create_invocation_context(parent_context)
        ctx._invocation_cost_manager = _InvocationCostManager()
        if self.run_config:
            ctx.run_config = self.run_config
        return ctx

    async def canonical_instruction(self, ctx: Any) -> tuple[str, bool]:
        """Bypasses ADK session state template substitution on instruction string.

        ADK attempts regex {var} variable substitution on agent instruction strings by default,
        which raises KeyError when code snippets containing curly braces appear in instructions.
        Returning bypass_state_injection=True disables this behavior.
        """
        raw_si, _ = await super().canonical_instruction(ctx)
        return raw_si, True

    def _is_final_model_text_event(self, event: Any) -> bool:
        """Returns True if event is a completed final model response requiring schema validation."""
        return bool(
            self.output_schema
            and not (hasattr(event, "get_function_calls") and event.get_function_calls())
            and not getattr(event, "partial", False)
            and getattr(event, "content", None)
            and getattr(event.content, "role", None) == "model"
            and getattr(event.content, "parts", None)
        )

    @staticmethod
    def _extract_json_candidates(raw_text: str) -> list[str]:
        """Extracts JSON object candidates from markdown code fences (last-to-first) or surrounding text."""
        candidates: list[str] = []
        # Match JSON objects wrapped in markdown code fences, e.g.:
        # ```json
        # {"vulnerabilities": [...]}
        # ```
        fenced_blocks = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, flags=re.DOTALL)
        for block in reversed(fenced_blocks):
            if stripped := block.strip():
                candidates.append(stripped)

        # Fallback for unfenced JSON surrounded by prose (e.g. "Here is the report: {...} Done."):
        # slice from the first '{' through the last '}' (inclusive via `end + 1` to keep `{...}`).
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start != -1 and end > start:
            outer = raw_text[start : end + 1].strip()
            if outer not in candidates:
                candidates.append(outer)
            # Also handle truncated JSON arrays of objects: {"vulnerabilities": [ {...}, {...}, {truncated...
            if not outer.endswith("]}") and ('"vulnerabilities"' in outer or '"findings"' in outer):
                repaired = outer.rstrip().rstrip(",") + "]}"
                if repaired not in candidates:
                    candidates.append(repaired)
        return candidates

    def _coerce_to_schema_json(self, raw_text: str) -> Optional[str]:
        """Validates raw_text or an extracted JSON candidate against self.output_schema."""
        try:
            self.output_schema.model_validate_json(raw_text)
            return raw_text
        except Exception:
            pass

        for candidate in self._extract_json_candidates(raw_text):
            try:
                data = json.loads(candidate)
                if (
                    isinstance(data, dict)
                    and "vulnerabilities" not in data
                    and isinstance(data.get("findings"), list)
                ):
                    data["vulnerabilities"] = data.pop("findings")
                try:
                    validated = self.output_schema.model_validate(data)
                    return validated.model_dump_json()
                except Exception:
                    # Item-by-item fallback for SecurityReport so one unrecognized CWE doesn't drop all findings
                    if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), list):
                        valid_items = []
                        for item in data["vulnerabilities"]:
                            if not isinstance(item, dict):
                                continue
                            try:
                                single = self.output_schema.model_validate(
                                    {"vulnerabilities": [item]}
                                )
                                valid_items.extend(single.vulnerabilities)
                            except Exception:
                                item_copy = dict(item)
                                item_copy["cwe"] = ""
                                try:
                                    single = self.output_schema.model_validate(
                                        {"vulnerabilities": [item_copy]}
                                    )
                                    valid_items.extend(single.vulnerabilities)
                                except Exception:
                                    pass
                        if valid_items or not data["vulnerabilities"]:
                            validated = self.output_schema.model_validate(
                                {"vulnerabilities": valid_items}
                            )
                            return validated.model_dump_json()
                    raise
            except Exception as e:
                logger.debug(f"Could not coerce fenced JSON candidate for {self.name}: {e}")
        return None

    def _sanitize_structured_event(self, event: Any, tracker: Any = None) -> None:
        """Normalizes model text parts to valid schema JSON before ADK processes output_schema."""
        if not self._is_final_model_text_event(event):
            return

        non_thought_parts = [
            p
            for p in event.content.parts
            if getattr(p, "text", None) and not getattr(p, "thought", False)
        ]
        raw_text = "".join(p.text for p in non_thought_parts).strip()
        if not raw_text:
            return

        coerced_json = self._coerce_to_schema_json(raw_text)
        if coerced_json is not None:
            non_thought_parts[0].text = coerced_json
            for extra_part in non_thought_parts[1:]:
                extra_part.text = ""
            return

        schema_name = getattr(self.output_schema, "__name__", str(self.output_schema))
        logger.warning(
            f"Agent {self.name} returned non-JSON text instead of {schema_name} "
            f"(len={len(raw_text)}, preview={raw_text[:200]!r}); suppressing crash."
        )
        if tracker is not None and hasattr(tracker, "reasoning_log"):
            _, _, target_key = tracker._resolve_event_keys(event, self.name)
            tracker.reasoning_log.setdefault(target_key, []).append(
                {
                    "agent": self.name,
                    "type": "uncoerced_output",
                    "content": raw_text,
                }
            )
        for part in non_thought_parts:
            part.text = ""

    async def run_async(self, parent_context: InvocationContext):
        tracker = getattr(parent_context.session, "state", {}).get("usage_tracker")
        async for event in super().run_async(parent_context):
            if tracker:
                tracker.track_event(event, agent_name=self.name)
            if self.output_schema:
                self._sanitize_structured_event(event, tracker)
            yield event
