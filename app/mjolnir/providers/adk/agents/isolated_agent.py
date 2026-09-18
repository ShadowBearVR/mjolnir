# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
import json
import re
from typing import Any, Optional
from google.adk import Agent
from google.adk.agents.invocation_context import (
    InvocationContext,
    _InvocationCostManager,
)
from google.adk.agents.run_config import RunConfig
from google.adk.models import BaseLlm, LLMRegistry, LlmRequest
from google.adk.models.google_llm import Gemini
from google.genai import types

from constants import (
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_INITIAL_DELAY,
    DEFAULT_RETRY_MAX_DELAY,
)
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
            if getattr(llm_request.config, "thinking_config", None) is None:
                llm_request.config.thinking_config = types.ThinkingConfig(include_thoughts=True)
            if getattr(llm_request.config, "cached_content", None):
                llm_request.config.system_instruction = None
                llm_request.config.tools = None
                llm_request.config.tool_config = None


def resolve_model_with_retries(model: str | BaseLlm) -> BaseLlm:
    """Polymorphically ensures any model (string name or instantiated BaseLlm) has transport-level retry options configured."""
    # 1. If passed an already-instantiated BaseLlm
    if isinstance(model, BaseLlm):
        if hasattr(model, "retry_options") and getattr(model, "retry_options", None) is None:
            model.retry_options = DEFAULT_HTTP_RETRY_OPTIONS
        return model

    # 2. If passed a string model name, resolve class dynamically via ADK registry
    llm_class = LLMRegistry.resolve(model)
    if issubclass(llm_class, Gemini):
        return CachedGemini(model=model, retry_options=DEFAULT_HTTP_RETRY_OPTIONS)

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

    def _sanitize_structured_event(self, event: Any, tracker: Any = None) -> None:
        """Strips markdown code fences or surrounding prose from final model text parts before ADK schema validation."""
        if (
            not self.output_schema
            or (hasattr(event, "get_function_calls") and event.get_function_calls())
            or getattr(event, "partial", False)
            or not getattr(event, "content", None)
            or getattr(event.content, "role", None) != "model"
            or not getattr(event.content, "parts", None)
        ):
            return

        non_thought_parts = [
            p
            for p in event.content.parts
            if getattr(p, "text", None) and not getattr(p, "thought", False)
        ]
        if not non_thought_parts:
            return

        raw_text = "".join(p.text for p in non_thought_parts).strip()
        if not raw_text:
            return

        # Fast path: already valid raw JSON for output_schema
        try:
            self.output_schema.model_validate_json(raw_text)
            return
        except Exception:
            pass

        # Extract fenced ```json { ... } ``` block or outermost JSON object
        fenced_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", raw_text, flags=re.DOTALL)
        if fenced_match:
            candidate = fenced_match.group(1).strip()
        else:
            start = raw_text.find("{")
            end = raw_text.rfind("}")
            candidate = raw_text[start : end + 1].strip() if (start != -1 and end > start) else ""

        if candidate:
            try:
                data = json.loads(candidate)
                if (
                    isinstance(data, dict)
                    and "vulnerabilities" not in data
                    and isinstance(data.get("findings"), list)
                ):
                    data["vulnerabilities"] = data.pop("findings")
                validated = self.output_schema.model_validate(data)
                non_thought_parts[0].text = validated.model_dump_json()
                for extra_part in non_thought_parts[1:]:
                    extra_part.text = ""
                return
            except Exception as e:
                logger.debug(f"Could not coerce fenced JSON for {self.name}: {e}")

        # Unparseable prose when structured output_schema was required: record error and clear text
        # so ADK's process_llm_agent_output sets output=None instead of raising ValidationError.
        schema_name = getattr(self.output_schema, "__name__", str(self.output_schema))
        logger.warning(
            f"Agent {self.name} returned non-JSON text instead of {schema_name}; suppressing crash."
        )
        if tracker:
            tracker.track_error(
                ValueError(f"SchemaValidationError: {schema_name}"),
                self.name,
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
