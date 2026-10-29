# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
import asyncio
import functools

from constants import DEFAULT_TOOL_OUTPUT_MAX_CHARS


def _truncate(result: object, max_chars: int) -> object:
    if isinstance(result, str) and len(result) > max_chars:
        half = max_chars // 2
        omitted = len(result) - max_chars
        truncated_info = (
            f"\n\n... [Observation truncated: omitted {omitted} middle characters "
            f"(limit {max_chars} chars, ~{max_chars // 4} tokens). "
            f"Showing first {half} and last {max_chars - half} characters.] ...\n\n"
        )
        return result[:half] + truncated_info + result[-(max_chars - half) :]
    return result


def limit_tool_output(
    func=None,
    *,
    max_chars: int = DEFAULT_TOOL_OUTPUT_MAX_CHARS,
):
    """Decorator to truncate tool output if it exceeds max_chars.

    Supports both bare decorator `@limit_tool_output` and parametrized `@limit_tool_output(max_chars=...)`.
    """

    def decorator(fn):
        if asyncio.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                return _truncate(await fn(*args, **kwargs), max_chars)

            return async_wrapper
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                return _truncate(fn(*args, **kwargs), max_chars)

            return sync_wrapper

    if func is not None:
        return decorator(func)
    return decorator
