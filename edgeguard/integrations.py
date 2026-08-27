import functools
from typing import Generator, Any
from edgeguard import EdgeGuard

class GuardrailViolationException(Exception):
    def __init__(self, violation_code: int, reason: str):
        self.violation_code = violation_code
        self.reason = reason
        super().__init__(f"Guardrail violation [{violation_code}]: {reason}")

def wrap_ollama_stream(stream_gen: Generator, window_size: int = 256) -> Generator:
    """Wraps an Ollama generator stream with real-time sub-microsecond scanning."""
    guard = EdgeGuard()
    scanner = guard.create_stream_scanner(window_size=window_size)

    for chunk in stream_gen:
        token = ""
        if isinstance(chunk, dict):
            token = chunk.get("message", {}).get("content", "") or chunk.get("response", "")
        elif hasattr(chunk, "message") and hasattr(chunk.message, "content"):
            token = chunk.message.content or ""
        elif hasattr(chunk, "response"):
            token = chunk.response or ""

        if token:
            check = scanner.feed_token(token)
            if not check["is_safe"]:
                raise GuardrailViolationException(check["violation_code"], check["reason"])

        yield chunk

def guard_prompt(prompt: str) -> None:
    """Validates prompt input before sending to LLM. Raises exception if unsafe."""
    guard = EdgeGuard()
    check = guard.scan(prompt)
    if not check["is_safe"]:
        raise GuardrailViolationException(check["violation_code"], check["reason"])
