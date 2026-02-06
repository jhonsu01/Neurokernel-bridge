from __future__ import annotations
from typing import Optional
import structlog
import httpx

from ..config import MemoryConfig

logger = structlog.get_logger("claude_mem")


class ClaudeMemBridge:
    """Communicates with claude-mem worker service via HTTP API."""

    def __init__(self, config: MemoryConfig):
        self.base_url = config.claude_mem_api_url
        self.enabled = config.enable_claude_mem
        self._client: Optional[httpx.Client] = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=10.0,
            )
        return self._client

    def search_context(self, query: str, limit: int = 5) -> list[dict]:
        if not self.enabled:
            return []
        try:
            resp = self.client.get(
                "/api/search",
                params={"q": query, "limit": limit},
            )
            resp.raise_for_status()
            return resp.json().get("results", [])
        except httpx.HTTPError as e:
            logger.warning("claude_mem_search_failed", error=str(e))
            return []

    def push_observation(self, observation: dict) -> None:
        if not self.enabled:
            return
        try:
            self.client.post("/api/observation", json=observation)
        except httpx.HTTPError as e:
            logger.warning("claude_mem_push_failed", error=str(e))

    def load_session_context(self) -> str:
        results = self.search_context(
            "linux security monitoring kernel eBPF threat detection"
        )
        if not results:
            return ""
        parts = []
        for r in results:
            title = r.get("title", "")
            narrative = r.get("narrative", "")
            if title or narrative:
                parts.append(f"- {title}: {narrative}")
        return "\n".join(parts)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
