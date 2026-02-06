from __future__ import annotations
import json
import time
from collections import deque
from datetime import datetime
from typing import Optional

import anthropic

from ..models import (
    BaseEvent, Decision, DecisionTier, DecisionResult,
)
from ..config import DecisionConfig


class LLMEngine:
    """Tier 3: Claude API for ambiguous events. Rate limited."""

    def __init__(self, config: DecisionConfig):
        self.config = config
        self.model = config.anthropic_model
        self.max_calls = config.max_api_calls_per_minute
        self.timeout = config.api_timeout_seconds
        self._call_timestamps: deque[float] = deque(maxlen=self.max_calls)
        self._client: Optional[anthropic.Anthropic] = None

    @property
    def client(self) -> anthropic.Anthropic:
        if self._client is None:
            self._client = anthropic.Anthropic(
                api_key=self.config.anthropic_api_key,
                timeout=self.timeout,
            )
        return self._client

    def _check_rate_limit(self) -> bool:
        now = time.time()
        while self._call_timestamps and (now - self._call_timestamps[0]) > 60:
            self._call_timestamps.popleft()
        if len(self._call_timestamps) >= self.max_calls:
            return False
        self._call_timestamps.append(now)
        return True

    def escalate(self, event: BaseEvent) -> DecisionResult:
        if not self.config.anthropic_api_key:
            return self._fallback(event, "No API key configured")

        if not self._check_rate_limit():
            return self._fallback(event, "Rate limited")

        prompt = self._build_prompt(event)
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=150,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}],
                system=(
                    "You are a Linux kernel security analyst. Classify system events. "
                    "Respond with ONLY a JSON object: "
                    '{"decision": "SAFE" or "LIMIT" or "MALICIOUS", '
                    '"confidence": 0.0 to 1.0, '
                    '"reasoning": "brief explanation"}'
                ),
            )
            return self._parse_response(event, response)
        except anthropic.APITimeoutError:
            return self._fallback(event, "API timeout")
        except anthropic.APIError as e:
            return self._fallback(event, f"API error: {e}")
        except Exception as e:
            return self._fallback(event, f"Unexpected error: {e}")

    def _build_prompt(self, event: BaseEvent) -> str:
        event_data = event.model_dump(exclude={"timestamp"})
        return (
            f"Analyze this Linux kernel security event:\n"
            f"- Dimension: {event.dimension.name}\n"
            f"- Process: {event.comm} (PID: {event.pid}, UID: {event.uid})\n"
            f"- Details: {json.dumps(event_data, default=str)}\n"
            f"\nClassify as SAFE, LIMIT, or MALICIOUS."
        )

    def _parse_response(self, event: BaseEvent, response) -> DecisionResult:
        text = response.content[0].text.strip()
        try:
            data = json.loads(text)
            decision_str = data.get("decision", "SAFE").upper()
            decision_map = {"SAFE": Decision.SAFE, "LIMIT": Decision.LIMIT, "MALICIOUS": Decision.MALICIOUS}
            decision = decision_map.get(decision_str, Decision.SAFE)
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
            reasoning = data.get("reasoning", "LLM classification")
        except (json.JSONDecodeError, KeyError, ValueError):
            decision = Decision.SAFE
            confidence = 0.4
            reasoning = f"Failed to parse LLM response: {text[:100]}"

        return DecisionResult(
            event=event, decision=decision, tier=DecisionTier.LLM,
            confidence=confidence, reasoning=reasoning, timestamp=datetime.now(),
        )

    def _fallback(self, event: BaseEvent, reason: str) -> DecisionResult:
        return DecisionResult(
            event=event, decision=Decision.SAFE, tier=DecisionTier.LLM,
            confidence=0.3, reasoning=f"Fallback ({reason})", timestamp=datetime.now(),
        )
