from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
import structlog

from ..config import AppConfig
from .chromadb_client import SecurityDecisionCache
from .claude_mem import ClaudeMemBridge

logger = structlog.get_logger("memory_bridge")


@dataclass
class SessionStats:
    start_time: datetime = field(default_factory=datetime.now)
    total_events: int = 0
    tier1_count: int = 0
    tier2_count: int = 0
    tier3_count: int = 0
    blocked_count: int = 0
    limited_count: int = 0
    safe_count: int = 0

    def to_facts(self) -> list[str]:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return [
            f"Session duration: {elapsed:.0f}s",
            f"Total events processed: {self.total_events}",
            f"Tier 1 (rules) decisions: {self.tier1_count}",
            f"Tier 2 (cache) decisions: {self.tier2_count}",
            f"Tier 3 (LLM) decisions: {self.tier3_count}",
            f"Processes blocked: {self.blocked_count}",
            f"Processes limited: {self.limited_count}",
        ]

    def to_narrative(self) -> str:
        return (
            f"Kernel security monitoring session processed {self.total_events} events. "
            f"Decision breakdown: {self.tier1_count} rule-based, "
            f"{self.tier2_count} cache hits, {self.tier3_count} LLM escalations. "
            f"Actions: {self.blocked_count} blocked, {self.limited_count} limited, "
            f"{self.safe_count} safe."
        )


class MemoryBridge:
    """Coordinates ChromaDB (fast cache) and claude-mem (long-term memory)."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.cache = SecurityDecisionCache(config.decision)
        self.mem = ClaudeMemBridge(config.memory)
        self.stats = SessionStats()

    def initialize(self) -> str:
        context = self.mem.load_session_context()
        if context:
            logger.info("loaded_prior_context", length=len(context))
        else:
            logger.info("no_prior_context_found")
        return context

    def record_decision(self, tier: int, decision_name: str) -> None:
        self.stats.total_events += 1
        if tier == 1:
            self.stats.tier1_count += 1
        elif tier == 2:
            self.stats.tier2_count += 1
        elif tier == 3:
            self.stats.tier3_count += 1

        if decision_name == "MALICIOUS":
            self.stats.blocked_count += 1
        elif decision_name == "LIMIT":
            self.stats.limited_count += 1
        elif decision_name == "SAFE":
            self.stats.safe_count += 1

    def periodic_sync(self) -> None:
        observation = {
            "type": "security_monitoring_stats",
            "title": f"Security stats: {self.stats.total_events} events processed",
            "facts": self.stats.to_facts(),
            "concepts": ["eBPF", "security", "threat-detection", "kernel-monitoring"],
        }
        self.mem.push_observation(observation)
        logger.info("periodic_sync_complete", total_events=self.stats.total_events)

    def compress_session(self) -> None:
        summary = {
            "type": "session_summary",
            "title": "Linux kernel security monitoring session",
            "narrative": self.stats.to_narrative(),
            "facts": self.stats.to_facts(),
            "concepts": ["eBPF", "kernel-security", "AI-decision-engine"],
        }
        self.mem.push_observation(summary)
        logger.info("session_compressed",
                     total_events=self.stats.total_events,
                     narrative=self.stats.to_narrative())

    def close(self) -> None:
        self.mem.close()
