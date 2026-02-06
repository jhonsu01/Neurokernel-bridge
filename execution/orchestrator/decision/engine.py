from __future__ import annotations
import structlog

from ..models import BaseEvent, Decision, DecisionResult
from ..config import AppConfig
from .rules import RuleEngine
from .cache import CacheEngine
from .llm import LLMEngine


logger = structlog.get_logger("decision_engine")


class DecisionEngine:
    """
    3-tier decision engine:
    Tier 1 (Rules)  -> instant, deterministic
    Tier 2 (Cache)  -> 1-5ms, ChromaDB similarity
    Tier 3 (LLM)    -> 500-2000ms, Claude API
    """

    def __init__(self, config: AppConfig):
        self.rules = RuleEngine(config.decision)
        self.cache = CacheEngine(config.decision)
        self.llm = LLMEngine(config.decision)

    def decide(self, event: BaseEvent) -> DecisionResult:
        # Tier 1: Rules
        result = self.rules.evaluate(event)
        if result.decision != Decision.UNKNOWN:
            logger.info("tier1_decision",
                        dimension=event.dimension.name,
                        decision=result.decision.name,
                        confidence=result.confidence,
                        comm=event.comm, pid=event.pid)
            return result

        # Tier 2: Cache
        cached = self.cache.lookup(event)
        if cached is not None and cached.decision != Decision.UNKNOWN:
            logger.info("tier2_decision",
                        dimension=event.dimension.name,
                        decision=cached.decision.name,
                        confidence=cached.confidence,
                        comm=event.comm, pid=event.pid)
            return cached

        # Tier 3: LLM
        result = self.llm.escalate(event)
        logger.info("tier3_decision",
                    dimension=event.dimension.name,
                    decision=result.decision.name,
                    confidence=result.confidence,
                    comm=event.comm, pid=event.pid)

        # Cache the LLM result for future Tier 2 hits
        if result.decision != Decision.UNKNOWN:
            self.cache.store(event, result)

        return result
