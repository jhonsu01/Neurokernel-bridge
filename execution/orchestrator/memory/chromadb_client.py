from __future__ import annotations
import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..models import (
    BaseEvent, ExecEvent, FileEvent, NetEvent, SuspiciousEvent, ResourceEvent,
    Decision, DecisionTier, DecisionResult,
)
from ..config import DecisionConfig
from .embeddings import NGramEmbeddingFunction


class SecurityDecisionCache:
    """SQLite-backed fast decision cache for security events.

    Uses n-gram embeddings for similarity matching instead of ChromaDB
    to avoid onnxruntime/Rust AVX CPU requirements.
    """

    def __init__(self, config: DecisionConfig):
        self.config = config
        self.embed_fn = NGramEmbeddingFunction()

        db_path = Path(config.chromadb_path) / "cache.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self._init_db()

    def _init_db(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                signature TEXT NOT NULL,
                embedding TEXT NOT NULL,
                decision INTEGER NOT NULL,
                confidence REAL NOT NULL,
                reasoning TEXT,
                tier INTEGER,
                comm TEXT,
                dimension TEXT,
                created_at TEXT
            )
        """)
        self.conn.commit()

    def compute_signature(self, event: BaseEvent) -> str:
        if isinstance(event, FileEvent):
            return f"{event.comm}:FILE:{event.filename}"
        if isinstance(event, NetEvent):
            return f"{event.comm}:NET:{event.direction}:daddr={event.daddr}:dport={event.dport}"
        if isinstance(event, SuspiciousEvent):
            return f"{event.comm}:SUSPICIOUS:{event.subtype}"
        if isinstance(event, ExecEvent):
            return f"{event.comm}:EXEC:{event.filename}"
        if isinstance(event, ResourceEvent):
            return f"{event.comm}:RESOURCE:{event.subtype}"
        return f"{event.comm}:{event.dimension.name}"

    def _cosine_similarity(self, a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = sum(x * x for x in a) ** 0.5
        norm_b = sum(x * x for x in b) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def lookup(self, event: BaseEvent) -> Optional[DecisionResult]:
        sig = self.compute_signature(event)
        query_vec = self.embed_fn([sig])[0]

        try:
            rows = self.conn.execute(
                "SELECT embedding, decision, confidence, reasoning FROM decisions"
            ).fetchall()
        except Exception:
            return None

        if not rows:
            return None

        best_sim = -1.0
        best_row = None
        for row in rows:
            stored_vec = json.loads(row[0])
            sim = self._cosine_similarity(query_vec, stored_vec)
            if sim > best_sim:
                best_sim = sim
                best_row = row

        if best_sim < self.config.similarity_threshold or best_row is None:
            return None

        return DecisionResult(
            event=event,
            decision=Decision(best_row[1]),
            tier=DecisionTier.CACHE,
            confidence=best_sim * best_row[2],
            reasoning=f"Cached: {best_row[3] or 'similar pattern'}",
            timestamp=datetime.now(),
        )

    def store(self, event: BaseEvent, result: DecisionResult) -> None:
        sig = self.compute_signature(event)
        vec = self.embed_fn([sig])[0]
        doc_id = hashlib.sha256(
            f"{sig}:{result.timestamp.isoformat()}".encode()
        ).hexdigest()[:16]

        self.conn.execute(
            """INSERT OR REPLACE INTO decisions
               (id, signature, embedding, decision, confidence, reasoning,
                tier, comm, dimension, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                doc_id, sig, json.dumps(vec),
                result.decision.value, result.confidence,
                result.reasoning[:200], result.tier.value,
                event.comm, event.dimension.name,
                datetime.now().isoformat(),
            ),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
