from __future__ import annotations
from pydantic import BaseModel
from datetime import datetime
from enum import IntEnum
from typing import Optional

class EventDimension(IntEnum):
    EXEC = 1
    FILE = 2
    NET_CONN = 3
    NET_ACCEPT = 4
    NET_DNS = 5
    RESOURCE = 6
    SUSPICIOUS = 7

class Decision(IntEnum):
    SAFE = 0
    LIMIT = 1
    MALICIOUS = 2
    UNKNOWN = 3

class DecisionTier(IntEnum):
    RULE = 1
    CACHE = 2
    LLM = 3

class BaseEvent(BaseModel):
    timestamp: datetime
    pid: int
    uid: int
    comm: str
    dimension: EventDimension

class ExecEvent(BaseEvent):
    dimension: EventDimension = EventDimension.EXEC
    ppid: int = 0
    filename: str = ""

class FileEvent(BaseEvent):
    dimension: EventDimension = EventDimension.FILE
    filename: str = ""
    flags: int = 0

class NetEvent(BaseEvent):
    dimension: EventDimension = EventDimension.NET_CONN
    saddr: str = "0.0.0.0"
    daddr: str = "0.0.0.0"
    sport: int = 0
    dport: int = 0
    direction: str = "outbound"
    protocol: str = "tcp"

class ResourceEvent(BaseEvent):
    dimension: EventDimension = EventDimension.RESOURCE
    subtype: str = "oom"
    value: int = 0

class SuspiciousEvent(BaseEvent):
    dimension: EventDimension = EventDimension.SUSPICIOUS
    subtype: str = ""
    target_pid: Optional[int] = None
    flags: int = 0
    detail: str = ""

class DecisionResult(BaseModel):
    event: BaseEvent
    decision: Decision
    tier: DecisionTier
    confidence: float
    reasoning: str
    timestamp: datetime
    action_taken: Optional[str] = None
