"""Tests for Pydantic data models."""
import pytest
from datetime import datetime

from execution.orchestrator.models import (
    ExecEvent, FileEvent, NetEvent, ResourceEvent, SuspiciousEvent,
    DecisionResult, EventDimension, Decision, DecisionTier,
)


def test_exec_event_defaults():
    e = ExecEvent(timestamp=datetime.now(), pid=1, uid=0, comm="init")
    assert e.dimension == EventDimension.EXEC
    assert e.ppid == 0
    assert e.filename == ""


def test_file_event_creation():
    e = FileEvent(timestamp=datetime.now(), pid=100, uid=1000,
                  comm="cat", filename="/etc/passwd", flags=0)
    assert e.dimension == EventDimension.FILE
    assert e.filename == "/etc/passwd"


def test_net_event_defaults():
    e = NetEvent(timestamp=datetime.now(), pid=200, uid=1000, comm="curl")
    assert e.direction == "outbound"
    assert e.protocol == "tcp"
    assert e.saddr == "0.0.0.0"


def test_suspicious_event_optional_target():
    e = SuspiciousEvent(timestamp=datetime.now(), pid=300, uid=1000,
                        comm="gdb", subtype="ptrace")
    assert e.target_pid is None
    assert e.flags == 0


def test_resource_event():
    e = ResourceEvent(timestamp=datetime.now(), pid=400, uid=0,
                      comm="stress", subtype="oom", value=1024)
    assert e.dimension == EventDimension.RESOURCE
    assert e.value == 1024


def test_decision_result_serialization():
    event = FileEvent(timestamp=datetime.now(), pid=1, uid=0,
                      comm="cat", filename="/tmp/test")
    result = DecisionResult(
        event=event, decision=Decision.SAFE, tier=DecisionTier.RULE,
        confidence=0.95, reasoning="Test", timestamp=datetime.now(),
    )
    data = result.model_dump()
    assert data["decision"] == 0  # SAFE
    assert data["tier"] == 1  # RULE
    assert data["confidence"] == 0.95


def test_event_dimension_values():
    assert EventDimension.EXEC == 1
    assert EventDimension.FILE == 2
    assert EventDimension.NET_CONN == 3
    assert EventDimension.SUSPICIOUS == 7


def test_decision_values():
    assert Decision.SAFE == 0
    assert Decision.MALICIOUS == 2
    assert Decision.UNKNOWN == 3
