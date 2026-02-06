"""Tests for Tier 1 rule engine - deterministic decision logic."""
import pytest
from datetime import datetime

from execution.orchestrator.decision.rules import RuleEngine
from execution.orchestrator.models import (
    ExecEvent, FileEvent, NetEvent, ResourceEvent, SuspiciousEvent,
    EventDimension, Decision, DecisionTier,
)
from execution.orchestrator.config import DecisionConfig


@pytest.fixture
def engine():
    return RuleEngine(DecisionConfig())


def _now():
    return datetime.now()


class TestFileAccessRules:
    def test_nonroot_shadow_access_is_malicious(self, engine):
        event = FileEvent(timestamp=_now(), pid=1234, uid=1000,
                          comm="curl", filename="/etc/shadow")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS
        assert result.tier == DecisionTier.RULE
        assert result.confidence >= 0.9

    def test_root_shadow_access_is_safe(self, engine):
        event = FileEvent(timestamp=_now(), pid=1, uid=0,
                          comm="passwd", filename="/etc/shadow")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_nonroot_passwd_access_is_safe(self, engine):
        """etc/passwd is world-readable — normal processes read it for user lookup."""
        event = FileEvent(timestamp=_now(), pid=2000, uid=1000,
                          comm="nc", filename="/etc/passwd")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_nonroot_sudoers_is_escalated(self, engine):
        """Sensitive but not critical — escalate to Tier 2/3 instead of killing."""
        event = FileEvent(timestamp=_now(), pid=3000, uid=1000,
                          comm="cat", filename="/etc/sudoers")
        result = engine.evaluate(event)
        assert result.decision == Decision.UNKNOWN

    def test_nonroot_ssh_is_escalated(self, engine):
        """Sensitive but not critical — escalate to Tier 2/3 instead of killing."""
        event = FileEvent(timestamp=_now(), pid=3001, uid=1000,
                          comm="wget", filename="/home/user/.ssh/id_rsa")
        result = engine.evaluate(event)
        assert result.decision == Decision.UNKNOWN

    def test_nonroot_gshadow_access_is_malicious(self, engine):
        """Critical path — non-root access is definitively malicious."""
        event = FileEvent(timestamp=_now(), pid=3002, uid=1000,
                          comm="exploit", filename="/etc/gshadow")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS
        assert result.confidence >= 0.9

    def test_whitelisted_process_file_safe(self, engine):
        event = FileEvent(timestamp=_now(), pid=1, uid=0,
                          comm="systemd", filename="/some/file")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_normal_file_access_unknown(self, engine):
        event = FileEvent(timestamp=_now(), pid=5000, uid=1000,
                          comm="vim", filename="/tmp/notes.txt")
        result = engine.evaluate(event)
        assert result.decision == Decision.UNKNOWN


class TestNetworkRules:
    def test_suspicious_port_4444_is_malicious(self, engine):
        event = NetEvent(timestamp=_now(), pid=5678, uid=1000,
                         comm="nc", daddr="10.0.0.1", dport=4444,
                         direction="outbound", protocol="tcp")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS
        assert result.confidence >= 0.9

    def test_suspicious_port_1337_is_malicious(self, engine):
        event = NetEvent(timestamp=_now(), pid=5679, uid=1000,
                         comm="bash", daddr="1.2.3.4", dport=1337,
                         direction="outbound", protocol="tcp")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS

    def test_unexpected_inbound_is_malicious(self, engine):
        event = NetEvent(timestamp=_now(), pid=6000, uid=1000,
                         comm="exploit",
                         dimension=EventDimension.NET_ACCEPT,
                         dport=9999, direction="inbound", protocol="tcp")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS

    def test_sshd_inbound_not_malicious(self, engine):
        event = NetEvent(timestamp=_now(), pid=100, uid=0,
                         comm="sshd",
                         dimension=EventDimension.NET_ACCEPT,
                         dport=22, direction="inbound", protocol="tcp")
        result = engine.evaluate(event)
        assert result.decision != Decision.MALICIOUS

    def test_normal_outbound_unknown(self, engine):
        event = NetEvent(timestamp=_now(), pid=7000, uid=1000,
                         comm="firefox", daddr="93.184.216.34", dport=443,
                         direction="outbound", protocol="tcp")
        result = engine.evaluate(event)
        assert result.decision == Decision.UNKNOWN


class TestSuspiciousRules:
    def test_nonroot_module_load_malicious(self, engine):
        event = SuspiciousEvent(timestamp=_now(), pid=9999, uid=1000,
                                comm="exploit", subtype="module_load")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS
        assert result.confidence == 1.0

    def test_nondebugger_ptrace_malicious(self, engine):
        event = SuspiciousEvent(timestamp=_now(), pid=2000, uid=1000,
                                comm="malware", subtype="ptrace",
                                target_pid=3000)
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS
        assert result.confidence >= 0.8

    def test_gdb_ptrace_is_safe(self, engine):
        event = SuspiciousEvent(timestamp=_now(), pid=2000, uid=1000,
                                comm="gdb", subtype="ptrace",
                                target_pid=3000)
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_strace_ptrace_is_safe(self, engine):
        event = SuspiciousEvent(timestamp=_now(), pid=2001, uid=1000,
                                comm="strace", subtype="ptrace",
                                target_pid=3001)
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_mmap_exec_is_malicious(self, engine):
        event = SuspiciousEvent(timestamp=_now(), pid=4000, uid=1000,
                                comm="shell", subtype="mmap_exec")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS
        assert result.confidence >= 0.6

    def test_mprotect_exec_is_malicious(self, engine):
        event = SuspiciousEvent(timestamp=_now(), pid=4001, uid=1000,
                                comm="injector", subtype="mprotect_exec")
        result = engine.evaluate(event)
        assert result.decision == Decision.MALICIOUS

    def test_mmap_exec_jit_python3_is_safe(self, engine):
        """Known JIT process using mmap_exec is normal — resolve at Tier 1."""
        event = SuspiciousEvent(timestamp=_now(), pid=4002, uid=1000,
                                comm="python3", subtype="mmap_exec")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE
        assert result.tier == DecisionTier.RULE

    def test_mprotect_exec_jit_node_is_safe(self, engine):
        """Known JIT process using mprotect_exec is normal — resolve at Tier 1."""
        event = SuspiciousEvent(timestamp=_now(), pid=4003, uid=1000,
                                comm="node", subtype="mprotect_exec")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE
        assert result.tier == DecisionTier.RULE


class TestExecRules:
    def test_whitelisted_exec_safe(self, engine):
        event = ExecEvent(timestamp=_now(), pid=1, uid=0,
                          comm="systemd", filename="/usr/lib/systemd/systemd")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_whitelisted_python3_exec_safe(self, engine):
        event = ExecEvent(timestamp=_now(), pid=8000, uid=1000,
                          comm="python3", filename="/usr/bin/python3")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_unknown_exec_escalated(self, engine):
        event = ExecEvent(timestamp=_now(), pid=8001, uid=1000,
                          comm="unknown_binary", filename="/tmp/unknown")
        result = engine.evaluate(event)
        assert result.decision == Decision.UNKNOWN


class TestResourceRules:
    def test_oom_is_limit(self, engine):
        event = ResourceEvent(timestamp=_now(), pid=9000, uid=1000,
                              comm="stress", subtype="oom")
        result = engine.evaluate(event)
        assert result.decision == Decision.LIMIT
        assert result.confidence >= 0.8


class TestDNSRules:
    def test_whitelisted_dns_safe(self, engine):
        event = NetEvent(timestamp=_now(), pid=100, uid=0,
                         comm="systemd",
                         dimension=EventDimension.NET_DNS,
                         dport=53, direction="outbound", protocol="udp")
        result = engine.evaluate(event)
        assert result.decision == Decision.SAFE

    def test_unknown_dns_escalated(self, engine):
        event = NetEvent(timestamp=_now(), pid=5000, uid=1000,
                         comm="dig",
                         dimension=EventDimension.NET_DNS,
                         dport=53, direction="outbound", protocol="udp")
        result = engine.evaluate(event)
        assert result.decision == Decision.UNKNOWN
