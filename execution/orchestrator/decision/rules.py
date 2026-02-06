from __future__ import annotations
from datetime import datetime
from ..models import (
    BaseEvent, ExecEvent, FileEvent, NetEvent, ResourceEvent, SuspiciousEvent,
    EventDimension, Decision, DecisionTier, DecisionResult,
)
from ..config import DecisionConfig


class RuleEngine:
    """Tier 1: Deterministic pattern matching. Zero API calls. ~0ms latency."""

    # Processes that legitimately use JIT (mmap_exec / mprotect_exec)
    _JIT_PROCS = frozenset({
        "python3", "python", "java", "javac", "node", "nodejs",
        "ruby", "perl", "php", "dotnet", "mono", "luajit",
        "chromium", "chrome", "firefox", "firefox-esr",
        "Xorg", "Xwayland", "gnome-shell", "plasmashell", "kwin_wayland", "kwin_x11",
        "konsole", "gnome-terminal", "xterm", "alacritty",
        "code", "electron",
    })

    def __init__(self, config: DecisionConfig):
        self.config = config

    def evaluate(self, event: BaseEvent) -> DecisionResult:
        match event.dimension:
            case EventDimension.EXEC:
                return self._eval_exec(event)
            case EventDimension.FILE:
                return self._eval_file(event)
            case EventDimension.NET_CONN | EventDimension.NET_ACCEPT:
                return self._eval_network(event)
            case EventDimension.NET_DNS:
                return self._eval_dns(event)
            case EventDimension.SUSPICIOUS:
                return self._eval_suspicious(event)
            case EventDimension.RESOURCE:
                return self._eval_resource(event)
            case _:
                return self._unknown(event)

    def _eval_exec(self, event: ExecEvent) -> DecisionResult:
        if event.comm in self.config.whitelisted_procs:
            return self._result(event, Decision.SAFE, 0.9,
                                f"Whitelisted process: {event.comm}")
        return self._unknown(event)

    def _eval_file(self, event: FileEvent) -> DecisionResult:
        # World-readable system files — always safe
        is_safe_system = any(p in event.filename for p in self.config.safe_system_files)
        if is_safe_system:
            return self._result(event, Decision.SAFE, 0.95,
                                f"World-readable system file: {event.filename}")

        # Critical paths (shadow, kcore, etc.) — only root allowed
        is_critical = any(p in event.filename for p in self.config.critical_paths)
        if is_critical and event.uid != 0:
            return self._result(event, Decision.MALICIOUS, 0.95,
                                f"Non-root uid={event.uid} accessing critical path {event.filename}")
        if is_critical and event.uid == 0:
            return self._result(event, Decision.SAFE, 0.85,
                                f"Root access to critical path {event.filename}")

        # Sensitive paths (sudoers, .ssh, /root) — escalate, don't kill
        is_sensitive = any(p in event.filename for p in self.config.sensitive_paths)
        if is_sensitive and event.uid != 0:
            return self._unknown(event)
        if is_sensitive and event.uid == 0:
            return self._result(event, Decision.SAFE, 0.85,
                                f"Root access to {event.filename}")

        if event.comm in self.config.whitelisted_procs:
            return self._result(event, Decision.SAFE, 0.9,
                                f"Whitelisted process: {event.comm}")
        return self._unknown(event)

    def _eval_network(self, event: NetEvent) -> DecisionResult:
        if event.dport in self.config.suspicious_ports:
            return self._result(event, Decision.MALICIOUS, 0.9,
                                f"Connection to suspicious port {event.dport}")
        if (event.direction == "inbound" and event.dport > 1024
                and event.comm not in ["sshd", "nginx", "apache2", "node", "python3"]):
            return self._result(event, Decision.MALICIOUS, 0.7,
                                f"Unexpected inbound connection from {event.comm} on port {event.dport}")
        if event.comm in self.config.whitelisted_procs:
            return self._result(event, Decision.SAFE, 0.9,
                                f"Whitelisted process: {event.comm}")
        return self._unknown(event)

    def _eval_dns(self, event: NetEvent) -> DecisionResult:
        if event.comm in self.config.whitelisted_procs:
            return self._result(event, Decision.SAFE, 0.9,
                                f"Whitelisted DNS from {event.comm}")
        return self._unknown(event)

    def _eval_suspicious(self, event: SuspiciousEvent) -> DecisionResult:
        if event.subtype == "module_load" and event.uid != 0:
            return self._result(event, Decision.MALICIOUS, 1.0,
                                "Non-root kernel module load attempt")
        if event.subtype == "ptrace":
            if event.comm not in ["gdb", "strace", "ltrace", "lldb"]:
                return self._result(event, Decision.MALICIOUS, 0.85,
                                    f"Non-debugger {event.comm} using ptrace")
            return self._result(event, Decision.SAFE, 0.8,
                                f"Known debugger {event.comm} using ptrace")
        if event.subtype == "mmap_exec":
            if event.comm in self._JIT_PROCS:
                return self._result(event, Decision.SAFE, 0.85,
                                    f"Known JIT process {event.comm} using mmap_exec")
            return self._result(event, Decision.MALICIOUS, 0.7,
                                "Anonymous executable memory mapping (potential shellcode)")
        if event.subtype == "mprotect_exec":
            if event.comm in self._JIT_PROCS:
                return self._result(event, Decision.SAFE, 0.85,
                                    f"Known JIT process {event.comm} using mprotect_exec")
            return self._result(event, Decision.MALICIOUS, 0.65,
                                "Memory protection changed to executable")
        return self._unknown(event)

    def _eval_resource(self, event: ResourceEvent) -> DecisionResult:
        if event.subtype == "oom":
            return self._result(event, Decision.LIMIT, 0.9,
                                f"OOM triggered by {event.comm}")
        return self._unknown(event)

    def _unknown(self, event: BaseEvent) -> DecisionResult:
        return self._result(event, Decision.UNKNOWN, 0.0, "No rule matched - escalating")

    def _result(self, event: BaseEvent, decision: Decision, confidence: float,
                reasoning: str) -> DecisionResult:
        return DecisionResult(
            event=event, decision=decision, tier=DecisionTier.RULE,
            confidence=confidence, reasoning=reasoning, timestamp=datetime.now(),
        )
