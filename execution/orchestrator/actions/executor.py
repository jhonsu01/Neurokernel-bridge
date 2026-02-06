from __future__ import annotations
import os
import signal
import subprocess
import structlog

from ..models import Decision, DecisionResult
from ..config import DecisionConfig

logger = structlog.get_logger("action_executor")

MAX_PID = 4194304


class ActionExecutor:
    """Executes security responses safely."""

    def __init__(self, config: DecisionConfig):
        self.dry_run = config.dry_run
        self.protected_procs = set(config.protected_procs)

    def execute(self, result: DecisionResult) -> None:
        match result.decision:
            case Decision.SAFE:
                logger.debug("safe_event",
                             comm=result.event.comm, pid=result.event.pid)
            case Decision.LIMIT:
                self._limit_process(result)
            case Decision.MALICIOUS:
                self._block_process(result)

    def _is_protected(self, comm: str) -> bool:
        return comm in self.protected_procs

    def _validate_pid(self, pid: int) -> bool:
        if not isinstance(pid, int) or pid <= 0 or pid > MAX_PID:
            logger.error("invalid_pid", pid=pid)
            return False
        return True

    def _limit_process(self, result: DecisionResult) -> None:
        pid = result.event.pid
        if not self._validate_pid(pid):
            return

        if self.dry_run:
            logger.warning("dry_run_would_limit",
                           pid=pid, comm=result.event.comm,
                           tier=result.tier.name,
                           confidence=result.confidence,
                           reasoning=result.reasoning)
            result.action_taken = "dry_run_renice"
            return

        try:
            subprocess.run(
                ["renice", "-n", "15", "-p", str(pid)],
                capture_output=True, timeout=5, check=False,
            )
            logger.info("process_limited",
                        pid=pid, comm=result.event.comm,
                        tier=result.tier.name,
                        confidence=result.confidence,
                        reasoning=result.reasoning)
            result.action_taken = "renice"
        except subprocess.TimeoutExpired:
            logger.error("renice_timeout", pid=pid)
        except OSError as e:
            logger.error("renice_error", pid=pid, error=str(e))

    def _block_process(self, result: DecisionResult) -> None:
        pid = result.event.pid
        comm = result.event.comm
        if not self._validate_pid(pid):
            return

        # Never kill protected processes (terminals, desktop, shells)
        if self._is_protected(comm):
            logger.warning("protected_process_not_killed",
                           pid=pid, comm=comm,
                           tier=result.tier.name,
                           confidence=result.confidence,
                           reasoning=result.reasoning)
            result.action_taken = "skipped_protected"
            return

        # Only kill if confidence is high enough to avoid false positives
        if result.confidence < 0.8:
            logger.warning("low_confidence_block_skipped",
                           pid=pid, comm=comm,
                           confidence=result.confidence,
                           reasoning=result.reasoning)
            result.action_taken = "skipped_low_confidence"
            return

        if self.dry_run:
            logger.warning("dry_run_would_block",
                           pid=pid, comm=comm,
                           tier=result.tier.name,
                           confidence=result.confidence,
                           reasoning=result.reasoning)
            result.action_taken = "dry_run_sigterm"
            return

        try:
            os.kill(pid, signal.SIGTERM)
            logger.critical("process_blocked",
                            pid=pid, comm=comm,
                            tier=result.tier.name,
                            confidence=result.confidence,
                            reasoning=result.reasoning)
            result.action_taken = "sigterm"
        except ProcessLookupError:
            logger.warning("process_already_gone", pid=pid)
        except PermissionError:
            logger.error("insufficient_permissions", pid=pid, comm=comm)
