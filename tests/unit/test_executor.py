"""Tests for the safe action executor."""
import pytest
from unittest.mock import patch
from datetime import datetime

from execution.orchestrator.actions.executor import ActionExecutor
from execution.orchestrator.models import (
    FileEvent, Decision, DecisionTier, DecisionResult,
)
from execution.orchestrator.config import DecisionConfig


@pytest.fixture
def executor():
    """Executor with dry_run=False for action tests."""
    config = DecisionConfig(dry_run=False)
    return ActionExecutor(config)


@pytest.fixture
def dry_executor():
    """Executor with dry_run=True (default)."""
    config = DecisionConfig(dry_run=True)
    return ActionExecutor(config)


def _make_result(decision, confidence=0.9, pid=1234, comm="test"):
    event = FileEvent(timestamp=datetime.now(), pid=pid, uid=1000,
                      comm=comm, filename="/tmp/test")
    return DecisionResult(
        event=event, decision=decision, tier=DecisionTier.RULE,
        confidence=confidence, reasoning="test", timestamp=datetime.now(),
    )


class TestPIDValidation:
    def test_rejects_negative_pid(self, executor):
        result = _make_result(Decision.LIMIT, pid=-1)
        executor._limit_process(result)
        # Should not crash, just log error

    def test_rejects_zero_pid(self, executor):
        result = _make_result(Decision.LIMIT, pid=0)
        executor._limit_process(result)

    def test_rejects_too_large_pid(self, executor):
        result = _make_result(Decision.LIMIT, pid=999999999)
        executor._limit_process(result)


class TestLimitProcess:
    @patch("subprocess.run")
    def test_uses_subprocess_not_os_system(self, mock_run, executor):
        result = _make_result(Decision.LIMIT, pid=1234)
        executor._limit_process(result)
        mock_run.assert_called_once_with(
            ["renice", "-n", "15", "-p", "1234"],
            capture_output=True, timeout=5, check=False,
        )
        assert result.action_taken == "renice"


class TestBlockProcess:
    def test_low_confidence_block_skipped(self, executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.5)
        executor._block_process(result)
        assert result.action_taken == "skipped_low_confidence"

    @patch("os.kill")
    def test_high_confidence_sends_sigterm(self, mock_kill, executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.95)
        executor._block_process(result)
        mock_kill.assert_called_once()
        assert result.action_taken == "sigterm"

    @patch("os.kill", side_effect=ProcessLookupError)
    def test_handles_process_already_gone(self, mock_kill, executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.95)
        executor._block_process(result)
        # Should not raise

    @patch("os.kill", side_effect=PermissionError)
    def test_handles_permission_error(self, mock_kill, executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.95)
        executor._block_process(result)
        # Should not raise


class TestProtectedProcesses:
    def test_protected_process_not_killed(self, executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.95, comm="konsole")
        executor._block_process(result)
        assert result.action_taken == "skipped_protected"

    def test_protected_bash_not_killed(self, executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.95, comm="bash")
        executor._block_process(result)
        assert result.action_taken == "skipped_protected"

    @patch("os.kill")
    def test_unprotected_process_can_be_killed(self, mock_kill, executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.95, comm="exploit_tool")
        executor._block_process(result)
        mock_kill.assert_called_once()
        assert result.action_taken == "sigterm"


class TestDryRunMode:
    def test_dry_run_block_only_logs(self, dry_executor):
        result = _make_result(Decision.MALICIOUS, confidence=0.95, comm="exploit_tool")
        dry_executor._block_process(result)
        assert result.action_taken == "dry_run_sigterm"

    def test_dry_run_limit_only_logs(self, dry_executor):
        result = _make_result(Decision.LIMIT, pid=1234)
        dry_executor._limit_process(result)
        assert result.action_taken == "dry_run_renice"

    def test_dry_run_protected_still_skipped(self, dry_executor):
        """Protected check happens before dry_run check."""
        result = _make_result(Decision.MALICIOUS, confidence=0.95, comm="konsole")
        dry_executor._block_process(result)
        assert result.action_taken == "skipped_protected"


class TestExecuteDispatch:
    def test_safe_does_nothing(self, executor):
        result = _make_result(Decision.SAFE)
        executor.execute(result)
        assert result.action_taken is None

    @patch("subprocess.run")
    def test_limit_calls_renice(self, mock_run, executor):
        result = _make_result(Decision.LIMIT)
        executor.execute(result)
        mock_run.assert_called_once()
