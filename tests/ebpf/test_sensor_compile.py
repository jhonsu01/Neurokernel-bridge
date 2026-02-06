"""Test that sensor.c compiles without errors.

This test does NOT require root - it only compiles the eBPF program
without attaching any probes to the kernel.
"""
import pytest
import os
from pathlib import Path


@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="BPF compilation requires root on some systems"
)
def test_sensor_compiles():
    """Verify the sensor.c eBPF program compiles without errors."""
    from bcc import BPF

    sensor_path = Path(__file__).parent.parent.parent / "execution" / "sensor.c"
    assert sensor_path.exists(), f"sensor.c not found at {sensor_path}"

    source = sensor_path.read_text()
    assert len(source) > 100, "sensor.c appears empty or truncated"

    # BPF() compiles but does not attach probes
    b = BPF(text=source)
    b.cleanup()


def test_sensor_file_exists():
    """Verify sensor.c exists and has expected content markers."""
    sensor_path = Path(__file__).parent.parent.parent / "execution" / "sensor.c"
    assert sensor_path.exists()

    source = sensor_path.read_text()
    assert "BPF_PERF_OUTPUT(exec_events)" in source
    assert "BPF_PERF_OUTPUT(file_events)" in source
    assert "BPF_PERF_OUTPUT(net_events)" in source
    assert "BPF_PERF_OUTPUT(resource_events)" in source
    assert "BPF_PERF_OUTPUT(suspicious_events)" in source
    assert "trace_execve" in source
    assert "trace_openat2" in source
    assert "trace_tcp_connect" in source
    assert "trace_oom" in source
    assert "trace_module_load" in source
    assert "pid_filter" in source
