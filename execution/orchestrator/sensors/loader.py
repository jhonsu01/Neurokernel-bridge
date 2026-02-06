"""BPF program loader and probe attachment."""
from __future__ import annotations
import ctypes
import os
from pathlib import Path
import structlog

from ..config import SensorConfig

logger = structlog.get_logger("sensor_loader")


class SensorLoader:
    """Loads the eBPF sensor program and attaches kernel probes."""

    def __init__(self, config: SensorConfig):
        self.config = config
        self._bpf = None

    @property
    def bpf(self):
        if self._bpf is None:
            raise RuntimeError("BPF not loaded. Call load() first.")
        return self._bpf

    def load(self):
        """Load and compile the eBPF program, attach all probes."""
        from bcc import BPF

        sensor_path = Path(self.config.sensor_path).resolve()
        if not sensor_path.exists():
            raise FileNotFoundError(f"Sensor not found: {sensor_path}")

        source = sensor_path.read_text()
        logger.info("loading_sensor", path=str(sensor_path))

        self._bpf = BPF(text=source)

        # Register our own PID in the filter map
        own_pid = os.getpid()
        pid_filter = self._bpf["pid_filter"]
        key = ctypes.c_uint32(own_pid)
        val = ctypes.c_uint8(1)
        pid_filter[key] = val
        logger.info("self_pid_filtered", pid=own_pid)

        self._attach_probes()
        logger.info("all_probes_attached")

    def _try_attach_kprobe(self, fn_name: str, candidates: list[str]) -> str:
        """Try attaching a kprobe to the first available kernel symbol."""
        b = self._bpf
        for event in candidates:
            try:
                b.attach_kprobe(event=event, fn_name=fn_name)
                logger.debug("probe_attached", probe=fn_name, symbol=event)
                return event
            except Exception:
                logger.debug("probe_skipped", probe=fn_name, symbol=event)
                continue
        raise RuntimeError(
            f"Cannot attach {fn_name}: none of {candidates} are traceable"
        )

    def _try_attach_kretprobe(self, fn_name: str, candidates: list[str]) -> str:
        """Try attaching a kretprobe to the first available kernel symbol."""
        b = self._bpf
        for event in candidates:
            try:
                b.attach_kretprobe(event=event, fn_name=fn_name)
                logger.debug("retprobe_attached", probe=fn_name, symbol=event)
                return event
            except Exception:
                logger.debug("retprobe_skipped", probe=fn_name, symbol=event)
                continue
        raise RuntimeError(
            f"Cannot attach {fn_name} (ret): none of {candidates} are traceable"
        )

    def _attach_probes(self):
        # Dimension 1: Process Execution
        self._try_attach_kprobe("trace_execve", [
            "__x64_sys_execve", "do_execve", "do_execveat_common",
            "__x64_sys_execveat",
        ])

        # Dimension 2: File Access
        self._try_attach_kprobe("trace_openat2", [
            "do_sys_openat2", "__x64_sys_openat2", "do_sys_open",
        ])

        # Dimension 3: Network - Outbound TCP
        evt = self._try_attach_kprobe("trace_tcp_connect", ["tcp_v4_connect"])
        self._try_attach_kretprobe("trace_tcp_connect_ret", [evt])

        # Dimension 3: Network - Inbound TCP
        self._try_attach_kretprobe("trace_tcp_accept", ["inet_csk_accept"])

        # Dimension 3: Network - DNS
        self._try_attach_kprobe("trace_udp_send", ["udp_sendmsg"])

        # Dimension 4: Resource - OOM
        self._try_attach_kprobe("trace_oom", ["out_of_memory"])

        # Dimension 5: Suspicious - mmap exec
        self._try_attach_kprobe("trace_mmap_exec", ["security_mmap_file"])

        # Dimension 5: Suspicious - Module loading
        self._try_attach_kprobe("trace_module_load", [
            "__x64_sys_finit_module", "__x64_sys_init_module",
        ])
        # Try second module symbol (optional, don't fail)
        try:
            self._bpf.attach_kprobe(
                event="__x64_sys_init_module", fn_name="trace_module_load")
        except Exception:
            pass

        # Note: ptrace is attached via TRACEPOINT_PROBE in sensor.c (auto-attached by BCC)

    def open_perf_buffers(self, callbacks: dict):
        """Open perf buffers with the provided callback dict.

        Args:
            callbacks: dict mapping buffer name to callback function.
                       e.g. {"exec_events": fn, "file_events": fn, ...}
        """
        b = self._bpf
        for name, cb in callbacks.items():
            b[name].open_perf_buffer(cb, page_cnt=64)
            logger.debug("perf_buffer_opened", buffer=name)

    def poll(self, timeout_ms: int = 100):
        """Poll all perf buffers. Blocks up to timeout_ms."""
        self._bpf.perf_buffer_poll(timeout=timeout_ms)

    def cleanup(self):
        """Detach probes and clean up."""
        if self._bpf is not None:
            self._bpf.cleanup()
            self._bpf = None
            logger.info("bpf_cleaned_up")
