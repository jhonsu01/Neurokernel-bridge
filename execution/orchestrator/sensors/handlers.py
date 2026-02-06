"""Perf buffer callbacks that parse C structs into Pydantic models."""
from __future__ import annotations
import ctypes
import socket
import struct
from datetime import datetime
from typing import Callable
import structlog

from ..models import (
    ExecEvent, FileEvent, NetEvent, ResourceEvent, SuspiciousEvent,
    EventDimension,
)

logger = structlog.get_logger("event_handlers")

SUSPICIOUS_SUBTYPES = {1: "ptrace", 2: "mmap_exec", 3: "mprotect_exec", 4: "module_load"}
RESOURCE_SUBTYPES = {1: "oom"}


def _u32_to_ip(addr: int) -> str:
    """Convert a u32 network-byte-order address to dotted notation."""
    return socket.inet_ntoa(struct.pack("I", addr))


def _decode_comm(raw: bytes) -> str:
    """Decode a null-terminated C string."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _decode_filename(raw: bytes) -> str:
    """Decode a null-terminated filename."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def create_handlers(bpf, submit_fn: Callable) -> dict:
    """Create perf buffer callback functions.

    Args:
        bpf: The BPF object (needed to call .event() on buffers)
        submit_fn: Callable that receives a parsed event model and submits
                   it to the processing queue.

    Returns:
        dict mapping buffer names to callback functions.
    """

    def handle_exec(cpu, data, size):
        event = bpf["exec_events"].event(data)
        try:
            model = ExecEvent(
                timestamp=datetime.now(),
                pid=event.pid,
                uid=event.uid,
                comm=_decode_comm(event.comm),
                ppid=event.ppid,
                filename="",  # exec filename not captured in current BPF probe
            )
            submit_fn(model)
        except Exception as e:
            logger.error("exec_event_parse_error", error=str(e))

    def handle_file(cpu, data, size):
        event = bpf["file_events"].event(data)
        try:
            model = FileEvent(
                timestamp=datetime.now(),
                pid=event.pid,
                uid=event.uid,
                comm=_decode_comm(event.comm),
                filename=_decode_filename(event.filename),
                flags=event.flags,
            )
            submit_fn(model)
        except Exception as e:
            logger.error("file_event_parse_error", error=str(e))

    def handle_net(cpu, data, size):
        event = bpf["net_events"].event(data)
        try:
            direction = "outbound" if event.direction == 0 else "inbound"
            protocol = "tcp" if event.protocol == 6 else "udp"
            dimension = EventDimension.NET_DNS if event.dport == 53 and protocol == "udp" else (
                EventDimension.NET_ACCEPT if direction == "inbound" else EventDimension.NET_CONN
            )
            model = NetEvent(
                timestamp=datetime.now(),
                pid=event.pid,
                uid=event.uid,
                comm=_decode_comm(event.comm),
                dimension=dimension,
                saddr=_u32_to_ip(event.saddr),
                daddr=_u32_to_ip(event.daddr),
                sport=event.sport,
                dport=event.dport,
                direction=direction,
                protocol=protocol,
            )
            submit_fn(model)
        except Exception as e:
            logger.error("net_event_parse_error", error=str(e))

    def handle_resource(cpu, data, size):
        event = bpf["resource_events"].event(data)
        try:
            model = ResourceEvent(
                timestamp=datetime.now(),
                pid=event.pid,
                uid=event.uid,
                comm=_decode_comm(event.comm),
                subtype=RESOURCE_SUBTYPES.get(event.subtype, f"unknown_{event.subtype}"),
                value=event.value,
            )
            submit_fn(model)
        except Exception as e:
            logger.error("resource_event_parse_error", error=str(e))

    def handle_suspicious(cpu, data, size):
        event = bpf["suspicious_events"].event(data)
        try:
            model = SuspiciousEvent(
                timestamp=datetime.now(),
                pid=event.pid,
                uid=event.uid,
                comm=_decode_comm(event.comm),
                subtype=SUSPICIOUS_SUBTYPES.get(event.subtype, f"unknown_{event.subtype}"),
                target_pid=event.target_pid if event.target_pid else None,
                flags=event.flags,
            )
            submit_fn(model)
        except Exception as e:
            logger.error("suspicious_event_parse_error", error=str(e))

    return {
        "exec_events": handle_exec,
        "file_events": handle_file,
        "net_events": handle_net,
        "resource_events": handle_resource,
        "suspicious_events": handle_suspicious,
    }
