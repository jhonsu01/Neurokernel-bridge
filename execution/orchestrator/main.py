"""Main entry point for the LinuxIAKernel security monitoring system.

Usage:
    sudo python3 -m execution.orchestrator.main
"""
from __future__ import annotations
import asyncio
import os
import signal
import sys
import threading
import time

import structlog

from .config import AppConfig
from .logging.structured import setup_logging
from .sensors.loader import SensorLoader
from .sensors.handlers import create_handlers
from .decision.engine import DecisionEngine
from .actions.executor import ActionExecutor
from .memory.bridge import MemoryBridge
from .batching.collector import EventBatchCollector
try:
    from .telegram.bot import TelegramBot
except ImportError:
    TelegramBot = None


logger = structlog.get_logger("main")


class KernelSecurityMonitor:
    """Orchestrates the full eBPF + AI security monitoring pipeline."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.sensor = SensorLoader(config.sensor)
        self.engine = DecisionEngine(config)
        self.executor = ActionExecutor(config.decision)
        self.memory = MemoryBridge(config)
        if TelegramBot is not None:
            self.telegram = TelegramBot(
                config=config.telegram,
                stats_fn=self._get_stats,
                dry_run=config.decision.dry_run,
            )
        else:
            self.telegram = None
            logger.warning("telegram_unavailable", reason="python-telegram-bot not installed")
        self.collector = EventBatchCollector(
            config=config.batching,
            engine=self.engine,
            executor=self.executor,
            memory=self.memory,
            telegram_bot=self.telegram if self.telegram and self.telegram.enabled else None,
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._bpf_thread: threading.Thread | None = None
        self._running = True
        self._sync_task: asyncio.Task | None = None
        self._collector_task: asyncio.Task | None = None

    def start(self) -> None:
        """Start the monitoring system."""
        # Check root
        if os.geteuid() != 0:
            logger.error("root_required")
            print("ERROR: This program requires root privileges.")
            print("Run with: sudo python3 -m execution.orchestrator.main")
            sys.exit(1)

        logger.info("starting_kernel_security_monitor")

        # Initialize memory (load prior context)
        context = self.memory.initialize()
        if context:
            logger.info("prior_context_loaded", length=len(context))

        # Load eBPF sensor
        self.sensor.load()

        # Setup event loop
        self._loop = asyncio.new_event_loop()

        # Create perf buffer handlers
        handlers = create_handlers(
            bpf=self.sensor.bpf,
            submit_fn=lambda event: self.collector.submit_sync(event, self._loop),
        )
        self.sensor.open_perf_buffers(handlers)

        # Start BPF polling in background thread
        self._bpf_thread = threading.Thread(
            target=self._bpf_poll_loop,
            daemon=True,
            name="bpf-poller",
        )
        self._bpf_thread.start()

        # Register signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            self._loop.add_signal_handler(sig, self._handle_shutdown)

        # Print startup banner
        mode = "DRY-RUN (observe only)" if self.config.decision.dry_run else "ACTIVE (enforcement on)"
        if self.telegram:
            tg_status = "connected" if self.telegram.enabled else "disabled (no token)"
        else:
            tg_status = "not installed (pip install python-telegram-bot)"
        print("\n" + "=" * 60)
        print("  LINUX IA KERNEL - Security Monitor Active")
        print(f"  Mode: {mode}")
        print("  eBPF probes: 11 | Dimensions: 5 | Decision tiers: 3")
        print(f"  API: Anthropic ({self.config.decision.anthropic_model})")
        print(f"  Telegram: {tg_status}")
        print(f"  Log: {self.config.log_file}")
        print("=" * 60 + "\n")

        logger.info("system_ready",
                     probes=11, dimensions=5, tiers=3,
                     model=self.config.decision.anthropic_model)

        # Run async event loop
        try:
            self._loop.run_until_complete(self._async_main())
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

    async def _async_main(self) -> None:
        """Main async entry: run collector, telegram bot, and periodic sync."""
        # Start Telegram bot if configured
        if self.telegram:
            await self.telegram.start()

        # Start periodic memory sync
        self._sync_task = asyncio.create_task(self._periodic_sync())

        # Run the batch collector as a cancellable task
        self._collector_task = asyncio.create_task(self.collector.run())
        try:
            await self._collector_task
        except asyncio.CancelledError:
            pass

        # Stop Telegram bot on exit
        if self.telegram:
            await self.telegram.stop()

    def _get_stats(self) -> dict:
        """Return current session stats for Telegram /status command."""
        s = self.memory.stats
        return {
            "total_events": s.total_events,
            "tier1_count": s.tier1_count,
            "tier2_count": s.tier2_count,
            "tier3_count": s.tier3_count,
            "safe_count": s.safe_count,
            "limited_count": s.limited_count,
            "blocked_count": s.blocked_count,
        }

    async def _periodic_sync(self) -> None:
        """Periodically sync stats to claude-mem."""
        interval = self.config.memory.session_compress_interval_minutes * 60
        while self._running:
            try:
                await asyncio.sleep(interval)
                self.memory.periodic_sync()
            except asyncio.CancelledError:
                break

    def _bpf_poll_loop(self) -> None:
        """Runs in a background thread, polls BPF perf buffers."""
        logger.info("bpf_poll_thread_started")
        while self._running:
            try:
                self.sensor.poll(timeout_ms=100)
            except Exception as e:
                if self._running:
                    logger.error("bpf_poll_error", error=str(e))
                    time.sleep(0.1)

    def _handle_shutdown(self) -> None:
        """Signal handler for graceful shutdown. Guarded against double invocation."""
        if not self._running:
            return
        logger.info("shutdown_signal_received")
        print("\nShutting down gracefully...")
        self._running = False
        self.collector.stop()
        if self._sync_task:
            self._sync_task.cancel()
        if self._collector_task:
            self._collector_task.cancel()

    def _shutdown(self) -> None:
        """Clean up all resources."""
        # Wait for BPF thread to stop before cleaning sensor
        if self._bpf_thread and self._bpf_thread.is_alive():
            logger.info("waiting_for_bpf_thread")
            self._bpf_thread.join(timeout=2.0)

        logger.info("compressing_session")
        self.memory.compress_session()

        logger.info("cleaning_up_sensor")
        self.sensor.cleanup()

        self.memory.close()

        # Clean up event loop
        if self._loop and not self._loop.is_closed():
            self._loop.close()

        logger.info("shutdown_complete")
        print("Shutdown complete.")


def main():
    """CLI entry point."""
    config = AppConfig()
    setup_logging(log_level=config.log_level, log_file=config.log_file)
    monitor = KernelSecurityMonitor(config)
    monitor.start()


if __name__ == "__main__":
    main()
