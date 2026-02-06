"""Event batch collector with time/size windowed processing."""
from __future__ import annotations
import asyncio
from datetime import datetime
from typing import TYPE_CHECKING, Optional
import structlog

from ..models import BaseEvent, DecisionResult
from ..config import BatchingConfig
from ..decision.engine import DecisionEngine
from ..actions.executor import ActionExecutor
from ..memory.bridge import MemoryBridge

if TYPE_CHECKING:
    from ..telegram.bot import TelegramBot

logger = structlog.get_logger("batch_collector")


class EventBatchCollector:
    """Collects kernel events and processes them in batches.

    Batches are flushed when either:
    - batch_window_seconds has elapsed since the first event
    - max_batch_size events have accumulated
    """

    def __init__(
        self,
        config: BatchingConfig,
        engine: DecisionEngine,
        executor: ActionExecutor,
        memory: MemoryBridge,
        telegram_bot: Optional[TelegramBot] = None,
    ):
        self.window = config.batch_window_seconds
        self.max_size = config.max_batch_size
        self.engine = engine
        self.executor = executor
        self.memory = memory
        self.telegram_bot = telegram_bot
        self.queue: asyncio.Queue[BaseEvent] = asyncio.Queue()
        self._batch: list[BaseEvent] = []
        self._batch_start: Optional[float] = None
        self._running = True

    def submit_sync(self, event: BaseEvent, loop: asyncio.AbstractEventLoop) -> None:
        """Thread-safe submission from BPF polling thread."""
        asyncio.run_coroutine_threadsafe(self.queue.put(event), loop)

    async def run(self) -> None:
        """Main processing loop. Runs on the asyncio event loop."""
        logger.info("batch_collector_started",
                    window=self.window, max_size=self.max_size)

        while self._running:
            try:
                timeout = self._remaining_window()
                event = await asyncio.wait_for(
                    self.queue.get(), timeout=timeout
                )
                self._batch.append(event)
                if self._batch_start is None:
                    self._batch_start = datetime.now().timestamp()

                if len(self._batch) >= self.max_size:
                    await self._flush()

            except asyncio.TimeoutError:
                if self._batch:
                    await self._flush()
            except asyncio.CancelledError:
                if self._batch:
                    await self._flush()
                break

    async def _flush(self) -> None:
        """Process the accumulated batch."""
        batch = self._batch
        self._batch = []
        self._batch_start = None

        if not batch:
            return

        logger.debug("flushing_batch", size=len(batch))

        for event in batch:
            try:
                result: DecisionResult = self.engine.decide(event)
                self.executor.execute(result)
                self.memory.record_decision(
                    tier=result.tier.value,
                    decision_name=result.decision.name,
                )
                # Send Telegram alert for non-SAFE decisions
                if self.telegram_bot:
                    try:
                        await self.telegram_bot.notify_alert(result)
                    except Exception as tg_err:
                        logger.error("telegram_notify_error", error=str(tg_err))
            except Exception as e:
                logger.error("event_processing_error",
                             error=str(e), comm=event.comm, pid=event.pid)
            # Yield control to event loop so Telegram polling can run
            await asyncio.sleep(0)

    def _remaining_window(self) -> float:
        """Calculate remaining time in the current batch window."""
        if self._batch_start is None:
            return self.window
        elapsed = datetime.now().timestamp() - self._batch_start
        remaining = max(0.01, self.window - elapsed)
        return remaining

    def stop(self) -> None:
        """Signal the collector to stop."""
        self._running = False
