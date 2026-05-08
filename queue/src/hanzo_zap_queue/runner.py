"""Async task runner with handler registry.

Resumable across process restarts: each handler accepts a `ctx` whose
`checkpoint(progress)` persists state. On crash + restart, the next
claim() returns the same task with its last checkpoint, the handler
reads `task.progress` and continues from there.
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .queue import Queue, Task, TaskStatus

logger = logging.getLogger("hanzo_zap_queue")

Handler = Callable[["Task", "RunCtx"], Awaitable[dict[str, Any] | None]]


@dataclass
class RunCtx:
    """Passed to every task handler. Use `checkpoint()` to persist progress."""

    task: Task
    queue: Queue

    def checkpoint(self, progress: dict[str, Any]) -> None:
        self.queue.checkpoint(self.task.id, progress)
        # Keep our in-memory copy current so handlers reading task.progress
        # mid-run don't see stale state.
        self.task.progress = dict(progress)


class TaskRunner:
    def __init__(self, queue: Queue) -> None:
        self.queue = queue
        self._handlers: dict[str, Handler] = {}
        self._stop = asyncio.Event()

    def handler(self, kind: str) -> Callable[[Handler], Handler]:
        """Decorator: register a handler for a task kind."""
        def _wrap(fn: Handler) -> Handler:
            self._handlers[kind] = fn
            return fn
        return _wrap

    def register(self, kind: str, fn: Handler) -> None:
        self._handlers[kind] = fn

    async def run_once(self) -> bool:
        """Claim and run a single task. Returns True if work was done."""
        # Iterate registered kinds in insertion order to be predictable.
        for kind in list(self._handlers.keys()):
            task = self.queue.claim(kind=kind)
            if task is None:
                continue
            await self._dispatch(task)
            return True
        return False

    async def run_forever(self, poll_interval: float = 1.0) -> None:
        """Loop: claim a task, run it, repeat. Sleeps `poll_interval` when idle."""
        while not self._stop.is_set():
            did = await self.run_once()
            if not did:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=poll_interval)
                except asyncio.TimeoutError:
                    pass

    def stop(self) -> None:
        self._stop.set()

    async def _dispatch(self, task: Task) -> None:
        handler = self._handlers.get(task.kind)
        if handler is None:
            self.queue.fail(task.id, f"no handler registered for kind={task.kind}", retry=False)
            return
        ctx = RunCtx(task=task, queue=self.queue)
        try:
            logger.info("task %s/%s start (attempt %d/%d)",
                        task.kind, task.id, task.attempts, task.max_attempts)
            result = await handler(task, ctx)
            self.queue.complete(task.id, result)
            logger.info("task %s/%s done", task.kind, task.id)
        except asyncio.CancelledError:
            self.queue.fail(task.id, "cancelled", retry=True)
            raise
        except Exception as e:
            tb = traceback.format_exc()
            logger.warning("task %s/%s failed: %s\n%s", task.kind, task.id, e, tb)
            self.queue.fail(task.id, f"{type(e).__name__}: {e}", retry=True)
