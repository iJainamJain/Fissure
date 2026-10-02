"""Bounded-concurrency helper for per-input module scanning.

Runs an async function over many items with at most `concurrency` in flight,
preserving input order in the results. Used by the non-timing modules to speed
up scans; time-based modules (sqli, cmdi) stay sequential so a queued sleep
can't inflate another request's measured latency.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


async def map_bounded(items: list[T], fn: Callable[[T], Awaitable[R]], concurrency: int) -> list[R]:
    if concurrency <= 1 or len(items) <= 1:
        return [await fn(it) for it in items]
    sem = asyncio.Semaphore(concurrency)

    async def _run(it: T) -> R:
        async with sem:
            return await fn(it)

    return await asyncio.gather(*(_run(it) for it in items))
