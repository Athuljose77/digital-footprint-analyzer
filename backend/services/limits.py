"""Process-wide limits for the analysis API.

The API runs real subprocesses and real network requests, so it must never be
possible for one caller (or one hung lookup) to consume the machine. These
limits bound how much work is in flight at once and how long a single analysis
may take, and they fail loudly instead of queueing forever.
"""

import asyncio
from contextlib import asynccontextmanager

# At most this many analyses run at the same time; further requests are told
# to come back instead of piling up.
MAX_INFLIGHT_ANALYSES = 3
BUSY_WAIT_SECONDS = 0.05

# Upper bound for one analysis, including its subprocesses. The individual
# services keep their own shorter budgets; this is the backstop.
ANALYSIS_TIMEOUT_SECONDS = 150.0


class ServerBusy(Exception):
    """Raised when the analyser already has its hands full."""


class AnalysisTimeout(Exception):
    """Raised when one analysis exceeded the server-side budget."""


_slots = asyncio.Semaphore(MAX_INFLIGHT_ANALYSES)

_TIMEOUT_AVAILABLE = hasattr(asyncio, "timeout")


@asynccontextmanager
async def limited_analysis(timeout: float = ANALYSIS_TIMEOUT_SECONDS):
    """Run one analysis inside the concurrency and time limits."""

    try:
        await asyncio.wait_for(_slots.acquire(), BUSY_WAIT_SECONDS)
    except (asyncio.TimeoutError, TimeoutError):
        raise ServerBusy(
            "The analyzer is already running other scans. Try again in a moment."
        )

    try:
        if _TIMEOUT_AVAILABLE:
            try:
                async with asyncio.timeout(timeout) as guard:
                    yield
            except TimeoutError:
                if guard.expired():
                    raise AnalysisTimeout(
                        "The analysis took too long and was stopped."
                    )
                raise
        else:  # Python < 3.11: the services' own timeouts still apply.
            yield
    finally:
        _slots.release()
