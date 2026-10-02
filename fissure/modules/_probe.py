"""Low-level helper for firing one payload at one injectable input.

Keeps the GET/POST plumbing in a single place so the SQLi/XSS/redirect modules
only have to describe *what* to inject and *how to recognize* a hit.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from ..crawler import Injectable
from ..http import Session


@dataclass
class Probe:
    status: int
    text: str
    headers: httpx.Headers
    elapsed: float  # seconds, wall-clock — used by time-based SQLi


def _payload_params(inj: Injectable, value: str) -> dict[str, str]:
    data = {name: val for name, val in inj.params}
    data[inj.param] = value
    return data


async def send(session: Session, inj: Injectable, value: str, *, follow_redirects: bool = False,
               headers: dict[str, str] | None = None) -> Probe:
    params = _payload_params(inj, value)
    start = time.perf_counter()
    if inj.method == "POST":
        resp = await session.client.post(inj.url, data=params, follow_redirects=follow_redirects, headers=headers)
    else:
        resp = await session.client.get(inj.url, params=params, follow_redirects=follow_redirects, headers=headers)
    elapsed = time.perf_counter() - start
    return Probe(status=resp.status_code, text=resp.text, headers=resp.headers, elapsed=elapsed)
