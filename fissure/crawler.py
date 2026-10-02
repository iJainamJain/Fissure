"""Same-host crawler that harvests injectable inputs.

The active modules do not guess URLs; they test what the crawler finds. Each
:class:`Injectable` names one place a value can be injected: a URL query
parameter (GET) or a form field (GET or POST). Discovery is breadth-first,
bounded by page and depth limits, and never leaves the target host.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .http import Session
from .targets import Target

# Links that would end or reset the scanning session if followed. The crawler
# skips any URL whose path contains one of these (e.g. DVWA's logout / DB reset).
DANGEROUS_PATH_TOKENS = ("logout", "signout", "sign-out", "setup.php")


@dataclass(frozen=True)
class Injectable:
    method: str  # "GET" or "POST"
    url: str  # action URL (no query string)
    param: str  # the field/parameter name to fuzz
    params: tuple[tuple[str, str], ...]  # all baseline params (name, value) for context

    def key(self) -> tuple[str, str, str]:
        return (self.method, self.url, self.param)


@dataclass
class PageResponse:
    """Response metadata captured during the crawl, for passive modules."""

    url: str
    status: int
    headers: dict[str, str]  # case-insensitive keys lowered; multi Set-Cookie excluded
    set_cookie: list[str]  # raw Set-Cookie header values, preserved individually
    content_type: str


@dataclass
class CrawlResult:
    pages: list[str] = field(default_factory=list)
    injectables: list[Injectable] = field(default_factory=list)
    responses: list[PageResponse] = field(default_factory=list)


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs_list) -> None:
        attrs = dict(attrs_list)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "form":
            self._form = {"action": attrs.get("action", ""), "method": (attrs.get("method") or "get").lower(), "inputs": []}
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            name = attrs.get("name")
            if name:
                self._form["inputs"].append((name, attrs.get("value", "test")))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class Crawler:
    def __init__(self, target: Target, session: Session, *, max_pages: int = 25, max_depth: int = 2, delay: float = 0.0) -> None:
        self.target = target
        self.session = session
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay

    async def crawl(self) -> CrawlResult:
        result = CrawlResult()
        seen_pages: set[str] = set()
        seen_injectables: set[tuple[str, str, str]] = set()
        queue: deque[tuple[str, int]] = deque([(self.target.start_url, 0)])

        while queue and len(seen_pages) < self.max_pages:
            url, depth = queue.popleft()
            if url in seen_pages:
                continue
            seen_pages.add(url)

            # A URL with its own query string is itself injectable.
            for inj in self._injectables_from_url(url):
                if inj.key() not in seen_injectables:
                    seen_injectables.add(inj.key())
                    result.injectables.append(inj)

            try:
                resp = await self.session.client.get(url, follow_redirects=True)
            except Exception:
                continue

            # Capture response metadata for passive modules (headers/cookies),
            # for every fetched URL — not only HTML — at no extra request cost.
            result.responses.append(PageResponse(
                url=str(resp.url),
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                set_cookie=resp.headers.get_list("set-cookie"),
                content_type=resp.headers.get("content-type", ""),
            ))

            if "text/html" not in resp.headers.get("content-type", ""):
                continue
            result.pages.append(url)

            parser = _LinkFormParser()
            parser.feed(resp.text)

            for form in parser.forms:
                for inj in self._injectables_from_form(url, form):
                    if inj.key() not in seen_injectables:
                        seen_injectables.add(inj.key())
                        result.injectables.append(inj)

            if depth < self.max_depth:
                for href in parser.links:
                    nxt = self._same_host(url, href)
                    if nxt and nxt not in seen_pages:
                        queue.append((nxt, depth + 1))

            if self.delay:
                await asyncio.sleep(self.delay)

        return result

    def _injectables_from_url(self, url: str) -> list[Injectable]:
        split = urlsplit(url)
        pairs = tuple(parse_qsl(split.query))
        if not pairs:
            return []
        clean = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
        return [Injectable("GET", clean, name, pairs) for name, _ in pairs]

    def _injectables_from_form(self, page_url: str, form: dict) -> list[Injectable]:
        action = urljoin(page_url, form["action"]) if form["action"] else page_url
        if urlsplit(action).hostname != self.target.hostname:
            return []
        pairs = tuple(form["inputs"])
        method = "POST" if form["method"] == "post" else "GET"
        return [Injectable(method, action, name, pairs) for name, _ in pairs]

    def _same_host(self, base: str, href: str) -> str | None:
        joined = urljoin(base, href)
        split = urlsplit(joined)
        if split.scheme not in {"http", "https"} or split.hostname != self.target.hostname:
            return None
        if any(token in split.path.lower() for token in DANGEROUS_PATH_TOKENS):
            return None
        return urlunsplit((split.scheme, split.netloc, split.path, split.query, ""))
