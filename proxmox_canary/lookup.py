"""Look up error messages on the web so the model can cite known causes and fixes.

Log text is scrubbed before it leaves your network: IPs, MACs, e-mail and
user@realm strings, UUIDs, long hex/number runs, home paths and your node,
guest and storage names are removed. Add anything else to `lookup.redact`.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from .config import LookupConfig

log = logging.getLogger(__name__)

BRAVE_URL = "https://api.search.brave.com/res/v1/web/search"
USER_AGENT ="Mozilla/5.0 (X11; Linux x86_64) proxmox-canary/0.1 (+self-hosted monitoring)"

_SCRUB = [
    re.compile(r"\b[\w.+-]+@[\w.-]+\b"),  # e-mail, user@realm
    re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.I),  # MAC
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?(?::\d+)?\b"),  # IPv4
    re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.I),  # IPv6, incl. "::"
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),  # UUID
    re.compile(r"\b\d{4}-\d\d-\d\d(?:[T ]\d\d:\d\d(?::\d\d)?\S*)?"),  # dates and timestamps
    re.compile(r"\b(?:0x)?[0-9a-f]{8,}\b", re.I),  # long hex
    re.compile(r"\b\d{3,}\b"),  # sectors, counters, ports, PIDs
    re.compile(r"(?:/home|/root|/Users)/\S*"),
    re.compile(r"UPID:\S+"),
]


def scrub(text: str, private_terms: set[str], extra: list[re.Pattern]) -> str:
    out = text
    # Structured patterns first: removing names first would split things like UPIDs apart.
    for p in _SCRUB + extra:
        out = p.sub(" ", out)
    for term in sorted((t for t in private_terms if t and len(t) >= 3), key=len, reverse=True):
        # Whole words only, so a guest called "plex" doesn't mangle "complex".
        out = re.sub(rf"(?<!\w){re.escape(term)}(?!\w)", " ", out, flags=re.I)
    out = re.sub(r"[\[\](){}<>'\"`|=,;]+", " ", out)
    return re.sub(r"\s+", " ", out).strip()[:200]


class WebLookup:
    def __init__(self, cfg: LookupConfig):
        self.cfg = cfg
        self._extra = [re.compile(p, re.I) for p in cfg.redact]

    def build_query(self, message: str, private_terms: set[str]) -> str:
        text = scrub(message, private_terms, self._extra)
        words = text.split()
        # Long kernel lines bury the useful part; keep the first ~14 words.
        query = " ".join(words[:14])
        if len(query) < 12:
            return ""
        prefix = self.cfg.query_prefix.strip()
        return f"{prefix} {query}" if prefix and prefix.lower() not in query.lower() else query

    # ------------------------------------------------------------------ search

    async def search(self, query: str) -> list[dict[str, str]]:
        n = self.cfg.results_per_query
        try:
            if self.cfg.provider == "ddgs":
                results = await asyncio.to_thread(self._ddgs, query, n)
            elif self.cfg.provider == "searxng":
                results = await self._searxng(query, n)
            else:
                results = await self._brave(query, n)
        except Exception as e:
            log.warning("Web search failed for %r: %s", query, e)
            return []
        return self._rank([r for r in results if r.get("url", "").startswith("http")])

    @staticmethod
    def _ddgs(query: str, n: int) -> list[dict[str, str]]:
        from ddgs import DDGS

        rows = DDGS().text(query, max_results=n) or []
        return [{"title": r.get("title", ""), "url": r.get("href", ""), "snippet": r.get("body", "")} for r in rows]

    async def _searxng(self, query: str, n: int) -> list[dict[str, str]]:
        url = self.cfg.searxng_url.rstrip("/") + "/search"
        async with httpx.AsyncClient(timeout=self.cfg.timeout) as client:
            r = await client.get(url, params={"q": query, "format": "json"}, headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            rows = r.json().get("results", [])[:n]
        return [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": x.get("content", "")} for x in rows]

    async def _brave(self, query: str, n: int) -> list[dict[str, str]]:
        async with httpx.AsyncClient(timeout=self.cfg.timeout) as client:
            r = await client.get(
                BRAVE_URL,
                params={"q": query, "count": n},
                headers={"X-Subscription-Token": self.cfg.brave_api_key, "Accept": "application/json"},
            )
            r.raise_for_status()
            rows = r.json().get("web", {}).get("results", [])[:n]
        return [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": x.get("description", "")} for x in rows]

    def _rank(self, results: list[dict[str, str]]) -> list[dict[str, str]]:
        prefs = [d.lower() for d in self.cfg.preferred_domains]

        def score(item: tuple[int, dict[str, str]]) -> tuple[int, int]:
            idx, r = item
            host = (urlparse(r["url"]).hostname or "").lower()
            for i, d in enumerate(prefs):
                if host == d or host.endswith("." + d):
                    return (i, idx)
            return (len(prefs), idx)

        return [r for _, r in sorted(enumerate(results), key=score)]

    # ------------------------------------------------------------------- fetch

    async def fetch_text(self, client: httpx.AsyncClient, url: str) -> str:
        try:
            r = await client.get(url)
            r.raise_for_status()
            if "html" not in r.headers.get("content-type", ""):
                return ""
        except httpx.HTTPError as e:
            log.debug("Could not fetch %s: %s", url, e)
            return ""
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style", "nav", "header", "footer", "aside", "form", "noscript", "svg"]):
            tag.decompose()
        # Forum posts and Q&A answers usually sit in <article>; fall back to <main>, then <body>.
        blocks = soup.find_all("article") or ([soup.main] if soup.main else []) or ([soup.body] if soup.body else [])
        text = " ".join(b.get_text(" ", strip=True) for b in blocks if b)
        return re.sub(r"\s+", " ", text)[: self.cfg.max_chars_per_page]

    async def research(self, query: str) -> list[dict[str, str]]:
        """Search, then read the best few pages. Returns [{title, url, excerpt}]."""
        results = await self.search(query)
        if not results:
            return []
        picked = results[: self.cfg.pages_to_read]
        async with httpx.AsyncClient(
            timeout=self.cfg.timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT}
        ) as client:
            texts = await asyncio.gather(*(self.fetch_text(client, r["url"]) for r in picked))
        sources: list[dict[str, Any]] = []
        for r, text in zip(picked, texts):  # same length: one text per picked result
            sources.append({"title": r["title"][:200], "url": r["url"], "excerpt": text or r.get("snippet", "")})
        # Unread results still help as snippets.
        for r in results[self.cfg.pages_to_read :]:
            if r.get("snippet"):
                sources.append({"title": r["title"][:200], "url": r["url"], "excerpt": r["snippet"][:400]})
        return sources
