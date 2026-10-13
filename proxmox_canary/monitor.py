"""One check cycle: collect, evaluate, look up, diagnose. Sending is done by the caller."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .collector import Collector, Snapshot
from .config import Config
from .llm import Diagnoser
from .lookup import WebLookup
from .rules import CRITICAL, Finding, evaluate
from .state import State

log = logging.getLogger(__name__)


@dataclass
class Report:
    findings: list[Finding]
    new: list[Finding]
    repeat: list[Finding]
    resolved: list[dict[str, Any]]
    complete: bool
    checked_at: float | None
    overview: str | None = None
    diagnoses: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def has_news(self) -> bool:
        return bool(self.new or self.repeat or self.resolved)


class Monitor:
    def __init__(self, cfg: Config, persist: bool = True, collector: Collector | None = None):
        self.cfg = cfg
        self.state = State.load(cfg.state_file if persist else None)
        self.collector = collector or Collector(cfg)
        self.diagnoser = Diagnoser(cfg.ollama)
        self.lookup = WebLookup(cfg.lookup) if cfg.lookup.enabled else None
        self._lock: asyncio.Lock | None = None

    @property
    def lock(self) -> asyncio.Lock:
        # Created on first use, inside the running event loop: on Python 3.9 a Lock made
        # outside a loop binds to a default loop and fails under asyncio.run().
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _private_terms(self, snap: Snapshot | None) -> set[str]:
        terms = {self.cfg.proxmox.host, self.cfg.proxmox.user, self.cfg.proxmox.token_name}
        if snap:
            terms |= {str(n.get("node", "")) for n in snap.nodes}
            terms |= {str(g.get("name", "")) for g in snap.guests}
            terms |= {str(s.get("storage", "")) for s in snap.storage}
            terms |= {str(p.get("name", "")) for p in snap.zfs_pools}
        # Generic words that happen to be names would wreck queries.
        return {t for t in terms if t and t.lower() not in {"local", "local-lvm", "rpool", "pve", "root"}}

    async def _gather_references(self, findings: list[Finding], snap: Snapshot | None) -> dict[str, list[dict[str, str]]]:
        if not self.lookup:
            return {}
        private = self._private_terms(snap)
        budget = self.cfg.lookup.max_lookups_per_check
        now = time.time()
        refs: dict[str, list[dict[str, str]]] = {}
        # Critical findings get the lookup budget first.
        for f in sorted(findings, key=lambda f: f.severity != CRITICAL):
            seen_urls: set[str] = set()
            collected: list[dict[str, str]] = []
            for msg in f.lookup_messages:
                query = self.lookup.build_query(msg, private)
                if not query:
                    continue
                cached = self.state.lookups.get(query)
                if cached is not None:
                    sources = cached["results"]
                elif budget > 0:
                    budget -= 1
                    log.info("Looking up: %s", query)
                    sources = await self.lookup.research(query)
                    if sources:  # don't cache failures, so the next check can try again
                        self.state.lookups[query] = {"at": now, "results": sources}
                else:
                    break
                for s in sources:
                    if s["url"] not in seen_urls:
                        seen_urls.add(s["url"])
                        collected.append(s)
            if collected:
                refs[f.key] = [dict(s, id=f"R{i + 1}") for i, s in enumerate(collected[:6])]
        return refs

    async def check(self, explain_all: bool = False) -> Report:
        now = time.time()
        since = self.state.last_check or now - self.cfg.initial_lookback_minutes * 60
        # A CollectorError (Proxmox API unreachable) propagates: that is the canary failing,
        # not a finding, so the caller logs it and posts only a friendly notice.
        snap = await asyncio.to_thread(self.collector.collect, since)
        findings = evaluate(snap, self.cfg, self.state)
        complete, checked_at = True, snap.taken_at

        new, repeat, resolved = self.state.diff(findings, now, self.cfg.renotify_hours * 3600, complete)
        if not self.cfg.send_resolved:
            resolved = []
        report = Report(findings, new, repeat, resolved, complete, checked_at)

        pool = findings if explain_all else new
        to_explain = [f for f in pool if f.severity != "info"]
        if to_explain:
            refs = await self._gather_references(to_explain, snap)
            result = await self.diagnoser.diagnose(to_explain, refs)
            if result:
                report.overview, report.diagnoses = result
        return report

    def commit(self, report: Report) -> None:
        keys = {f.key for f in report.new + report.repeat}
        self.state.commit(report.findings, keys, time.time(), report.checked_at, report.complete)
