"""Persistent state: active alerts, storage trends, notification dedupe, lookup cache."""
from __future__ import annotations

import json
import logging
import os
import tempfile
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .rules import Finding

log = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


class State:
    def __init__(self, path: str | os.PathLike | None):
        self.path = Path(path) if path else None
        self.last_check: float | None = None
        self.active: dict[str, dict[str, Any]] = {}
        self.trends: dict[str, list[list[float]]] = {}
        self.recent: dict[str, float] = {}
        self.lookups: dict[str, dict[str, Any]] = {}
        # When the canary itself started failing; set once "Oops" has been posted.
        self.broken_since: float | None = None
        self._samples: dict[str, deque] = {}

    # ------------------------------------------------------------- persistence

    @classmethod
    def load(cls, path: str | os.PathLike | None) -> State:
        s = cls(path)
        if s.path and s.path.exists():
            try:
                data = json.loads(s.path.read_text())
                s.last_check = data.get("last_check")
                s.active = data.get("active", {})
                s.trends = data.get("trends", {})
                s.recent = data.get("recent", {})
                s.lookups = data.get("lookups", {})
                s.broken_since = data.get("broken_since")
            except (OSError, ValueError) as e:
                log.warning("Could not read state file %s, starting fresh: %s", s.path, e)
        return s

    def save(self) -> None:
        if not self.path:
            return
        data = {
            "last_check": self.last_check,
            "active": self.active,
            "trends": self.trends,
            "recent": self.recent,
            "lookups": self.lookups,
            "broken_since": self.broken_since,
        }
        # A failed save must not raise: the alerts have already gone out by now, and the
        # in-memory state is still correct, so the service keeps running without repeats.
        tmp = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".canary-state.")
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except OSError as e:
            log.error("Could not write state file %s: %s", self.path, e)
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # ----------------------------------------------------------------- metrics

    def samples(self, key: str, n: int) -> deque:
        d = self._samples.get(key)
        if d is None or d.maxlen != n:
            d = deque(d or [], maxlen=n)
            self._samples[key] = d
        return d

    def forget_samples(self, *keys: str) -> None:
        for k in keys:
            self._samples.pop(k, None)

    def record_trend(self, key: str, ts: float, value: float, window_s: float) -> list[list[float]]:
        cutoff = ts - window_s
        pts = [p for p in self.trends.get(key, []) if p[0] >= cutoff]
        pts.append([ts, float(value)])
        self.trends[key] = pts
        return pts

    def prune(self, now: float, trend_window_s: float, keep_recent_s: float, lookup_ttl_s: float) -> None:
        self.trends = {
            k: v for k, v in self.trends.items() if v and v[-1][0] >= now - trend_window_s
        }
        self.recent = {k: t for k, t in self.recent.items() if now - t < keep_recent_s}
        self.lookups = {
            k: v for k, v in self.lookups.items() if now - v.get("at", 0) < lookup_ttl_s
        }

    def recently_notified(self, key: str, now: float, window_s: float) -> bool:
        ts = self.recent.get(key)
        return ts is not None and now - ts < window_s

    # ----------------------------------------------------------- notifications

    def diff(
        self, findings: list[Finding], now: float, renotify_s: float, complete: bool
    ) -> tuple[list[Finding], list[Finding], list[dict[str, Any]]]:
        """Split findings into new alerts, reminders, and conditions that have cleared."""
        new, repeat = [], []
        for f in findings:
            if f.kind == "event":
                new.append(f)
                continue
            a = self.active.get(f.key)
            if a is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK.get(a.get("severity"), 0):
                new.append(f)
            elif f.severity != "info" and now - a.get("last_notified", 0) >= renotify_s:
                repeat.append(f)
        resolved: list[dict[str, Any]] = []
        if complete:
            current = {f.key for f in findings}
            resolved = [dict(a, key=k) for k, a in self.active.items() if k not in current]
        return new, repeat, resolved

    def commit(
        self,
        findings: list[Finding],
        notified_keys: set[str],
        now: float,
        checked_at: float | None,
        complete: bool,
    ) -> None:
        """Record what was sent. Only called after Discord accepted the alerts."""
        conditions = {f.key: f for f in findings if f.kind == "condition"}
        if complete:
            for k in list(self.active):
                if k not in conditions:
                    del self.active[k]
        for k, f in conditions.items():
            entry = self.active.setdefault(k, {"first_seen": now, "last_notified": 0.0})
            entry["severity"] = f.severity
            entry["title"] = f.title
            if k in notified_keys:
                entry["last_notified"] = now
        for f in findings:
            if f.key in notified_keys:
                for dk in f.dedupe_keys:
                    self.recent[dk] = now
        if checked_at is not None:
            self.last_check = checked_at
        self.save()
