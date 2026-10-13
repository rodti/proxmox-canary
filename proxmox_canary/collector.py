"""Read-only data collection from the Proxmox VE API.

Every call here is a GET. The API token only needs audit-level privileges
(see the README for the exact role).
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import urllib3
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException

from .config import Config
from .issues import classify, successful_login

log = logging.getLogger(__name__)

_CURSOR = re.compile(r"^s=[0-9a-f]+;i=[0-9a-f]+;")


class CollectorError(Exception):
    """The Proxmox API could not be reached at all."""


class CollectorCancelled(Exception):
    """The service is shutting down; stop making API calls."""


@dataclass
class Snapshot:
    taken_at: float
    since: float = 0.0  # start of the window logs and tasks were read from
    nodes: list[dict[str, Any]] = field(default_factory=list)
    guests: list[dict[str, Any]] = field(default_factory=list)
    storage: list[dict[str, Any]] = field(default_factory=list)
    zfs_pools: list[dict[str, Any]] = field(default_factory=list)
    disks: list[dict[str, Any]] = field(default_factory=list)
    failed_tasks: list[dict[str, Any]] = field(default_factory=list)
    log_errors: dict[str, list[str]] = field(default_factory=dict)
    updates: dict[str, int] = field(default_factory=dict)


class Collector:
    def __init__(self, cfg: Config, api: Any = None):
        self.cfg = cfg
        px = cfg.proxmox
        if api is None:
            if not px.verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            api = ProxmoxAPI(
                px.host,
                port=px.port,
                user=px.user,
                token_name=px.token_name,
                token_value=px.token_value,
                verify_ssl=px.verify_ssl,
                timeout=px.timeout,
            )
        self.api = api
        flags = re.IGNORECASE
        self._include = [re.compile(p, flags) for p in cfg.logs.include]
        self._ignore = [re.compile(p, flags) for p in cfg.logs.ignore]
        self._warned: set[str] = set()
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        """Stop a collection running in a worker thread after its current API call."""
        self._cancelled.set()

    # ------------------------------------------------------------------ helpers

    def _optional(self, what: str, fn: Callable[[], Any], default: Any, needs: str = "") -> Any:
        """Run an API call whose failure should not abort the whole check."""
        if self._cancelled.is_set():
            raise CollectorCancelled(what)
        try:
            return fn()
        except ResourceException as e:
            if what not in self._warned:
                self._warned.add(what)
                hint = ""
                if getattr(e, "status_code", None) in (401, 403):
                    hint = f" (the API token needs {needs})" if needs else " (check the API token's privileges)"
                log.warning("Skipping %s: %s%s", what, e, hint)
            return default
        except Exception as e:  # network hiccup on one node, etc.
            log.warning("Skipping %s: %s", what, e)
            return default

    def _is_error_line(self, line: str) -> bool:
        return any(p.search(line) for p in self._include) and not any(
            p.search(line) for p in self._ignore
        )

    # ------------------------------------------------------------------ collect

    def collect(self, since: float) -> Snapshot:
        """Gather everything needed for one check. `since` bounds logs and tasks."""
        if self._cancelled.is_set():
            raise CollectorCancelled("collect")
        snap = Snapshot(taken_at=time.time(), since=since)
        try:
            resources = self.api.cluster.resources.get()
        except Exception as e:
            raise CollectorError(f"cannot query /cluster/resources: {e}") from e

        ignore_guests = set(self.cfg.ignore_guests)
        ignore_storage = set(self.cfg.ignore_storage)
        snap.nodes = [r for r in resources if r.get("type") == "node"]
        online_nodes = {n.get("node") for n in snap.nodes if n.get("status") == "online"}
        seen_shared: set[str] = set()
        for r in resources:
            rtype = r.get("type")
            if rtype in ("qemu", "lxc"):
                if r.get("template") or r.get("vmid") in ignore_guests:
                    continue
                snap.guests.append(r)
            elif rtype == "storage":
                name = r.get("storage")
                # Storage on an offline node reads as 'unknown'; the node-down alert covers it.
                if name in ignore_storage or r.get("node") not in online_nodes:
                    continue
                if r.get("shared"):
                    if name in seen_shared:
                        continue
                    seen_shared.add(name)
                snap.storage.append(r)

        for node in [n["node"] for n in snap.nodes if n.get("status") == "online"]:
            self._collect_node(snap, node, since)

        tasks = self._optional("tasks", lambda: self.api.cluster.tasks.get(), [], "Sys.Audit")
        for t in tasks:
            end, status = t.get("endtime"), t.get("status")
            # A minute of overlap so a task finishing during the previous check is not missed;
            # duplicates are filtered later by the task's UPID.
            if not end or end < since - 60 or not status or status == "OK":
                continue
            t = dict(t)
            t["log_tail"] = self._task_log(t)
            snap.failed_tasks.append(t)
        return snap

    def _collect_node(self, snap: Snapshot, node: str, since: float) -> None:
        nd = self.api.nodes(node)

        for pool in self._optional(f"ZFS pools on {node}", lambda: nd.disks.zfs.get(), [], "Sys.Audit"):
            snap.zfs_pools.append({**pool, "node": node})

        for disk in self._optional(f"disk list on {node}", lambda: nd.disks.list.get(), [], "Sys.Audit"):
            snap.disks.append({**disk, "node": node})

        if self.cfg.logs.enabled:
            lines = self._optional(
                f"journal on {node}", lambda: nd.journal.get(since=int(since)), [], "Sys.Syslog"
            )
            # The reader returns a journal cursor as the first and last entries.
            generic: list[str] = []
            recognised: list[str] = []
            for line in lines:
                if not isinstance(line, str) or _CURSOR.match(line):
                    continue
                if any(p.search(line) for p in self._ignore):
                    continue
                if classify(line) or successful_login(line):
                    # Kept in full (up to a sanity cap): a brute-force run is counted, not sampled.
                    recognised.append(line)
                elif any(p.search(line) for p in self._include):
                    generic.append(line)
            matched = recognised[-50_000:] + generic[-self.cfg.logs.max_lines_per_node :]
            if matched:
                snap.log_errors[node] = matched

        if self.cfg.check_updates:
            pkgs = self._optional(f"update list on {node}", lambda: nd.apt.update.get(), None, "Sys.Modify")
            if pkgs is not None:
                snap.updates[node] = len(pkgs)

    def _task_log(self, task: dict[str, Any], tail: int = 25) -> list[str]:
        node, upid = task.get("node"), task.get("upid")
        if not node or not upid:
            return []
        entries = self._optional(
            "task logs", lambda: self.api.nodes(node).tasks(upid).log.get(limit=5000), [], "Sys.Audit"
        )
        return [str(e.get("t", "")) for e in entries if isinstance(e, dict)][-tail:]
