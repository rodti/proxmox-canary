"""Turn a snapshot into findings. Plain thresholds and trends; no LLM involved."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from .collector import Snapshot
from .config import Config
from .state import State

CRITICAL, WARNING, INFO = "critical", "warning", "info"


@dataclass
class Finding:
    key: str
    severity: str
    title: str
    detail: str
    kind: str = "condition"  # "condition" persists until it clears; "event" is one-off
    context: list[str] = field(default_factory=list)  # evidence lines for the LLM and Discord
    lookup_messages: list[str] = field(default_factory=list)  # error text worth searching
    dedupe_keys: list[str] = field(default_factory=list)


# ------------------------------------------------------------------- helpers


def _pct(used: Any, total: Any) -> float:
    try:
        return 100.0 * float(used) / float(total) if total else 0.0
    except (TypeError, ValueError):
        return 0.0


def fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def _sustained(state: State, key: str, value: float, threshold: float, n: int) -> bool:
    hist = state.samples(key, n)
    hist.append(value)
    return len(hist) >= n and all(v >= threshold for v in hist)


def _guest_label(g: dict[str, Any]) -> str:
    kind = "VM" if g.get("type") == "qemu" else "CT"
    return f"{kind} {g.get('vmid')} ({g.get('name', '?')})"


def _top_guests(snap: Snapshot, node: str, metric: str, n: int = 3) -> str:
    running = [g for g in snap.guests if g.get("node") == node and g.get("status") == "running"]
    if metric == "cpu":
        ranked = sorted(running, key=lambda g: float(g.get("cpu") or 0) * float(g.get("maxcpu") or 1), reverse=True)
        parts = [f"{_guest_label(g)} {float(g.get('cpu') or 0) * float(g.get('maxcpu') or 1):.1f} cores" for g in ranked[:n]]
    else:
        ranked = sorted(running, key=lambda g: float(g.get("mem") or 0), reverse=True)
        parts = [f"{_guest_label(g)} {fmt_bytes(g.get('mem') or 0)}" for g in ranked[:n]]
    return ("Top guests: " + ", ".join(parts) + ".") if parts else ""


def _days_to_full(points: list[list[float]], used: float, total: float, min_span_s: float = 3600):
    """Least-squares growth rate over the window. Returns (days, bytes_per_day, span_h) or None."""
    if len(points) < 4:
        return None
    span = points[-1][0] - points[0][0]
    if span < min_span_s:
        return None
    n = len(points)
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    den = sum((p[0] - mx) ** 2 for p in points)
    if den == 0:
        return None
    slope = sum((p[0] - mx) * (p[1] - my) for p in points) / den  # bytes per second
    if slope <= 0:
        return None
    per_day = slope * 86400
    return max(total - used, 0) / per_day, per_day, span / 3600


_JOURNAL_PREFIX = re.compile(r"^\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+\S+\s+")
_ISO_PREFIX = re.compile(r"^\d{4}-\d\d-\d\dT\S+\s+\S+\s+")
_PID = re.compile(r"\[\d+\]")


def clean_log_line(line: str) -> str:
    """Drop the timestamp/host prefix and PIDs so repeated messages group together."""
    msg = _JOURNAL_PREFIX.sub("", line)
    msg = _ISO_PREFIX.sub("", msg)
    return _PID.sub("", msg).strip()[:400]


def group_key(msg: str) -> str:
    """Looser key for dedupe: numbers vary (sectors, counters) but the problem is the same."""
    return re.sub(r"0x[0-9a-f]+|\d+", "#", msg.lower())


@lru_cache(maxsize=8)
def _compile(patterns: tuple[str, ...]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# --------------------------------------------------------------------- rules


def evaluate(snap: Snapshot, cfg: Config, state: State) -> list[Finding]:
    t = cfg.thresholds
    out: list[Finding] = []
    renotify_s = cfg.renotify_hours * 3600

    # Nodes
    for n in snap.nodes:
        name = n.get("node", "?")
        status = n.get("status", "unknown")
        if status != "online":
            out.append(Finding(
                f"node-down:{name}", CRITICAL, f"Node {name} is {status}",
                "The cluster reports this node as not online. Its guests, storage and logs "
                "cannot be checked until it is back.",
            ))
            continue
        cpu = float(n.get("cpu") or 0) * 100
        mem = _pct(n.get("mem"), n.get("maxmem"))
        root = _pct(n.get("disk"), n.get("maxdisk"))
        if _sustained(state, f"node-cpu:{name}", cpu, t.node_cpu_pct, t.sustained_samples):
            out.append(Finding(
                f"node-cpu:{name}", WARNING, f"High CPU on node {name}",
                f"CPU at {cpu:.0f}% across the last {t.sustained_samples} check(s) "
                f"(threshold {t.node_cpu_pct:.0f}%). {_top_guests(snap, name, 'cpu')}",
            ))
        if _sustained(state, f"node-mem:{name}", mem, t.node_mem_pct, t.sustained_samples):
            out.append(Finding(
                f"node-mem:{name}", CRITICAL if mem >= 97 else WARNING, f"High memory use on node {name}",
                f"RAM at {mem:.0f}% ({fmt_bytes(n.get('mem') or 0)} of {fmt_bytes(n.get('maxmem') or 0)}) "
                f"across the last {t.sustained_samples} check(s). {_top_guests(snap, name, 'mem')} "
                "If ZFS is in use, the ARC counts as used memory but is released under pressure.",
            ))
        if root >= t.node_rootfs_pct:
            out.append(Finding(
                f"node-rootfs:{name}", CRITICAL if root >= 95 else WARNING,
                f"Root filesystem on {name} is {root:.0f}% full",
                f"{fmt_bytes(n.get('disk') or 0)} of {fmt_bytes(n.get('maxdisk') or 0)} used.",
            ))

    # Guests
    for g in snap.guests:
        gid = f"{g.get('type')}/{g.get('vmid')}"
        if g.get("status") != "running":
            # Forget old samples so a restart doesn't alert on stale readings.
            state.forget_samples(f"guest-cpu:{gid}", f"guest-mem:{gid}")
            continue
        label = f"{_guest_label(g)} on {g.get('node')}"
        cpu = float(g.get("cpu") or 0) * 100
        mem = _pct(g.get("mem"), g.get("maxmem"))
        if _sustained(state, f"guest-cpu:{gid}", cpu, t.guest_cpu_pct, t.sustained_samples):
            out.append(Finding(
                f"guest-cpu:{gid}", WARNING, f"{label} is CPU-bound",
                f"Using {cpu:.0f}% of its {g.get('maxcpu', '?')} vCPU(s) across the last "
                f"{t.sustained_samples} check(s).",
            ))
        if _sustained(state, f"guest-mem:{gid}", mem, t.guest_mem_pct, t.sustained_samples):
            out.append(Finding(
                f"guest-mem:{gid}", WARNING, f"{label} is near its memory limit",
                f"{fmt_bytes(g.get('mem') or 0)} of {fmt_bytes(g.get('maxmem') or 0)} ({mem:.0f}%). "
                "For VMs without the guest agent or ballooning this includes the guest's page cache.",
            ))

    # Storage
    window_s = t.storage_trend_window_hours * 3600
    for s in snap.storage:
        name, node = s.get("storage", "?"), s.get("node", "?")
        sid = name if s.get("shared") else f"{node}/{name}"
        label = f"{name} (shared)" if s.get("shared") else f"{name} on {node}"
        if s.get("status") != "available":
            out.append(Finding(
                f"storage-unavailable:{sid}", WARNING, f"Storage {label} is unavailable",
                f"Status reported as '{s.get('status', 'unknown')}'. If this storage is "
                "disabled on purpose, add it to ignore_storage.",
            ))
            continue
        used, total = float(s.get("disk") or 0), float(s.get("maxdisk") or 0)
        if not total:
            continue
        pct = _pct(used, total)
        sev = CRITICAL if pct >= t.storage_crit_pct else WARNING if pct >= t.storage_warn_pct else None
        if sev:
            out.append(Finding(
                f"storage-full:{sid}", sev, f"Storage {label} is {pct:.0f}% full",
                f"{fmt_bytes(used)} of {fmt_bytes(total)} used, {fmt_bytes(total - used)} free.",
            ))
        trend = _days_to_full(state.record_trend(f"storage:{sid}", snap.taken_at, used, window_s), used, total)
        if trend and trend[0] <= t.storage_days_to_full:
            days, per_day, span_h = trend
            out.append(Finding(
                f"storage-trend:{sid}", CRITICAL if days <= 1 else WARNING,
                f"Storage {label} projected full in {days:.1f} days",
                f"Growing about {fmt_bytes(per_day)}/day over the last {span_h:.1f} h; "
                f"{fmt_bytes(total - used)} left ({pct:.0f}% used).",
            ))

    # ZFS pools
    for p in snap.zfs_pools:
        health = str(p.get("health", "")).upper()
        if health and health != "ONLINE":
            out.append(Finding(
                f"zfs:{p['node']}/{p.get('name')}", CRITICAL,
                f"ZFS pool {p.get('name')} on {p['node']} is {health}",
                "The pool has lost redundancy or is failing. Check `zpool status -v` on the node.",
            ))

    # Disks
    for d in snap.disks:
        dev, node = d.get("devpath", "?"), d["node"]
        model = d.get("model") or "unknown model"
        health = str(d.get("health", "")).upper()
        if health and health not in ("PASSED", "OK", "UNKNOWN", "N/A"):
            out.append(Finding(
                f"disk-health:{node}{dev}", CRITICAL, f"Disk {dev} on {node} reports SMART {health}",
                f"{model}, serial {d.get('serial', '?')}. Back up anything on it and plan a replacement.",
            ))
        wear = d.get("wearout")
        if isinstance(wear, (int, float)) or (isinstance(wear, str) and wear.isdigit()):
            remaining = int(wear)
            if remaining <= t.disk_life_remaining_pct:
                out.append(Finding(
                    f"disk-wear:{node}{dev}", CRITICAL if remaining <= 3 else WARNING,
                    f"SSD {dev} on {node} has {remaining}% life left",
                    f"{model}, serial {d.get('serial', '?')}. The Proxmox UI shows this as "
                    f"{100 - remaining}% wearout.",
                ))

    # Failed tasks (one-off events)
    for task in snap.failed_tasks:
        key = f"task:{task.get('upid')}"
        if state.recently_notified(key, snap.taken_at, 7 * 86400):
            continue
        status = str(task.get("status", ""))
        warnings_only = status.upper().startswith("WARNINGS")
        what = task.get("type", "task")
        tid = f" {task['id']}" if task.get("id") else ""
        # The task log's error lines say far more than the one-line status.
        error_lines = [
            clean_log_line(l) for l in task.get("log_tail", [])
            if re.search(r"\berror\b|\bfail(ed|ure)\b\s*[-:(]", l, re.I)
        ]
        out.append(Finding(
            key, INFO if warnings_only else WARNING,
            f"{what}{tid} on {task.get('node')} {'finished with warnings' if warnings_only else 'failed'}",
            f"Status: {status}",
            kind="event",
            context=task.get("log_tail", []),
            lookup_messages=[] if warnings_only else (error_lines[:2] or [f"{what} {status}"]),
            dedupe_keys=[key],
        ))

    # Journal errors (one-off events, deduped per message for renotify_hours)
    crit_patterns = _compile(tuple(cfg.logs.critical))
    for node, lines in snap.log_errors.items():
        groups: dict[str, list[str]] = {}
        for line in lines:
            msg = clean_log_line(line)
            groups.setdefault(group_key(msg), []).append(msg)
        fresh = {
            g: msgs for g, msgs in groups.items()
            if not state.recently_notified(f"log:{node}|{g}", snap.taken_at, renotify_s)
        }
        if not fresh:
            continue
        is_crit = {g: any(p.search(m) for p in crit_patterns for m in msgs[:5]) for g, msgs in fresh.items()}
        # Critical first, then most frequent.
        ordered = sorted(fresh, key=lambda g: (not is_crit[g], -len(fresh[g])))
        context = [
            f"{len(fresh[g])}× {fresh[g][-1]}" if len(fresh[g]) > 1 else fresh[g][-1]
            for g in ordered[:25]
        ]
        total = sum(len(m) for m in fresh.values())
        out.append(Finding(
            f"logs:{node}:{int(snap.taken_at)}",
            CRITICAL if any(is_crit.values()) else WARNING,
            f"{total} error line(s) in the journal on {node}",
            f"{len(fresh)} distinct message(s) since the last check"
            + (f", {len(groups) - len(fresh)} more already reported recently." if len(groups) > len(fresh) else "."),
            kind="event",
            context=context,
            lookup_messages=[fresh[g][-1] for g in ordered],
            dedupe_keys=[f"log:{node}|{g}" for g in fresh],
        ))

    # Pending updates
    for node, count in snap.updates.items():
        if count:
            out.append(Finding(
                f"updates:{node}", INFO, f"{count} package update(s) pending on {node}",
                "Install them from the node's Updates panel or with `apt full-upgrade` when convenient.",
            ))

    state.prune(snap.taken_at, window_s, keep_recent_s=8 * 86400, lookup_ttl_s=cfg.lookup.cache_days * 86400)
    return out
