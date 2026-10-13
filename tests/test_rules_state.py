import json
import time

import pytest

from proxmox_canary.collector import Snapshot
from proxmox_canary.rules import Finding, _days_to_full, clean_log_line, evaluate, fmt_bytes, group_key
from proxmox_canary.state import State

GiB = 1024**3


@pytest.fixture
def cfg(make_cfg):
    c = make_cfg()
    c.thresholds.sustained_samples = 3
    return c


def node(name="pve1", cpu=0.1, mem=10, maxmem=100, disk=10, maxdisk=100, status="online"):
    return {"type": "node", "node": name, "status": status, "cpu": cpu, "maxcpu": 16,
            "mem": mem * GiB, "maxmem": maxmem * GiB, "disk": disk * GiB, "maxdisk": maxdisk * GiB}


def snap(**kw):
    s = Snapshot(taken_at=kw.pop("taken_at", time.time()))
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def keys(findings):
    return {f.key for f in findings}


def test_quiet_cluster_has_no_findings(cfg):
    assert evaluate(snap(nodes=[node()]), cfg, State(None)) == []


def test_cpu_needs_sustained_samples(cfg):
    st = State(None)
    s = lambda c: snap(nodes=[node(cpu=c)])  # noqa: E731
    assert "node-cpu:pve1" not in keys(evaluate(s(0.95), cfg, st))
    assert "node-cpu:pve1" not in keys(evaluate(s(0.95), cfg, st))
    assert "node-cpu:pve1" in keys(evaluate(s(0.95), cfg, st))
    # One dip resets the run.
    assert "node-cpu:pve1" not in keys(evaluate(s(0.50), cfg, st))
    assert "node-cpu:pve1" not in keys(evaluate(s(0.95), cfg, st))


def test_memory_severity_and_top_guests(cfg):
    cfg.thresholds.sustained_samples = 1
    guests = [
        {"type": "qemu", "vmid": 101, "name": "plex", "node": "pve1", "status": "running", "cpu": 0.5, "maxcpu": 8, "mem": 12 * GiB, "maxmem": 16 * GiB},
        {"type": "lxc", "vmid": 200, "name": "dns", "node": "pve1", "status": "running", "cpu": 0.1, "maxcpu": 1, "mem": GiB, "maxmem": 2 * GiB},
        {"type": "qemu", "vmid": 102, "name": "other", "node": "pve2", "status": "running", "cpu": 0.1, "maxcpu": 1, "mem": 50 * GiB, "maxmem": 64 * GiB},
    ]
    f = {x.key: x for x in evaluate(snap(nodes=[node(mem=98)], guests=guests), cfg, State(None))}
    m = f["node-mem:pve1"]
    assert m.severity == "critical"
    assert "VM 101 (plex) 12.0 GiB" in m.detail and "CT 200 (dns)" in m.detail and "other" not in m.detail
    f2 = evaluate(snap(nodes=[node(mem=92)]), cfg, State(None))
    assert [x.severity for x in f2 if x.key == "node-mem:pve1"] == ["warning"]


def test_offline_node_is_critical_and_skips_metrics(cfg):
    f = evaluate(snap(nodes=[node(status="offline", cpu=1.0, mem=100)]), cfg, State(None))
    assert keys(f) == {"node-down:pve1"} and f[0].severity == "critical"


def test_rootfs(cfg):
    f = {x.key: x for x in evaluate(snap(nodes=[node(disk=96)]), cfg, State(None))}
    assert f["node-rootfs:pve1"].severity == "critical"


def test_guest_samples_reset_when_stopped(cfg):
    st = State(None)
    g = lambda status: [{"type": "qemu", "vmid": 1, "name": "a", "node": "pve1", "status": status,  # noqa: E731
                         "cpu": 1.0, "maxcpu": 2, "mem": GiB, "maxmem": 8 * GiB}]
    evaluate(snap(nodes=[node()], guests=g("running")), cfg, st)
    evaluate(snap(nodes=[node()], guests=g("running")), cfg, st)
    evaluate(snap(nodes=[node()], guests=g("stopped")), cfg, st)
    # After a restart it needs a full run of samples again.
    assert "guest-cpu:qemu/1" not in keys(evaluate(snap(nodes=[node()], guests=g("running")), cfg, st))


def storage(used, total=100, name="tank", node_="pve1", status="available", shared=0):
    return {"type": "storage", "storage": name, "node": node_, "status": status, "shared": shared,
            "disk": used * GiB, "maxdisk": total * GiB}


def test_storage_thresholds(cfg):
    f = {x.key: x.severity for x in evaluate(snap(storage=[storage(85), storage(95, name="b"), storage(10, name="c")]), cfg, State(None))}
    assert f == {"storage-full:pve1/tank": "warning", "storage-full:pve1/b": "critical"}


def test_storage_unavailable_and_shared_keys(cfg):
    f = keys(evaluate(snap(storage=[storage(0, status="unknown", name="usb"), storage(95, name="nas", shared=1)]), cfg, State(None)))
    assert f == {"storage-unavailable:pve1/usb", "storage-full:nas"}


def test_storage_trend_projects_days_to_full(cfg):
    st = State(None)
    t0 = 1_700_000_000
    out = []
    # 10 GiB/hour growth with 40 GiB free → about 4 hours left.
    for i in range(7):
        out = evaluate(snap(taken_at=t0 + i * 1800, storage=[storage(30 + 5 * i, total=100)]), cfg, st)
    trend = [f for f in out if f.key == "storage-trend:pve1/tank"]
    assert trend and trend[0].severity == "critical"
    assert "projected full in 0.2 days" in trend[0].title


def test_trend_math():
    pts = [[i * 3600.0, 100.0 + 10 * i] for i in range(5)]
    days, per_day, span = _days_to_full(pts, used=140, total=380)
    assert per_day == pytest.approx(240) and days == pytest.approx(1.0) and span == pytest.approx(4)
    assert _days_to_full(pts[:3], 1, 2) is None  # too few points
    assert _days_to_full([[0, 5], [600, 5], [1200, 5], [1800, 5]], 5, 10) is None  # span < 1h
    assert _days_to_full([[i * 3600.0, 100.0 - i] for i in range(5)], 96, 200) is None  # shrinking


def test_shrinking_storage_no_trend(cfg):
    st = State(None)
    for i in range(6):
        out = evaluate(snap(taken_at=1e9 + i * 3600, storage=[storage(50 - i)]), cfg, st)
    assert not any(f.key.startswith("storage-trend") for f in out)


def test_zfs_and_disks(cfg):
    disks = [
        {"node": "pve1", "devpath": "/dev/sda", "health": "PASSED", "wearout": 7, "model": "X"},
        {"node": "pve1", "devpath": "/dev/sdb", "health": "FAILED", "wearout": "N/A"},
        {"node": "pve1", "devpath": "/dev/sdc", "health": "OK", "wearout": "2"},
        {"node": "pve1", "devpath": "/dev/sdd", "health": "UNKNOWN", "wearout": 100},
        {"node": "pve1", "devpath": "/dev/nvme0n1", "health": "PASSED", "wearout": 55.5},
    ]
    zfs = [{"node": "pve1", "name": "rpool", "health": "ONLINE"}, {"node": "pve1", "name": "tank", "health": "DEGRADED"}]
    f = {x.key: x for x in evaluate(snap(disks=disks, zfs_pools=zfs), cfg, State(None))}
    assert set(f) == {"zfs:pve1/tank", "disk-health:pve1/dev/sdb", "disk-wear:pve1/dev/sda", "disk-wear:pve1/dev/sdc"}
    assert f["disk-wear:pve1/dev/sda"].severity == "warning" and "93% wearout" in f["disk-wear:pve1/dev/sda"].detail
    assert f["disk-wear:pve1/dev/sdc"].severity == "critical"


def test_failed_tasks(cfg):
    st = State(None)
    tasks = [
        {"upid": "U1", "node": "pve1", "type": "vzdump", "id": "101", "status": "job errors",
         "log_tail": ["INFO: start", "ERROR: Backup of VM 101 failed - Input/output error"]},
        {"upid": "U2", "node": "pve1", "type": "vzdump", "status": "WARNINGS: 2", "log_tail": []},
    ]
    f = {x.key: x for x in evaluate(snap(failed_tasks=tasks), cfg, st)}
    assert f["task:U1"].severity == "warning" and f["task:U1"].kind == "event"
    assert f["task:U1"].lookup_messages == ["ERROR: Backup of VM 101 failed - Input/output error"]
    assert f["task:U2"].severity == "info" and f["task:U2"].lookup_messages == []
    # Once notified, the same UPID is not reported again.
    st.recent["task:U1"] = time.time()
    assert "task:U1" not in keys(evaluate(snap(failed_tasks=tasks), cfg, st))


def test_log_grouping_dedupe_and_severity(cfg):
    st = State(None)
    lines = [
        "Oct 03 09:40:01 pve1 kernel: EXT4-fs error (device dm-1): ext4_find_entry:1455: inode #2: comm ls",
        "Oct 03 09:40:02 pve1 kernel: EXT4-fs error (device dm-1): ext4_find_entry:1455: inode #9: comm ls",
        "Oct 03 09:41:00 pve1 pvestatd[1234]: storage 'nas' is not online",
    ]
    f = evaluate(snap(log_errors={"pve1": lines}), cfg, st)
    assert len(f) == 1
    log = f[0]
    assert log.severity == "critical" and log.kind == "event"
    assert log.title == "3 error line(s) in the journal on pve1"
    assert log.context[0].startswith("2× kernel: EXT4-fs error")
    assert len(log.dedupe_keys) == 2
    # Mark as notified: the same messages are suppressed, a new one still alerts.
    for k in log.dedupe_keys:
        st.recent[k] = time.time()
    assert evaluate(snap(log_errors={"pve1": lines}), cfg, st) == []
    new = evaluate(snap(log_errors={"pve1": lines + ["Oct 03 09:45:00 pve1 cron[1]: job failed"]}), cfg, st)
    assert len(new) == 1 and new[0].severity == "warning" and "1 more" not in new[0].detail
    assert "2 more already reported" in new[0].detail


def test_generic_grouping_ignores_addresses_and_names():
    a = "pveproxy: failed login from 2001:db8::1 for 'alice' user=alice@pve port 4431"
    b = "pveproxy: failed login from fe80::abcd for 'bob' user=bob@pam port 53"
    assert group_key(a) == group_key(b)


def test_clean_and_group():
    assert clean_log_line("Oct 03 09:40:01 pve1 pvestatd[1234]: storage 'nas' is not online") == "pvestatd: storage 'nas' is not online"
    assert clean_log_line("2026-10-13T09:40:01+0200 pve1 kernel: x") == "kernel: x"
    assert group_key("sector 123 at 0xdeadbeef") == group_key("sector 456 at 0x1")


def test_fmt_bytes():
    assert fmt_bytes(512) == "512 B"
    assert fmt_bytes(1536) == "1.5 KiB"
    assert fmt_bytes(3 * 1024**4) == "3.0 TiB"
    assert fmt_bytes(5 * 1024**5) == "5120.0 TiB"


# ------------------------------------------------------------------- state


def F(key, sev="warning", kind="condition", dk=()):
    return Finding(key, sev, f"title {key}", "detail", kind=kind, dedupe_keys=list(dk))


def test_state_lifecycle(tmp_path):
    st = State(tmp_path / "s.json")
    now = 1000.0
    new, rep, res = st.diff([F("a"), F("e", kind="event", dk=["e"])], now, 3600, True)
    assert [f.key for f in new] == ["a", "e"] and not rep and not res
    st.commit([F("a"), F("e", kind="event", dk=["e"])], {"a", "e"}, now, now, True)
    assert set(st.active) == {"a"} and st.recent == {"e": now}

    # Still active, before renotify → nothing.
    assert st.diff([F("a")], now + 100, 3600, True) == ([], [], [])
    # After renotify → reminder.
    new, rep, res = st.diff([F("a")], now + 4000, 3600, True)
    assert not new and [f.key for f in rep] == ["a"]
    # Escalation counts as new.
    new, rep, res = st.diff([F("a", "critical")], now + 100, 3600, True)
    assert [f.key for f in new] == ["a"]
    # Info conditions never remind.
    st.commit([F("i", "info")], {"i"}, now, now, True)
    assert st.diff([F("i", "info")], now + 10**6, 3600, True) == ([], [], [])
    # Cleared → resolved.
    st.commit([F("a")], {"a"}, now, now, True)
    new, rep, res = st.diff([], now + 10, 3600, True)
    assert [r["key"] for r in res] == ["a"]


def test_incomplete_check_keeps_active(tmp_path):
    st = State(tmp_path / "s.json")
    st.commit([F("a")], {"a"}, 1.0, 1.0, True)
    new, rep, res = st.diff([F("api-unreachable", "critical")], 2.0, 3600, complete=False)
    assert not res
    st.commit([F("api-unreachable", "critical")], {"api-unreachable"}, 2.0, None, complete=False)
    assert set(st.active) == {"a", "api-unreachable"} and st.last_check == 1.0


def test_state_persists_and_survives_corruption(tmp_path):
    p = tmp_path / "s.json"
    st = State(p)
    st.record_trend("storage:x", 10, 5, 3600)
    st.lookups["q"] = {"at": 1, "results": []}
    st.commit([F("a")], {"a"}, 5.0, 6.0, True)
    st2 = State.load(p)
    assert st2.last_check == 6.0 and "a" in st2.active and st2.trends and st2.lookups
    assert not list(tmp_path.glob(".canary-state.*"))  # temp files cleaned up
    p.write_text("{not json")
    st3 = State.load(p)
    assert st3.active == {} and st3.last_check is None


def test_prune(tmp_path):
    st = State(None)
    st.trends = {"old": [[0, 1]], "new": [[1000, 1]]}
    st.recent = {"old": 0, "new": 999}
    st.lookups = {"old": {"at": 0}, "new": {"at": 999}}
    st.prune(1000, trend_window_s=100, keep_recent_s=100, lookup_ttl_s=100)
    assert set(st.trends) == set(st.recent) == set(st.lookups) == {"new"}
    st.save()  # no path → no-op
    json.dumps(st.active)
