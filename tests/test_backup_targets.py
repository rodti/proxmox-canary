"""Backup targets are left out of storage warnings; command options aren't errors."""
import time

import pytest

from proxmox_canary.collector import Collector, Snapshot, _without_options
from proxmox_canary.rules import evaluate
from proxmox_canary.state import State

GiB = 1024**3


def storage(name, pct, content, plugintype="dir", node="pve1"):
    return {"type": "storage", "storage": name, "node": node, "status": "available", "shared": 0,
            "plugintype": plugintype, "content": content, "disk": pct * GiB, "maxdisk": 100 * GiB}


def keys(findings):
    return {f.key for f in findings}


@pytest.fixture
def cfg(make_cfg):
    return make_cfg()


def test_backup_only_targets_are_skipped(cfg):
    snap = Snapshot(taken_at=time.time(), backup_targets={"local", "usb-backup"}, storage=[
        storage("local", 99, "iso,vztmpl,backup"),          # job target, no guest disks
        storage("usb-backup", 95, "backup"),                 # job target
        storage("dump", 95, "backup"),                       # backup-only content, no job
        storage("pbs", 97, "backup", plugintype="pbs"),      # Proxmox Backup Server
        storage("isos", 85, "iso,vztmpl"),                   # ordinary storage
    ])
    assert keys(evaluate(snap, cfg, State(None))) == {"storage-full:pve1/isos"}


def test_mixed_target_only_alerts_when_critical(cfg):
    st, t0 = State(None), time.time()
    mixed = "images,rootdir,backup,iso"
    warn = Snapshot(taken_at=t0, backup_targets={"local-btrfs"}, storage=[storage("local-btrfs", 85, mixed)])
    assert evaluate(warn, cfg, st) == []
    crit = Snapshot(taken_at=t0, backup_targets={"local-btrfs"}, storage=[storage("local-btrfs", 93, mixed)])
    f = evaluate(crit, cfg, st)
    assert [x.key for x in f] == ["storage-full:pve1/local-btrfs"] and f[0].severity == "critical"
    assert "holds backups and VM/CT disks" in f[0].detail


def test_mixed_target_has_no_growth_trend(cfg):
    st, t0 = State(None), time.time()
    for i in range(8):  # a nightly backup's worth of growth
        snap = Snapshot(taken_at=t0 + i * 900, backup_targets={"local-btrfs"},
                        storage=[storage("local-btrfs", 50 + i * 4, "images,backup")])
        f = evaluate(snap, cfg, st)
    assert not any(k.startswith("storage-trend") for k in keys(f))


def test_option_can_be_turned_off(cfg):
    cfg.ignore_backup_targets = False
    snap = Snapshot(taken_at=time.time(), backup_targets={"local"}, storage=[storage("local", 95, "backup")])
    assert keys(evaluate(snap, cfg, State(None))) == {"storage-full:pve1/local"}


def test_collector_reads_backup_jobs(pve, make_cfg):
    pve.scenario["backup_jobs"] = [
        {"id": "backup-1", "storage": "nas", "enabled": 1, "schedule": "21:00", "all": 1},
        {"id": "backup-2", "storage": "old-usb", "enabled": 0},
        {"id": "backup-3"},  # no storage set: not guessed
    ]
    snap = Collector(make_cfg(pve=pve)).collect(time.time() - 60)
    assert snap.backup_targets == {"nas"}
    # The fake's 'nas' (90% would alert) has no content field: treated as backup-only.
    f = evaluate(snap, make_cfg(), State(None))
    assert not any("nas" in k for k in keys(f))


def test_collector_without_backup_permission(pve, make_cfg):
    cfg = make_cfg(pve=pve)
    cfg.ignore_backup_targets = False
    Collector(cfg).collect(time.time() - 60)
    assert not any("/cluster/backup" in r[1] for r in pve.server.requests)


# ------------------------------------------------------- options aren't errors

def test_backup_job_options_are_not_errors(pve, make_cfg):
    t = time.strftime("%b %d %H:%M:%S")
    pve.scenario["journal"]["pve1"] = [
        f"{t} pve1 pvescheduler[2201]: INFO: starting new backup job: vzdump --storage local-btrfs "
        "--notes-template '{{guestname}}' --mailnotification failure --fleecing 0 --all 1 "
        "--prune-backups 'keep-last=1' --mailto admin@example.com --node pve1 --compress zstd --mode snapshot --quiet 1",
        f"{t} pve1 vzdump[2202]: ERROR: Backup of VM 101 failed - unable to open file",
    ]
    snap = Collector(make_cfg(pve=pve)).collect(time.time() - 60)
    assert snap.log_errors["pve1"] == [pve.scenario["journal"]["pve1"][1]]


@pytest.mark.parametrize("line,kept", [
    ("vzdump --mailnotification failure --mode snapshot", "vzdump"),
    ("cmd --opt='a failure' --x \"error here\" done", "cmd done"),
    ("kernel: something failed --- really", "kernel: something failed --- really"),
    ("ERROR: Backup of VM 101 failed - unable to open file", "ERROR: Backup of VM 101 failed - unable to open file"),
])
def test_without_options(line, kept):
    assert " ".join(_without_options(line).split()) == kept
