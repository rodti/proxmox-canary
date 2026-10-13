"""Real proxmoxer/httpx/websockets against the fake servers: collector, full checks, the service loop and the CLI."""
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import write_config
from fakes import validate_message
from proxmox_canary import __main__ as cli
from proxmox_canary.collector import Collector, CollectorError
from proxmox_canary.monitor import Monitor

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------- collector

def test_collector_against_https_api(pve, make_cfg, caplog):
    cfg = make_cfg(pve=pve)
    since = time.time() - 3600
    snap = Collector(cfg).collect(since)
    assert [n["node"] for n in snap.nodes] == ["pve1", "pve2"]
    assert sorted(g["vmid"] for g in snap.guests) == [101, 200, 300]  # template skipped
    # Offline node's storage dropped; shared 'nas' taken from the online node.
    assert {(s["storage"], s["node"]) for s in snap.storage} == {("tank", "pve1"), ("nas", "pve1"), ("usb", "pve1")}
    assert snap.zfs_pools == [dict(pve.scenario["zfs"]["pve1"][0], node="pve1")]
    assert len(snap.disks) == 4
    # Journal: gzip stream decoded, cursors and ignored noise dropped, 'since' passed as an int epoch.
    assert pve.journal_since == [int(since)]
    lines = snap.log_errors["pve1"]
    assert len(lines) == 3 and not any(line.startswith("s=") for line in lines)
    assert not any("vanished client" in line or "starting task" in line for line in lines)
    # Failed task with its log fetched by a UPID containing '!' and '@'; OK/running/old tasks skipped.
    assert [t["type"] for t in snap.failed_tasks] == ["vzdump"]
    assert "Input/output error" in snap.failed_tasks[0]["log_tail"][2]
    assert snap.updates == {}  # check_updates is off by default


def test_collector_update_check_403_warns_once(pve, make_cfg, caplog):
    cfg = make_cfg(pve=pve)
    cfg.check_updates = True
    c = Collector(cfg)
    c.collect(time.time() - 60)
    c.collect(time.time() - 60)
    warns = [r for r in caplog.records if "update list on pve1" in r.getMessage()]
    assert len(warns) == 1 and "Sys.Modify" in warns[0].getMessage()


def test_collector_missing_syslog_privilege(pve, make_cfg, caplog):
    pve.scenario["syslog_allowed"] = False
    pve.scenario["no_zfs"] = {"pve1"}
    snap = Collector(make_cfg(pve=pve)).collect(time.time() - 60)
    assert snap.log_errors == {} and snap.zfs_pools == [] and snap.nodes
    msgs = " ".join(r.getMessage() for r in caplog.records)
    assert "journal on pve1" in msgs and "Sys.Syslog" in msgs


def test_collector_errors(pve, make_cfg, tmp_path):
    cfg = make_cfg(pve=pve)
    cfg.proxmox.token_value = "wrong"
    with pytest.raises(CollectorError, match="401"):
        Collector(cfg).collect(0)
    cfg = make_cfg(pve=pve)
    cfg.proxmox.verify_ssl = True
    with pytest.raises(CollectorError, match="(?i)certificate"):
        Collector(cfg).collect(0)
    pve.scenario["down"] = True
    with pytest.raises(CollectorError, match="503"):
        Collector(make_cfg(pve=pve)).collect(0)
    with pytest.raises(CollectorError):
        Collector(make_cfg()).collect(0)  # nothing listening


# ------------------------------------------------------------ full check

def test_full_check_with_lookup_and_diagnosis(pve, ollama, web, make_cfg):
    cfg = make_cfg(pve=pve, ollama=ollama, web=web)
    m = Monitor(cfg)
    r = asyncio.run(m.check())
    keys = {f.key.split(":")[0] for f in r.new}
    assert keys == {"node-down", "node-cpu", "node-mem", "guest-cpu", "storage-full", "storage-unavailable",
                    "zfs", "disk-health", "disk-wear", "task", "logs", "disk-io"}
    # Searches were scrubbed of node/guest/storage names, IPs and users.
    assert web.searches, "expected web lookups"
    for q in web.searches:
        for secret in ("pve1", "192.168", "rod@pam", "123456", "nas", "UPID"):
            assert secret not in q, (secret, q)
    assert any("I/O error" in q for q in web.searches)
    assert len(web.searches) <= cfg.lookup.max_lookups_per_check
    # The diagnosis covers every non-info finding and only cites pages it was given.
    assert set(r.diagnoses) == {f.key for f in r.new if f.severity != "info"}
    io_key = next(f.key for f in r.new if f.key.startswith("disk-io:"))
    assert io_key == "disk-io:pve1:sdb"
    assert r.diagnoses[io_key]["sources"] and all(s["url"].startswith(web.base) for s in r.diagnoses[io_key]["sources"])
    # The prompt fed to the model has the scraped forum text but not page chrome or scripts.
    prompt = ollama.chats[-1]["messages"][1]["content"]
    assert "bad SATA cable" in prompt and "tracking" not in prompt
    # Lookup cache: a second monitor reusing the state does not search again.
    m.commit(r)
    before = len(web.searches)
    m2 = Monitor(cfg)
    m2.state.last_check = None
    m2.state.recent.clear()
    asyncio.run(m2.check())
    assert len(set(web.searches)) == len(web.searches), "cached queries must not be searched again"
    assert len(web.searches) >= before


def test_failed_lookup_not_cached(pve, ollama, web, make_cfg):
    web.fail_search = True
    cfg = make_cfg(pve=pve, ollama=ollama, web=web)
    m = Monitor(cfg)
    asyncio.run(m.check())
    assert m.state.lookups == {}


def test_check_without_ollama_still_reports(pve, make_cfg):
    m = Monitor(make_cfg(pve=pve))
    r = asyncio.run(m.check())
    assert r.new and r.diagnoses == {} and r.overview is None


# -------------------------------------------------------- service loop

def run_service_until(cfg, done, timeout: float = 30.0, settle: float = 0.0):
    """Run the real service loop until done() is true, then stop it with SIGTERM like `docker stop`."""
    async def go():
        async def watcher():
            t0 = time.monotonic()
            while not done() and time.monotonic() - t0 < timeout:
                await asyncio.sleep(0.05)
            await asyncio.sleep(settle)
            os.kill(os.getpid(), signal.SIGTERM)
        w = asyncio.create_task(watcher())
        rc = await asyncio.wait_for(cli.run_service(cfg), timeout + 30)
        await w
        return rc
    rc = asyncio.run(go())
    assert done(), "service did not reach the expected state in time"
    return rc


def embeds(discord):
    return [e for m in discord.messages for e in m.get("embeds", [])]


def test_service_loop(pve, ollama, web, discord, make_cfg, tmp_path):
    cfg = make_cfg(pve=pve, ollama=ollama, web=web, discord=discord)
    cfg.poll_interval_seconds = 1
    calls = lambda: len([r for r in pve.server.requests if r[1].startswith("/api2/json/cluster/resources")])  # noqa: E731
    assert run_service_until(cfg, lambda: calls() >= 3) == 0  # three full cycles
    assert discord.identifies, "gateway login expected at startup"
    assert discord.messages, "expected alerts"
    assert discord.messages[0]["content"].startswith("<@&555>\n🚨 **Danger!**")
    for msg in discord.messages:
        assert validate_message(msg) == []
    # Later cycles posted nothing new: same problems, already reported.
    titles = [e["title"] for e in embeds(discord)]
    assert len(titles) == len(set(titles))
    state = json.loads((tmp_path / "state.json").read_text())
    assert "zfs:pve1/tank" in state["active"] and state["last_check"]

    # The problem clears → "All good" on the next run, using the saved state.
    pve.scenario["zfs"]["pve1"][0]["health"] = "ONLINE"
    discord.messages.clear()
    run_service_until(cfg, lambda: any(e["title"] == "✅ Resolved" for e in embeds(discord)))
    resolved = [e for e in embeds(discord) if e["title"] == "✅ Resolved"]
    assert "ZFS pool tank on pve1 is DEGRADED" in resolved[0]["description"]
    assert [e for e in embeds(discord) if e["title"] != "✅ Resolved"] == []


def test_service_retries_when_discord_down(pve, discord, make_cfg, tmp_path, monkeypatch):
    import proxmox_canary.discord_alerts as da

    async def no_backoff(s):  # skip the retry back-off waits
        return None

    monkeypatch.setattr(da, "_sleep", no_backoff)
    cfg = make_cfg(pve=pve, discord=discord)
    cfg.poll_interval_seconds = 1
    discord.fail_posts = 5  # the first cycle's send fails after all retries
    run_service_until(cfg, lambda: bool(embeds(discord)), settle=1.5)
    posts = [r for r in discord.server.requests if r[0] == "POST"]
    assert len(posts) > 5, "expected a retry on a later cycle"
    # Failed send → friendly notice (Discord was back by then), then recovery, then the alerts.
    from proxmox_canary.discord_alerts import OOPS, RECOVERED
    assert [m.get("content") for m in discord.messages[:2]] == [OOPS, RECOVERED]
    assert "503" not in json.dumps(discord.messages)
    assert len(discord.identifies) == 1
    titles = [e["title"] for e in embeds(discord)]
    assert "🔴 ZFS pool tank on pve1 is DEGRADED" in titles
    assert len(titles) == len(set(titles)), "alerts should arrive once after recovery, not twice"
    # Journal errors from before the outage were not lost.
    assert any("error line(s) in the journal" in t for t in titles)
    assert json.loads((tmp_path / "state.json").read_text())["active"]


def test_api_outage_and_recovery(pve, discord, make_cfg, caplog):
    from proxmox_canary.discord_alerts import OOPS, RECOVERED
    cfg = make_cfg(pve=pve, discord=discord)
    cfg.poll_interval_seconds = 1
    run_service_until(cfg, lambda: bool(discord.messages))
    discord.messages.clear()
    pve.scenario["down"] = True
    checks = lambda: len([r for r in pve.server.requests if "cluster/resources" in r[1]])  # noqa: E731
    before = checks()
    run_service_until(cfg, lambda: checks() >= before + 3)  # several failing checks
    # Discord: one friendly notice for the whole outage, no error text, nothing resolved.
    assert [m["content"] for m in discord.messages] == [OOPS]
    assert all("embeds" not in m for m in discord.messages)
    # Logs: the real error.
    assert "Check failed; retrying next cycle: cannot query /cluster/resources: 503" in caplog.text
    discord.messages.clear()
    # A restart during the outage remembers the notice was already posted.
    run_service_until(cfg, lambda: checks() >= before + 5)
    assert discord.messages == []
    pve.scenario["down"] = False
    run_service_until(cfg, lambda: bool(discord.messages), settle=1.5)
    assert [m.get("content") for m in discord.messages] == [RECOVERED]  # alerts were already recorded


# ------------------------------------------------------------------ CLI

def test_cli_once(pve, ollama, tmp_path):
    cfgp = write_config(tmp_path, pve=pve, ollama=ollama)
    text = cfgp.read_text().replace("discord:\n  token: bot-token", "discord:\n  token: ''")
    cfgp.write_text(text)
    out = subprocess.run([sys.executable, "-m", "proxmox_canary", "--once", "-c", str(cfgp), "--log-level", "WARNING"],
                         cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("Overview: Disk sdb is failing")
    assert "[CRITICAL] ZFS pool tank on pve1 is DEGRADED" in out.stdout
    assert "cause (medium): Likely cause of:" in out.stdout
    assert not (tmp_path / "state.json").exists()  # --once never writes state


def test_cli_config_error(tmp_path):
    out = subprocess.run([sys.executable, "-m", "proxmox_canary", "-c", str(ROOT / "config.example.yaml")],
                         cwd=ROOT, capture_output=True, text=True, timeout=30, env={**os.environ, "CANARY_PROXMOX_TOKEN_VALUE": ""})
    assert out.returncode == 2 and "Config error" in out.stderr


def test_cli_version():
    out = subprocess.run([sys.executable, "-m", "proxmox_canary", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0 and "0.1.0" in out.stdout


def test_send_test_alert(discord, make_cfg, capsys):
    cfg = make_cfg(discord=discord)
    assert asyncio.run(cli.send_test_alert(cfg)) == 0
    assert discord.messages[0]["embeds"][0]["title"] == "🟡 Test alert from proxmox-canary"
    assert validate_message(discord.messages[0]) == []
