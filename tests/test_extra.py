"""Branches the main suites don't reach: CLI in-process, embed trimming, gateway edge cases,
state write failures, rarer rules and collector paths, lookup budgeting."""
import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

from fakes import validate_message
from proxmox_canary import __main__ as cli
from proxmox_canary import discord_alerts as da
from proxmox_canary.collector import Collector, Snapshot
from proxmox_canary.config import ConfigError, load_config
from proxmox_canary.discord_alerts import MAX_EMBED_CHARS, _embed_size, build_messages, finding_embed
from proxmox_canary.llm import Diagnoser
from proxmox_canary.monitor import Monitor, Report
from proxmox_canary.rules import CRITICAL, WARNING, Finding, _pct, evaluate, fmt_bytes
from proxmox_canary.state import State

GiB = 1024**3


def report_of(findings, overview=None, diagnoses=None):
    return Report(list(findings), list(findings), [], [], True, time.time(), overview, diagnoses or {})


# ------------------------------------------------------------------ CLI in-process

def test_format_report_quiet_and_full():
    assert cli.format_report(report_of([])) == "✅ All good: no issues found."
    f = Finding("k", CRITICAL, "Disk sdb failing", "SMART FAILED", context=["kernel: I/O error"])
    text = cli.format_report(report_of(
        [Finding("u", "info", "2 updates", "later"), f],
        overview="Replace sdb.",
        diagnoses={"k": {"root_cause": "Dying SSD", "fix": "Replace it", "confidence": "high",
                         "sources": [{"title": "Forum", "url": "https://forum.proxmox.com/t/1"}]}},
    ))
    lines = text.splitlines()
    assert lines[0] == "Overview: Replace sdb."
    assert lines[2] == "[CRITICAL] Disk sdb failing"  # critical sorted before info
    assert "    cause (high): Dying SSD" in lines and "    fix: Replace it" in lines
    assert "    source: Forum <https://forum.proxmox.com/t/1>" in lines
    assert "    | kernel: I/O error" in lines
    assert text.index("[CRITICAL]") < text.index("[INFO]")


def test_run_once_in_process(pve, ollama, make_cfg, capsys, tmp_path):
    cfg = make_cfg(pve=pve, ollama=ollama)
    cfg.thresholds.sustained_samples = 5
    assert asyncio.run(cli.run_once(cfg)) == 0
    out = capsys.readouterr().out
    assert cfg.thresholds.sustained_samples == 1  # --once treats one sample as sustained
    assert "[CRITICAL] ZFS pool tank on pve1 is DEGRADED" in out
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize("argv,expected", [
    (["--once"], "once"), (["--test-alert"], "test"), ([], "service"),
])
def test_main_dispatch(make_cfg, tmp_path, monkeypatch, argv, expected):
    from conftest import write_config
    cfgp = write_config(tmp_path)
    called = []

    async def fake(name):
        called.append(name)
        return 0

    monkeypatch.setattr(cli, "run_once", lambda cfg: fake("once"))
    monkeypatch.setattr(cli, "send_test_alert", lambda cfg: fake("test"))
    monkeypatch.setattr(cli, "run_service", lambda cfg: fake("service"))
    monkeypatch.setattr(sys, "argv", ["proxmox-canary", "-c", str(cfgp), *argv])
    assert cli.main() == 0 and called == [expected]


def test_main_config_error_and_exclusive_flags(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["proxmox-canary", "-c", str(tmp_path / "nope.yaml")])
    assert cli.main() == 2
    assert "config file not found" in capsys.readouterr().err
    monkeypatch.setattr(sys, "argv", ["proxmox-canary", "--once", "--test-alert"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 2


def test_once_mode_does_not_need_discord(tmp_path, monkeypatch):
    from conftest import write_config
    p = write_config(tmp_path)
    text = p.read_text()
    p.write_text(text[: text.index("discord:")] + text[text.index("state_file:"):])
    with pytest.raises(ConfigError, match="discord"):
        load_config(p)
    cfg = load_config(p, require_discord=False)
    assert cfg.discord.token == "" and cfg.discord.channel_id == 0


def test_env_override_creates_missing_section(tmp_path, monkeypatch):
    from conftest import write_config
    p = write_config(tmp_path, extra="")
    text = p.read_text().replace("lookup:\n  enabled: false\n  provider: searxng", "lookup:\n  enabled: true\n  provider: brave")
    p.write_text(text)
    with pytest.raises(ConfigError, match="brave_api_key"):
        load_config(p)
    monkeypatch.setenv("CANARY_BRAVE_API_KEY", "k123")
    monkeypatch.setenv("CANARY_DISCORD_CHANNEL_ID", "987654321098765432")
    cfg = load_config(p)
    assert cfg.lookup.brave_api_key == "k123" and cfg.discord.channel_id == 987654321098765432


# ------------------------------------------------------------- embed trimming

def test_oversized_embed_is_trimmed_without_breaking_markup():
    f = Finding("k", CRITICAL, "T" * 300, "D" * 5000,
                context=["```evil``` " + "x" * 400 for _ in range(10)])
    diag = {"root_cause": "R" * 2000, "fix": "F" * 2000, "confidence": "low",
            "sources": [{"title": "S" * 200, "url": f"https://forum.proxmox.com/threads/{i}/" + "p" * 150} for i in range(4)]}
    e = finding_embed(f, diag, reminder_since=time.time() - 60)
    assert _embed_size(e) <= MAX_EMBED_CHARS
    fields = {x["name"]: x["value"] for x in e["fields"]}
    ev = fields["📜 Evidence"]
    assert ev.startswith("```\n") and ev.endswith("\n```") and ev.count("```") == 2
    for line in fields["📚 Sources"].split("\n"):  # links are dropped whole, never cut in half
        assert line.startswith("[") and line.endswith(")") and "](https://" in line
    assert e["fields"][0]["name"] == "⏰ Still happening"
    assert validate_message({"content": "x", "embeds": [e]}) == []


def test_fit_embed_shrinks_fields_when_description_is_not_enough():
    from proxmox_canary.discord_alerts import _fit_embed
    e = {"title": "t", "description": "d" * 400, "fields": [
        {"name": "🔍 Likely cause", "value": "c" * 1000},
        {"name": "📜 Evidence", "value": "```\n" + "e" * 992 + "\n```"},
        {"name": "📚 Sources", "value": "\n".join(f"[s{i}](https://x.org/{'p' * 280})" for i in range(3))},
    ]}
    out = _fit_embed(e, limit=1500)
    assert _embed_size(out) <= 1500
    vals = {f["name"]: f["value"] for f in out["fields"]}
    assert vals["📜 Evidence"].startswith("```\n") and vals["📜 Evidence"].endswith("\n```")
    if "📚 Sources" in vals:
        assert all(l.endswith(")") for l in vals["📚 Sources"].split("\n"))
    # Even an impossible limit leaves valid markup: sources dropped rather than cut.
    tiny = _fit_embed({**e, "fields": [dict(f) for f in e["fields"]]}, limit=200)
    assert all(f["name"] != "📚 Sources" for f in tiny["fields"])


def test_source_links_are_never_cut():
    from proxmox_canary.discord_alerts import _source_links
    huge = {"title": "Huge", "url": "https://example.com/" + "q" * 1100}
    ok = [{"title": f"T{i}", "url": f"https://forum.proxmox.com/threads/{i}/" + "p" * 250} for i in range(4)]
    assert _source_links([huge]) == ""  # longer than a field: left out, not truncated
    links = _source_links(ok)
    assert len(links) <= 1024 and links.count("](https://") == 3  # 4th didn't fit whole
    e = finding_embed(Finding("k", WARNING, "t", "d"), {"root_cause": "r", "sources": [huge]})
    assert all(f["name"] != "📚 Sources" for f in e["fields"])


def test_many_big_findings_split_into_valid_messages():
    findings = [Finding(f"k{i}", WARNING, f"Problem {i}", "d" * 3000, context=["line " * 50] * 8) for i in range(23)]
    msgs = build_messages(report_of(findings), {})
    assert len(msgs) >= 12 and "content" in msgs[0] and all("content" not in m for m in msgs[1:])
    assert sum(len(m["embeds"]) for m in msgs) == 23
    for m in msgs:
        assert validate_message(m) == []


# ------------------------------------------------------------ gateway edge cases

async def _with_gateway(behaviour, coro_factory):
    from websockets.asyncio.server import serve

    async with serve(behaviour, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        return await coro_factory(f"ws://127.0.0.1:{port}")


def _hello():
    return json.dumps({"op": 10, "d": {"heartbeat_interval": 41250}})


def test_gateway_invalid_session():
    async def behaviour(ws):
        await ws.send(_hello())
        await ws.recv()
        await ws.send(json.dumps({"op": 9, "d": False}))
        await asyncio.sleep(0.5)

    with pytest.raises(RuntimeError, match="rejected the session"):
        asyncio.run(_with_gateway(behaviour, lambda url: da._identify(url, "t")))


def test_gateway_bad_greeting():
    async def behaviour(ws):
        await ws.send(json.dumps({"op": 7}))
        await asyncio.sleep(0.5)

    with pytest.raises(RuntimeError, match="unexpected gateway greeting"):
        asyncio.run(_with_gateway(behaviour, lambda url: da._identify(url, "t")))


def test_gateway_skips_other_events_before_ready():
    async def behaviour(ws):
        await ws.send(_hello())
        await ws.recv()
        await ws.send(json.dumps({"op": 11}))  # heartbeat ack
        await ws.send(json.dumps({"op": 0, "t": "RESUMED", "d": {}}))
        await ws.send(json.dumps({"op": 0, "t": "READY", "d": {"user": {"username": "Canary"}}}))
        await asyncio.sleep(0.5)

    assert asyncio.run(_with_gateway(behaviour, lambda url: da._identify(url, "t"))) == "Canary"


def test_gateway_other_close_code(discord, monkeypatch):
    orig = da._identify

    async def closes_4000(url, token):
        async def behaviour(ws):
            await ws.send(_hello())
            await ws.recv()
            await ws.close(4000, "Unknown error")
        return await _with_gateway(behaviour, lambda u: orig(u, token))

    monkeypatch.setattr(da, "_identify", closes_4000)
    with pytest.raises(RuntimeError, match="code 4000"):
        asyncio.run(da.gateway_login("bot-token"))


# ------------------------------------------------------------- state failures

def test_state_save_failure_is_logged_not_raised(tmp_path, caplog):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    s = State(blocker / "state.json")  # parent "directory" is a file
    s.last_check = 1.0
    s.save()  # must not raise
    assert "Could not write state file" in caplog.text


def test_state_save_unwritable_dir(tmp_path, caplog):
    d = tmp_path / "ro"
    d.mkdir()
    d.chmod(0o500)
    try:
        if (d / "probe").exists() or _writable(d):
            pytest.skip("running as root: directory permissions are not enforced")
        State(d / "state.json").save()
        assert "Could not write state file" in caplog.text
    finally:
        d.chmod(0o700)


def _writable(d):
    try:
        (d / ".probe").write_text("")
        (d / ".probe").unlink()
        return True
    except OSError:
        return False


def test_commit_survives_save_failure(tmp_path):
    blocker = tmp_path / "f"
    blocker.write_text("")
    s = State(blocker / "state.json")
    f = Finding("zfs:a", CRITICAL, "t", "d")
    s.commit([f], {"zfs:a"}, 100.0, 99.0, True)  # must not raise; memory still updated
    assert s.active["zfs:a"]["last_notified"] == 100.0 and s.last_check == 99.0


# ------------------------------------------------------------------ rules

def test_guest_memory_and_zero_size_storage(make_cfg):
    cfg = make_cfg()
    snap = Snapshot(taken_at=time.time())
    snap.nodes = [{"node": "pve1", "status": "online", "cpu": 0.1, "mem": 1, "maxmem": 10, "disk": 1, "maxdisk": 10}]
    snap.guests = [{"type": "qemu", "vmid": 101, "name": "win", "node": "pve1", "status": "running",
                    "cpu": 0.1, "maxcpu": 4, "mem": 15.8 * GiB, "maxmem": 16 * GiB}]
    snap.storage = [{"storage": "cifs", "node": "pve1", "status": "available", "disk": 0, "maxdisk": 0}]
    out = evaluate(snap, cfg, State(None))
    assert [f.key for f in out] == ["guest-mem:qemu/101"]
    assert out[0].title == "VM 101 (win) on pve1 is near its memory limit" and "99%" in out[0].detail


def test_updates_finding(make_cfg):
    cfg = make_cfg()
    snap = Snapshot(taken_at=time.time(), updates={"pve1": 4, "pve2": 0})
    out = evaluate(snap, cfg, State(None))
    assert [(f.key, f.severity, f.title) for f in out] == [("updates:pve1", "info", "4 package update(s) pending on pve1")]


def test_helpers_tolerate_bad_values():
    assert _pct("n/a", 10) == 0.0 and _pct(None, None) == 0.0 and _pct(5, 0) == 0.0
    assert fmt_bytes(0) == "0 B" and fmt_bytes(5 * 1024**5) == "5120.0 TiB"


# --------------------------------------------------------------- collector

class _Api:
    """Minimal stand-in for proxmoxer, for paths the HTTPS fake doesn't produce."""

    def __init__(self, routes, path=()):
        self.routes, self.path = routes, path

    def __getattr__(self, name):
        return _Api(self.routes, self.path + (name,))

    def __call__(self, arg):
        return _Api(self.routes, self.path + (str(arg),))

    def get(self, **kw):
        r = self.routes.get("/".join(self.path), [])
        if isinstance(r, Exception):
            raise r
        return r


def test_collector_shared_storage_and_network_errors(make_cfg, caplog):
    routes = {
        "cluster/resources": [
            {"type": "node", "node": "a", "status": "online"},
            {"type": "node", "node": "b", "status": "online"},
            {"type": "storage", "storage": "nas", "node": "a", "shared": 1, "status": "available"},
            {"type": "storage", "storage": "nas", "node": "b", "shared": 1, "status": "available"},
            {"type": "storage", "storage": "local", "node": "a", "status": "available"},
            {"type": "storage", "storage": "local", "node": "b", "status": "available"},
        ],
        "nodes/b/disks/list": ConnectionError("node b timed out"),
        "cluster/tasks": [{"upid": None, "node": "a", "type": "x", "status": "boom", "endtime": time.time()}],
    }
    snap = Collector(make_cfg(), api=_Api(routes)).collect(time.time() - 60)
    assert [(s["storage"], s["node"]) for s in snap.storage] == [("nas", "a"), ("local", "a"), ("local", "b")]
    assert "Skipping disk list on b: node b timed out" in caplog.text
    assert snap.failed_tasks[0]["log_tail"] == []  # no UPID → no log fetch


# --------------------------------------------------------------- monitor / llm

class _StubCollector:
    def __init__(self, snap):
        self.snap = snap

    def collect(self, since):
        self.snap.taken_at = time.time()
        return self.snap


def test_lookup_budget_goes_to_critical_first(make_cfg, monkeypatch):
    cfg = make_cfg()
    cfg.lookup.enabled = True
    cfg.lookup.max_lookups_per_check = 1
    snap = Snapshot(taken_at=time.time(), log_errors={
        "pve1": ["Oct 13 09:00:00 pve1 pvestatd[1]: got timeout while reading storage status"],
        "pve2": ["Oct 13 09:00:00 pve2 kernel: blk_update_request: I/O error, dev sdb, sector 1234"],
    })
    m = Monitor(cfg, persist=False, collector=_StubCollector(snap))
    searched = []

    async def research(q):
        searched.append(q)
        return [{"title": "t", "url": "https://forum.proxmox.com/x", "excerpt": "e"}]

    async def diagnose(findings, refs):
        return None

    monkeypatch.setattr(m.lookup, "research", research)
    monkeypatch.setattr(m.diagnoser, "diagnose", diagnose)
    asyncio.run(m.check())
    assert len(searched) == 1 and "I/O error" in searched[0]


def test_short_queries_skipped_and_resolved_suppressed(make_cfg, monkeypatch):
    cfg = make_cfg()
    cfg.lookup.enabled = True
    cfg.send_resolved = False
    m = Monitor(cfg, persist=False, collector=_StubCollector(Snapshot(taken_at=0)))
    f = Finding("k", WARNING, "t", "d", kind="event", lookup_messages=["pve1 1234", "error 9"])
    called = []

    async def research(q):
        called.append(q)
        return []

    monkeypatch.setattr(m.lookup, "research", research)
    assert asyncio.run(m._gather_references([f], None)) == {} and called == []
    m.state.active["gone"] = {"severity": "warning", "title": "old", "last_notified": 0}
    r = asyncio.run(m.check())
    assert r.resolved == [] and r.findings == []


def test_diagnose_nothing_is_none(make_cfg):
    assert asyncio.run(Diagnoser(make_cfg().ollama).diagnose([], {})) is None


# ----------------------------------------------------- prompt shutdown (docker stop)

def _hanging_server():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)  # accepts connections, never answers
    return s


def _stop_after(delay):
    import os
    import signal

    async def later():
        await asyncio.sleep(delay)
        os.kill(os.getpid(), signal.SIGTERM)
    return later


@pytest.mark.parametrize("phase", ["startup", "check"])
def test_sigterm_interrupts_slow_ollama_promptly(pve, discord, make_cfg, phase):
    hang = _hanging_server()
    try:
        cfg = make_cfg(pve=pve, discord=discord)
        cfg.ollama.url = f"http://127.0.0.1:{hang.getsockname()[1]}"
        cfg.ollama.timeout = 300
        cfg.poll_interval_seconds = 300
        if phase == "check":
            # Let the 10 s model check fail fast so the hang happens inside the check's diagnosis call.
            async def quick_check(self):
                return False
            from proxmox_canary.llm import Diagnoser
            orig = Diagnoser.check_model
            Diagnoser.check_model = quick_check

        async def go():
            asyncio.ensure_future(_stop_after(2.0)())
            t0 = time.monotonic()
            rc = await asyncio.wait_for(cli.run_service(cfg), 30)
            return rc, time.monotonic() - t0

        try:
            rc, elapsed = asyncio.run(go())
        finally:
            if phase == "check":
                Diagnoser.check_model = orig
        assert rc == 0 and elapsed < 4, f"took {elapsed:.1f}s to stop"
        assert discord.messages == []  # interrupted before sending; nothing marked as sent
    finally:
        hang.close()


def test_collector_cancel_stops_after_current_call(make_cfg):
    from proxmox_canary.collector import CollectorCancelled
    calls = []

    class Api(_Api):
        def __getattr__(self, name):
            return Api(self.routes, self.path + (name,))

        def __call__(self, arg):
            return Api(self.routes, self.path + (str(arg),))

        def get(self, **kw):
            calls.append("/".join(self.path))
            if self.path == ("nodes", "a", "disks", "zfs"):
                collector.cancel()  # stop requested while this call is in flight
            return super().get(**kw)

    routes = {"cluster/resources": [{"type": "node", "node": "a", "status": "online"},
                                    {"type": "node", "node": "b", "status": "online"}]}
    collector = Collector(make_cfg(), api=Api(routes))
    with pytest.raises(CollectorCancelled):
        collector.collect(time.time() - 60)
    assert calls == ["cluster/resources", "nodes/a/disks/zfs"]
    with pytest.raises(CollectorCancelled):
        collector.collect(time.time())


def test_sigterm_during_delivery_finishes_and_records(pve, discord, make_cfg, tmp_path, monkeypatch):
    """docker stop while alerts are being posted: delivery completes and is recorded, so a
    restart does not post the same alerts again."""
    import os
    import signal
    orig_send = da.DiscordAlerter.send

    async def slow_send(self, messages):
        os.kill(os.getpid(), signal.SIGTERM)  # stop arrives mid-delivery
        await asyncio.sleep(1.0)
        await orig_send(self, messages)

    monkeypatch.setattr(da.DiscordAlerter, "send", slow_send)
    cfg = make_cfg(pve=pve, discord=discord)
    cfg.poll_interval_seconds = 300
    t0 = time.monotonic()
    assert asyncio.run(asyncio.wait_for(cli.run_service(cfg), 30)) == 0
    assert time.monotonic() - t0 < 5
    first = len(discord.messages)
    assert first and json.loads((tmp_path / "state.json").read_text())["active"]

    # Restart: same problems, already recorded → nothing posted.
    monkeypatch.setattr(da.DiscordAlerter, "send", orig_send)

    async def run_briefly():
        asyncio.ensure_future(_stop_after(2.0)())
        return await asyncio.wait_for(cli.run_service(cfg), 30)

    assert asyncio.run(run_briefly()) == 0
    assert len(discord.messages) == first


def test_stuck_delivery_is_cut_off_after_grace():
    class Coll:
        cancelled = False

        def cancel(self):
            self.cancelled = True

    class Mon:
        collector = Coll()

    async def go():
        stop = asyncio.Event()

        async def stuck():
            stop.set()
            await asyncio.sleep(60)

        t0 = time.monotonic()
        await cli._unless_stopped(stuck(), stop, Mon(), delivering=lambda: True, grace=0.5)
        return time.monotonic() - t0

    elapsed = asyncio.run(go())
    assert 0.4 < elapsed < 2 and Mon.collector.cancelled


# ------------------------------------------- the canary's own errors never reach Discord

def _all_discord_text(discord):
    return json.dumps(discord.messages, ensure_ascii=False)


def test_unexpected_crash_posts_oops_once_and_logs_details(pve, discord, make_cfg, monkeypatch, caplog):
    from test_end_to_end import run_service_until
    from proxmox_canary import monitor as monitor_mod
    from proxmox_canary.discord_alerts import OOPS, RECOVERED

    real_evaluate = monitor_mod.evaluate
    crashing = {"on": True}

    def broken(*a, **kw):
        if crashing["on"]:
            raise RuntimeError("internal detail: KeyError 'maxmem' at rules.py:123")
        return real_evaluate(*a, **kw)

    monkeypatch.setattr(monitor_mod, "evaluate", broken)
    cfg = make_cfg(pve=pve, discord=discord)
    cfg.poll_interval_seconds = 1
    calls = lambda: len([r for r in pve.server.requests if "cluster/resources" in r[1]])  # noqa: E731
    run_service_until(cfg, lambda: calls() >= 3)
    assert [m["content"] for m in discord.messages] == [OOPS]  # once, not every cycle
    text = _all_discord_text(discord)
    for leak in ("internal detail", "KeyError", "Traceback", "RuntimeError", "rules.py"):
        assert leak not in text
    assert "internal detail: KeyError" in caplog.text and "Traceback" in caplog.text

    crashing["on"] = False
    discord.messages.clear()
    run_service_until(cfg, lambda: len(discord.messages) >= 2, settle=0.5)
    assert discord.messages[0]["content"] == RECOVERED  # then the real alerts
    assert any(e["title"].startswith("🔴") for m in discord.messages[1:] for e in m["embeds"])


def test_discord_down_is_logged_only(pve, discord, make_cfg, monkeypatch, caplog):
    from test_end_to_end import run_service_until

    async def no_backoff(s):
        return None

    monkeypatch.setattr(da, "_sleep", no_backoff)
    discord.fail_posts = 10_000
    cfg = make_cfg(pve=pve, discord=discord)
    cfg.poll_interval_seconds = 1
    calls = lambda: len([r for r in pve.server.requests if "cluster/resources" in r[1]])  # noqa: E731
    run_service_until(cfg, lambda: calls() >= 2)
    assert discord.messages == []
    assert "Could not post the failure notice to Discord" in caplog.text
    state = Path(cfg.state_file)
    assert not state.exists() or json.loads(state.read_text()).get("broken_since") is None


def test_once_failure_prints_oops(pve, make_cfg, capsys, caplog):
    from proxmox_canary.discord_alerts import OOPS
    pve.scenario["down"] = True
    assert asyncio.run(cli.run_once(make_cfg(pve=pve))) == 1
    assert capsys.readouterr().out.strip() == OOPS
    assert "cannot query /cluster/resources: 503" in caplog.text


def test_test_alert_failure_prints_oops(discord, make_cfg, capsys, caplog):
    from proxmox_canary.discord_alerts import OOPS
    cfg = make_cfg(discord=discord)
    cfg.discord.token = "wrong"
    assert asyncio.run(cli.send_test_alert(cfg)) == 1
    assert capsys.readouterr().out.strip() == OOPS
    assert "401" in caplog.text and discord.messages == []


def test_oops_wording():
    from proxmox_canary.discord_alerts import OOPS, oops_message
    assert OOPS == "🐤💫 Oops! Something broke." and oops_message() == {"content": OOPS}
