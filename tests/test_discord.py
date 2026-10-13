import asyncio
import time

import pytest

from fakes import validate_message
from proxmox_canary.config import DiscordConfig
from proxmox_canary.discord_alerts import (
    COLORS, HEADLINES, DiscordAlerter, _allowed_mentions, build_messages, gateway_login,
)
from proxmox_canary.monitor import Report
from proxmox_canary.rules import Finding


def report(new=(), repeat=(), resolved=(), overview=None, diagnoses=None):
    new, repeat = list(new), list(repeat)
    return Report(new + repeat, new, repeat, list(resolved), True, time.time(), overview, diagnoses or {})


def test_theme_and_ordering():
    msgs = build_messages(report(
        new=[Finding("w", "warning", "Warn", "d"), Finding("c", "critical", "Crit", "d"), Finding("i", "info", "Info", "d")],
        overview="Overview text", diagnoses={"c": {"root_cause": "Cause", "fix": "Fix", "confidence": "high",
                                                   "sources": [{"title": "Forum", "url": "https://forum.proxmox.com/1"}]}},
    ), {}, mention="<@&555>")
    assert len(msgs) == 1
    m = msgs[0]
    assert m["content"].startswith("<@&555>\n" + HEADLINES["critical"]) and "> Overview text" in m["content"]
    titles = [e["title"] for e in m["embeds"]]
    assert titles == ["🔴 Crit", "🟡 Warn", "🔵 Info"]
    crit = m["embeds"][0]
    assert crit["color"] == COLORS["critical"] and crit["author"]["name"] == "Proxmox Canary"
    names = [f["name"] for f in crit["fields"]]
    assert names == ["🔍 Likely cause (high confidence)", "🛠️ Suggested fix", "📚 Sources"]
    assert "[Forum](https://forum.proxmox.com/1)" in crit["fields"][2]["value"]
    assert not validate_message(m)


def test_moods_and_mentions():
    warn = build_messages(report(new=[Finding("w", "warning", "W", "d")]), {}, mention="<@&555>")[0]
    assert warn["content"] == HEADLINES["warning"]  # no ping for warnings
    info = build_messages(report(new=[Finding("i", "info", "I", "d")]), {})[0]
    assert info["content"] == HEADLINES["info"]
    res = build_messages(report(resolved=[{"key": "a", "title": "High CPU"}]), {})[0]
    assert res["content"] == HEADLINES["resolved"] and res["embeds"][0]["description"] == "✅ High CPU"
    assert res["embeds"][0]["color"] == COLORS["resolved"]
    assert build_messages(report(), {}) == []


def test_reminder_embed():
    f = Finding("w", "warning", "W", "d")
    m = build_messages(report(repeat=[f]), {"w": {"first_seen": 1_700_000_000}})[0]
    e = m["embeds"][0]
    assert e["fields"][0] == {"name": "⏰ Still happening", "value": "First seen <t:1700000000:R>.", "inline": False}
    assert "reminder" in e["footer"]["text"]


def test_limits_with_huge_content():
    big = [Finding(f"k{i}", "critical", "T" * 400, "D" * 5000, kind="event",
                   context=["L" * 900 + "```"] * 30) for i in range(23)]
    diags = {f.key: {"root_cause": "C" * 3000, "fix": "F" * 3000, "confidence": "low",
                     "sources": [{"title": "S" * 200, "url": "https://x/" + "u" * 300}] * 6} for f in big}
    msgs = build_messages(report(new=big, overview="O" * 3000, diagnoses=diags), {}, mention="<@&1>")
    assert sum(len(m["embeds"]) for m in msgs) == 23
    for m in msgs:
        assert validate_message(m) == [], validate_message(m)
    ev = next(f for f in msgs[0]["embeds"][0]["fields"] if f["name"] == "📜 Evidence")
    assert ev["value"].startswith("```\n") and ev["value"].endswith("\n```") and ev["value"].count("```") == 2


def test_allowed_mentions():
    assert _allowed_mentions("") == {"parse": [], "roles": [], "users": []}
    assert _allowed_mentions("<@&1> <@2> <@!3>") == {"parse": [], "roles": ["1"], "users": ["2", "3"]}


def test_gateway_login_and_verify(discord):
    assert asyncio.run(gateway_login("bot-token")) == "Proxmox Canary"
    assert discord.identifies[0]["d"]["intents"] == 0
    asyncio.run(DiscordAlerter(DiscordConfig(token="bot-token", channel_id=discord.channel_id)).verify())


def test_bad_token(discord):
    with pytest.raises(RuntimeError, match="401"):
        asyncio.run(gateway_login("wrong"))


def test_gateway_close_4004(discord, monkeypatch):
    # Token accepted by REST but refused by the gateway → close code 4004.
    import proxmox_canary.discord_alerts as da
    orig = da._identify

    async def wrong_token(url, token):
        return await orig(url, "wrong")

    monkeypatch.setattr(da, "_identify", wrong_token)
    with pytest.raises(RuntimeError, match="4004"):
        asyncio.run(gateway_login("bot-token"))


def test_wrong_channel(discord):
    import httpx
    with pytest.raises(httpx.HTTPStatusError, match="403"):
        asyncio.run(DiscordAlerter(DiscordConfig(token="bot-token", channel_id=999)).verify())


def test_send_handles_rate_limit_and_5xx(discord):
    a = DiscordAlerter(DiscordConfig(token="bot-token", channel_id=discord.channel_id, mention_on_critical="<@&555>"))
    msgs = build_messages(report(new=[Finding("c", "critical", "C", "d")]), {}, "<@&555>")
    discord.rate_limit_next = 1
    discord.fail_posts = 1
    t = time.monotonic()
    asyncio.run(a.send(msgs))
    assert len(discord.messages) == 1 and time.monotonic() - t < 5
    assert discord.messages[0]["allowed_mentions"] == {"parse": [], "roles": ["555"], "users": []}


def test_send_gives_up(discord, monkeypatch):
    import httpx

    import proxmox_canary.discord_alerts as da
    waits = []

    async def fast_sleep(s):
        waits.append(s)

    monkeypatch.setattr(da, "_sleep", fast_sleep)
    a = DiscordAlerter(DiscordConfig(token="bot-token", channel_id=discord.channel_id))
    discord.fail_posts = 10
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(a.send(build_messages(report(new=[Finding("c", "critical", "C", "d")]), {})))
    assert discord.messages == [] and waits == [1, 2, 4, 8]
