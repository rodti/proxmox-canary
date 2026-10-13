"""Send canary-themed alerts to a Discord channel with a bot token (REST only, alerts only)."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

import httpx

from .config import DiscordConfig
from .monitor import Report
from .rules import Finding

log = logging.getLogger(__name__)

API = "https://discord.com/api/v10"
_sleep = asyncio.sleep  # back-off waits (patched in tests)

COLORS = {
    "critical": 0xC0392B,  # the canary is down
    "warning": 0xFFD300,  # canary yellow
    "info": 0xFFF1A6,  # pale yellow
    "resolved": 0x58D68D,
}
ICONS = {"critical": "🔴", "warning": "🟡", "info": "🔵"}
HEADLINES = {
    "critical": "🚨 **Danger!**",
    "warning": "⚠️ **Potential issue detected.**",
    "info": "ℹ️ **For information.**",
    "resolved": "✅ **All good.**",
}
AUTHOR = {"name": "Proxmox Canary"}

# The canary's own failures never reach Discord as error text: details go to the logs,
# Discord gets these.
OOPS = "🐤💫 Oops! Something broke."
RECOVERED = "✅ **All good.** Monitoring is working again."


def oops_message() -> dict[str, Any]:
    return {"content": OOPS}


def recovered_message() -> dict[str, Any]:
    return {"content": RECOVERED}
CONFIDENCE = {"high": "high confidence", "medium": "medium confidence", "low": "low confidence"}


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _embed_size(e: dict[str, Any]) -> int:
    n = len(e.get("title", "")) + len(e.get("description", ""))
    n += len(e.get("footer", {}).get("text", "")) + len(e.get("author", {}).get("name", ""))
    n += sum(len(f["name"]) + len(f["value"]) for f in e.get("fields", []))
    return n


MAX_EMBED_CHARS = 5900  # Discord rejects messages whose embeds total more than 6000 characters
SOURCES = "📚 Sources"


def _shrink_field(field: dict[str, Any], target: int) -> None:
    value = field["value"]
    if field["name"] == SOURCES:
        # Drop whole links rather than cutting one in half; a cut link is broken markdown.
        lines = value.split("\n")
        while len(lines) > 1 and len("\n".join(lines)) > target:
            lines.pop()
        field["value"] = "\n".join(lines)
    elif value.startswith("```\n") and value.endswith("\n```"):
        field["value"] = "```\n" + _clip(value[4:-4], max(target - 8, 1)) + "\n```"
    else:
        field["value"] = _clip(value, max(target, 1))


def _fit_embed(e: dict[str, Any], limit: int = MAX_EMBED_CHARS) -> dict[str, Any]:
    """Trim the description, then fields from the bottom up, until one embed fits on its own."""
    over = _embed_size(e) - limit
    if over > 0:
        desc = e.get("description", "")
        cut = min(over, max(len(desc) - 300, 0))
        if cut:
            e["description"] = _clip(desc, len(desc) - cut)
            over = _embed_size(e) - limit
    for field in reversed(e.get("fields", [])):
        if over <= 0:
            break
        cut = min(over, max(len(field["value"]) - 120, 0))
        if cut:
            _shrink_field(field, len(field["value"]) - cut)
            over = _embed_size(e) - limit
    if over > 0:  # only a single long link is left to give up
        e["fields"] = [f for f in e.get("fields", []) if f["name"] != SOURCES]
    return e


def _source_links(sources: list[dict[str, str]], limit: int = 1024) -> str:
    """Markdown links, whole ones only, within Discord's field limit."""
    lines: list[str] = []
    for s in sources[:4]:
        line = f"[{_clip(s['title'] or s['url'], 90)}]({s['url']})"
        if len("\n".join(lines + [line])) <= limit:
            lines.append(line)
    return "\n".join(lines)


def finding_embed(f: Finding, diag: dict[str, Any] | None, reminder_since: float | None = None) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    if reminder_since:
        fields.append({"name": "⏰ Still happening", "value": f"First seen <t:{int(reminder_since)}:R>.", "inline": False})
    if diag:
        if diag.get("root_cause"):
            conf = CONFIDENCE.get(diag.get("confidence", ""), "")
            name = "🔍 Likely cause" + (f" ({conf})" if conf else "")
            fields.append({"name": name, "value": _clip(diag["root_cause"], 1024), "inline": False})
        if diag.get("fix"):
            fields.append({"name": "🛠️ Suggested fix", "value": _clip(diag["fix"], 1024), "inline": False})
    if f.context:
        excerpt = _clip("\n".join(f.context[:8]).replace("```", "'''"), 1000)
        fields.append({"name": "📜 Evidence", "value": f"```\n{excerpt}\n```", "inline": False})
    links = _source_links(diag.get("sources") or []) if diag else ""
    if links:
        fields.append({"name": SOURCES, "value": links, "inline": False})
    return _fit_embed({
        "author": AUTHOR,
        "title": _clip(f"{ICONS.get(f.severity, '')} {f.title}", 256),
        "description": _clip(f.detail, 4096),
        "color": COLORS.get(f.severity, COLORS["info"]),
        "fields": fields[:25],
        "footer": {"text": _clip(f"proxmox-canary · {f.severity}{' · reminder' if reminder_since else ''}", 2048)},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


def resolved_embed(items: list[dict[str, Any]]) -> dict[str, Any]:
    lines = [f"✅ {a.get('title', a['key'])}" for a in items]
    return {
        "author": AUTHOR,
        "title": "✅ Resolved",
        "description": _clip("\n".join(lines), 4000),
        "color": COLORS["resolved"],
        "footer": {"text": "proxmox-canary · resolved"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def build_messages(report: Report, active: dict[str, dict[str, Any]], mention: str = "") -> list[dict[str, Any]]:
    """Turn a report into Discord message payloads (≤10 embeds and ≤6000 chars each)."""
    rank = {"critical": 0, "warning": 1, "info": 2}
    new = sorted(report.new, key=lambda f: rank.get(f.severity, 3))
    repeat = sorted(report.repeat, key=lambda f: rank.get(f.severity, 3))
    embeds = [finding_embed(f, report.diagnoses.get(f.key)) for f in new]
    embeds += [finding_embed(f, None, active.get(f.key, {}).get("first_seen") or time.time()) for f in repeat]
    if report.resolved:
        embeds.append(resolved_embed(report.resolved))
    if not embeds:
        return []

    alerting = report.new + report.repeat
    if any(f.severity == "critical" for f in alerting):
        mood = "critical"
    elif any(f.severity == "warning" for f in alerting):
        mood = "warning"
    elif alerting:
        mood = "info"
    else:
        mood = "resolved"
    header = [HEADLINES[mood]]
    if mention and any(f.severity == "critical" for f in report.new):
        header.insert(0, mention)
    if report.overview:
        header.append(f"> {report.overview}")
    content = _clip("\n".join(header), 2000)

    messages: list[dict[str, Any]] = []
    batch: list[dict[str, Any]] = []
    size = 0
    for e in embeds:
        es = _embed_size(e)
        if batch and (len(batch) == 10 or size + es > 5800):
            messages.append({"embeds": batch})
            batch, size = [], 0
        batch.append(e)
        size += es
    messages.append({"embeds": batch})
    messages[0]["content"] = content
    return messages


def _allowed_mentions(mention: str) -> dict[str, Any]:
    roles = re.findall(r"<@&(\d+)>", mention)
    users = re.findall(r"<@!?(\d+)>", mention)
    return {"parse": [], "roles": roles, "users": users}


class DiscordAlerter:
    def __init__(self, cfg: DiscordConfig):
        self.cfg = cfg
        self.headers = {
            "Authorization": f"Bot {cfg.token}",
            "User-Agent": "DiscordBot (https://github.com/, 0.1) proxmox-canary",
        }

    async def _request(self, client: httpx.AsyncClient, method: str, path: str, **kw) -> httpx.Response:
        for attempt in range(5):
            r = await client.request(method, f"{API}{path}", headers=self.headers, **kw)
            if r.status_code == 429:
                wait = float(r.json().get("retry_after", 1.0)) if r.content else 1.0
                log.info("Discord rate limit, waiting %.1fs", wait)
                await _sleep(wait + 0.1)
                continue
            if r.status_code >= 500 and attempt < 4:
                await _sleep(2**attempt)
                continue
            r.raise_for_status()
            return r
        r.raise_for_status()
        return r

    async def verify(self) -> None:
        """Log in to the gateway once (Discord requires it before a bot can post) and check the channel."""
        await gateway_login(self.cfg.token)
        async with httpx.AsyncClient(timeout=20) as client:
            r = await self._request(client, "GET", f"/channels/{self.cfg.channel_id}")
            log.info("Discord channel OK: #%s", r.json().get("name", self.cfg.channel_id))

    async def send(self, messages: list[dict[str, Any]]) -> None:
        allowed = _allowed_mentions(self.cfg.mention_on_critical)
        async with httpx.AsyncClient(timeout=30) as client:
            for m in messages:
                await self._request(
                    client, "POST", f"/channels/{self.cfg.channel_id}/messages",
                    json={**m, "allowed_mentions": allowed},
                )


async def gateway_login(token: str) -> str:
    """Identify on the Discord gateway once, then disconnect. Returns the bot's username."""
    import websockets

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"{API}/gateway/bot", headers={"Authorization": f"Bot {token}"})
        if r.status_code == 401:
            raise RuntimeError("Discord rejected the bot token (401)")
        r.raise_for_status()
        url = r.json()["url"]
    try:
        return await _identify(f"{url}/?v=10&encoding=json", token)
    except websockets.ConnectionClosed as e:
        code = e.rcvd.code if e.rcvd else None
        if code == 4004:
            raise RuntimeError("Discord rejected the bot token (gateway close 4004)") from e
        raise RuntimeError(f"Discord gateway closed the connection (code {code})") from e


async def _identify(url: str, token: str) -> str:
    import websockets

    async with websockets.connect(url, open_timeout=20) as ws:
        hello = json.loads(await asyncio.wait_for(ws.recv(), 20))
        if hello.get("op") != 10:
            raise RuntimeError(f"unexpected gateway greeting: {hello.get('op')}")
        await ws.send(json.dumps({
            "op": 2,
            "d": {
                "token": token,
                "intents": 0,
                "properties": {"os": "linux", "browser": "proxmox-canary", "device": "proxmox-canary"},
            },
        }))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            msg = json.loads(await asyncio.wait_for(ws.recv(), 20))
            if msg.get("op") == 9:
                raise RuntimeError("Discord gateway rejected the session")
            if msg.get("t") == "READY":
                name = msg["d"]["user"]["username"]
                log.info("Discord bot logged in as %s", name)
                return name
    raise RuntimeError("timed out waiting for Discord gateway READY")
