import asyncio
import json

import pytest

from proxmox_canary.config import LookupConfig, OllamaConfig
from proxmox_canary.llm import MAX_PROMPT_CHARS, Diagnoser
from proxmox_canary.lookup import WebLookup, scrub
from proxmox_canary.rules import Finding


# ------------------------------------------------------------------ scrubbing

def test_scrub_removes_private_details():
    line = ("pvedaemon: authentication failure; rhost=::ffff:192.168.1.23 user=alice@pam msg=bad "
            "mac 52:54:00:12:34:56 uuid 0b5c4e2a-1d3f-4b6a-9c8d-7e6f5a4b3c2d on pve1 vm plex "
            "path /home/alice/secret.txt task UPID:pve1:0001:abc:vzdump::root@pam: sector 123456 email a.b@ex.com "
            "ipv6 fe80::1ff:fe23:4567:890a hash 9f86d081884c7d65")
    out = scrub(line, {"pve1", "plex"}, [])
    for secret in ("192.168", "alice@pam", "52:54:00", "0b5c4e2a", "pve1", "plex", "/home/alice", "UPID", "123456",
                   "a.b@ex.com", "fe80", "9f86d081884c7d65"):
        assert secret not in out, secret
    assert "authentication failure" in out


def test_scrub_whole_words_only():
    out = scrub("complex plexus plex failed", {"plex"}, [])
    assert out == "complex plexus failed"


def test_scrub_extra_patterns():
    import re
    assert scrub("job for customer-acme failed", set(), [re.compile(r"customer-\w+")]) == "job for failed"


def test_build_query():
    w = WebLookup(LookupConfig())
    q = w.build_query("kernel: blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2", {"pve1"})
    assert q.startswith("proxmox kernel: blk_update_request: I/O error dev sdb sector")
    assert len(q.split()) <= 15
    assert w.build_query("x 1234", set()) == ""  # nothing searchable left
    w2 = WebLookup(LookupConfig(query_prefix=""))
    assert not w2.build_query("pveproxy: failed to bind socket address in use", set()).startswith("proxmox")


def test_rank_prefers_known_domains():
    w = WebLookup(LookupConfig())
    rows = [{"url": "https://blog.example.com/a"}, {"url": "https://www.reddit.com/r/Proxmox/x"},
            {"url": "https://forum.proxmox.com/threads/1"}, {"url": "https://evilforum.proxmox.com.attacker.net/x"}]
    order = [r["url"] for r in w._rank(rows)]
    assert order[0].startswith("https://forum.proxmox.com") and order[1].startswith("https://www.reddit.com")
    assert order.index("https://evilforum.proxmox.com.attacker.net/x") > 1


# ------------------------------------------------------------ search + fetch

def test_searxng_research(web):
    w = WebLookup(LookupConfig(provider="searxng", searxng_url=web.base + "/", pages_to_read=2))
    src = asyncio.run(w.research("proxmox I/O error"))
    assert web.searches == ["proxmox I/O error"]
    assert [s["title"] for s in src][:2] == ["Random blog about disks", "I/O error on SATA SSD | Proxmox Support Forum"]
    forum = src[1]["excerpt"]
    assert "failing disk or a bad SATA cable" in forum and "Replacing the cable" in forum
    assert "tracking" not in forum and "Home Forums" not in forum and "Copyright" not in forum
    # Unread results become snippet-only sources; non-HTML and 404 pages fall back to snippets too.
    assert {"pdf snippet", "missing snippet"} <= {s["excerpt"] for s in src}


def test_research_falls_back_to_snippet_when_page_unreadable(web):
    w = WebLookup(LookupConfig(provider="searxng", searxng_url=web.base, pages_to_read=4))
    src = asyncio.run(w.research("x"))
    by_title = {s["title"]: s["excerpt"] for s in src}
    assert by_title["A PDF"] == "pdf snippet" and by_title["Gone"] == "missing snippet"


def test_brave(web):
    w = WebLookup(LookupConfig(provider="brave", brave_api_key="brave-key", pages_to_read=0))
    rows = asyncio.run(w.search("query"))
    assert len(rows) == 4 and rows[0]["snippet"]
    bad = WebLookup(LookupConfig(provider="brave", brave_api_key="wrong"))
    assert asyncio.run(bad.search("query")) == []


def test_search_failure_returns_empty(web):
    web.fail_search = True
    w = WebLookup(LookupConfig(provider="searxng", searxng_url=web.base))
    assert asyncio.run(w.research("x")) == []


def test_ddgs_adapter(monkeypatch):
    import ddgs

    class Fake:
        def text(self, query, max_results):
            assert max_results == 5
            return [{"title": "T", "href": "https://forum.proxmox.com/t", "body": "B"}, {"title": "no url", "href": "", "body": ""}]

    monkeypatch.setattr(ddgs, "DDGS", Fake)
    rows = asyncio.run(WebLookup(LookupConfig()).search("q"))
    assert rows == [{"title": "T", "url": "https://forum.proxmox.com/t", "snippet": "B"}]


def test_ddgs_error_is_caught(monkeypatch):
    import ddgs

    class Boom:
        def text(self, *a, **k):
            raise ddgs.exceptions.DDGSException("No results found.")

    monkeypatch.setattr(ddgs, "DDGS", Boom)
    assert asyncio.run(WebLookup(LookupConfig()).search("q")) == []


# --------------------------------------------------------------------- Ollama

def findings():
    return [
        Finding("disk-health:pve1/dev/sdb", "critical", "Disk /dev/sdb reports SMART FAILED", "Crucial MX500"),
        Finding("logs:pve1:1", "critical", "2 error lines", "1 distinct", kind="event",
                context=["2× kernel: I/O error, dev sdb"]),
    ]


REFS = {"logs:pve1:1": [{"id": "R1", "title": "Forum", "url": "https://forum.proxmox.com/1", "excerpt": "Bad cable"},
                        {"id": "R2", "title": "Blog", "url": "https://blog/2", "excerpt": "Other"}]}


def test_check_model(ollama):
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).check_model())
    ollama.models = ["qwen2.5:latest"]
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5")).check_model())
    assert not asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="llama3.1:8b")).check_model())
    assert not asyncio.run(Diagnoser(OllamaConfig(url="http://127.0.0.1:1", model="x")).check_model())


def test_diagnose_request_and_parse(ollama):
    d = Diagnoser(OllamaConfig(url=ollama.url + "/", model="qwen2.5:7b", keep_alive="1h30m"))
    overview, diag = asyncio.run(d.diagnose(findings(), REFS))
    req = ollama.chats[0]
    assert req["format"] == "json" and req["options"]["num_ctx"] == 12288 and req["stream"] is False
    payload = json.loads(req["messages"][1]["content"].split("Findings:\n", 1)[1])
    assert payload[1]["references"][0]["id"] == "R1" and payload[1]["evidence"] == ["2× kernel: I/O error, dev sdb"]
    assert "references" not in payload[0]
    assert overview.startswith("Disk sdb is failing")
    assert diag["logs:pve1:1"]["sources"] == [{"title": "Forum", "url": "https://forum.proxmox.com/1"},
                                              {"title": "Blog", "url": "https://blog/2"}]
    assert diag["disk-health:pve1/dev/sdb"]["sources"] == []
    assert diag["logs:pve1:1"]["confidence"] == "medium"


def test_diagnose_drops_hallucinations(ollama):
    ollama.mode = "hallucinate"
    _, diag = asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), REFS))
    assert "made-up:key" not in diag
    assert [s["url"] for s in diag["logs:pve1:1"]["sources"]] == ["https://forum.proxmox.com/1"]
    assert diag["logs:pve1:1"]["confidence"] == ""


@pytest.mark.parametrize("mode", ["garbage", "not_object", "error"])
def test_diagnose_failures_return_none(ollama, mode):
    ollama.mode = mode
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), {})) is None


@pytest.mark.parametrize("mode", ["fenced", "thought"])
def test_diagnose_tolerates_wrapped_json(ollama, mode):
    ollama.mode = mode
    overview, diag = asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), {}))
    assert overview.startswith("Disk sdb is failing") and diag
    assert len(ollama.chats) == 1  # no retry needed


def test_diagnose_retries_without_json_mode(ollama, caplog):
    caplog.set_level("INFO", logger="proxmox_canary")
    ollama.mode = "json_mode_empty"
    overview, diag = asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), {}))
    assert diag and [c.get("format") for c in ollama.chats] == ["json", None]
    assert "no JSON object" in caplog.text and "chars of thinking" in caplog.text
    assert "Retrying with thinking off" in caplog.text


def test_diagnose_reports_full_context(ollama, caplog):
    ollama.mode = "ctx_full"
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), {})) is None
    assert "Raise ollama.num_ctx" in caplog.text and "done_reason=length" in caplog.text
    assert len(ollama.chats) == 3  # every approach tried


def test_thinking_disabled_by_default(ollama):
    ollama.mode = "thinker"
    overview, diag = asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), {}))
    assert diag and ollama.chats[0]["think"] is False and len(ollama.chats) == 1


def test_thinking_enabled_falls_back_when_out_of_room(ollama, caplog):
    ollama.mode = "thinker"  # thinks itself out of room whenever thinking is on
    d = Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b", think=True))
    overview, diag = asyncio.run(d.diagnose(findings(), {}))
    assert diag and "spent its whole output budget thinking" in caplog.text
    assert [c.get("think") for c in ollama.chats] == [None, False]  # thinking first, as configured


def test_model_without_think_support(ollama, caplog):
    caplog.set_level("INFO", logger="proxmox_canary")
    ollama.mode = "no_think_support"
    d = Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b"))
    overview, diag = asyncio.run(d.diagnose(findings(), {}))
    assert diag and len(ollama.rejected) == 1 and "think" not in ollama.chats[0]
    assert "does not accept the think option" in caplog.text
    asyncio.run(d.diagnose(findings(), {}))  # remembered: no second rejection
    assert len(ollama.rejected) == 1


def test_garbage_reply_is_logged(ollama, caplog):
    ollama.mode = "garbage"
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), {})) is None
    assert "Start of reply: 'Sure! Here is my analysis" in caplog.text


def test_diagnose_timeout_and_unreachable(ollama):
    ollama.mode = "slow"
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b", timeout=1)).diagnose(findings(), {})) is None
    assert asyncio.run(Diagnoser(OllamaConfig(url="http://127.0.0.1:1", model="m")).diagnose(findings(), {})) is None
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="missing:1b")).diagnose(findings(), {})) is None


def test_prompt_is_bounded():
    big = [Finding(f"logs:n{i}:1", "warning", "t", "d", kind="event", context=["x" * 500] * 40) for i in range(30)]
    refs = {f.key: [{"id": "R1", "title": "t", "url": "u", "excerpt": "y" * 5000}] * 6 for f in big}
    assert len(Diagnoser(OllamaConfig(url="http://x", model="m"))._build_prompt(big, refs)) <= MAX_PROMPT_CHARS


def test_empty_instant_reply_is_explained(ollama, caplog):
    ollama.mode = "instant_empty"
    assert asyncio.run(Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b")).diagnose(findings(), {})) is None
    assert "'eval_count': 0" in caplog.text and "'total_duration': '0.05s'" in caplog.text
    assert "produced no tokens at all" in caplog.text and "ollama -v" in caplog.text


def test_model_that_only_answers_when_thinking(ollama, caplog):
    """Returns nothing instantly with thinking off; needs thinking and a big context."""
    caplog.set_level("INFO", logger="proxmox_canary")
    ollama.mode = "gemma_like"
    d = Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b"))
    overview, diag = asyncio.run(d.diagnose(findings(), {}))
    assert overview.startswith("Disk sdb is failing") and diag
    assert [(c.get("think"), c.get("format"), c["options"]["num_ctx"]) for c in ollama.chats] == [
        (False, "json", 12288), (False, None, 12288), (None, None, 32768)]
    assert "produced no tokens at all" in caplog.text
    assert "works with thinking on; using that first from now on" in caplog.text
    # Next time it goes straight to what worked.
    ollama.chats.clear()
    assert asyncio.run(d.diagnose(findings(), {}))[1]
    assert len(ollama.chats) == 1 and "think" not in ollama.chats[0]


def test_timeout_stops_the_fallbacks(ollama):
    ollama.mode = "slow"
    d = Diagnoser(OllamaConfig(url=ollama.url, model="qwen2.5:7b", timeout=1))
    assert asyncio.run(d.diagnose(findings(), {})) is None
    assert len(ollama.chats) == 1  # not three slow attempts in a row


def test_unreachable_stops_the_fallbacks(caplog):
    d = Diagnoser(OllamaConfig(url="http://127.0.0.1:1", model="m"))
    assert asyncio.run(d.diagnose(findings(), {})) is None
    assert caplog.text.count("Ollama request failed") == 1
