from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from fakes import FakeDiscord, FakeOllama, FakeProxmox, FakeWeb  # noqa: E402

from proxmox_canary import discord_alerts, lookup  # noqa: E402
from proxmox_canary.config import load_config  # noqa: E402


@pytest.fixture(scope="session")
def certdir(tmp_path_factory):
    return tmp_path_factory.mktemp("certs")


@pytest.fixture
def pve(certdir):
    s = FakeProxmox(certdir)
    yield s
    s.close()


@pytest.fixture
def ollama():
    s = FakeOllama()
    yield s
    s.close()


@pytest.fixture
def web(monkeypatch):
    s = FakeWeb()
    monkeypatch.setattr(lookup, "BRAVE_URL", f"{s.base}/brave")
    yield s
    s.close()


@pytest.fixture
def discord(monkeypatch):
    s = FakeDiscord()
    monkeypatch.setattr(discord_alerts, "API", s.api)
    yield s
    s.close()


def write_config(tmp_path: Path, pve=None, ollama=None, web=None, discord=None, extra: str = "") -> Path:
    text = f"""
proxmox:
  host: 127.0.0.1
  port: {pve.port if pve else 1}
  user: canary@pve
  token_name: monitor
  token_value: 11111111-2222-3333-4444-555555555555
  verify_ssl: false
  timeout: 5
ollama:
  url: {ollama.url if ollama else 'http://127.0.0.1:1'}
  model: qwen2.5:7b
  timeout: 10
discord:
  token: bot-token
  channel_id: {discord.channel_id if discord else 4242}
  mention_on_critical: "<@&555>"
state_file: {tmp_path / 'state.json'}
thresholds:
  sustained_samples: 1
lookup:
  enabled: {'true' if web else 'false'}
  provider: searxng
  searxng_url: {web.base if web else 'http://127.0.0.1:1'}
  timeout: 5
{extra}
"""
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return p


@pytest.fixture
def make_cfg(tmp_path):
    def _make(**kw):
        return load_config(write_config(tmp_path, **kw))
    return _make
