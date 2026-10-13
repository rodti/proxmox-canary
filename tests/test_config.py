from pathlib import Path

import pytest

from proxmox_canary.config import ConfigError, load_config

ROOT = Path(__file__).resolve().parents[1]


def _write(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return p


def test_example_config_needs_secrets():
    with pytest.raises(ConfigError, match="proxmox.token_value"):
        load_config(ROOT / "config.example.yaml")


def test_example_config_loads_with_env(monkeypatch):
    monkeypatch.setenv("CANARY_PROXMOX_TOKEN_VALUE", "secret")
    monkeypatch.setenv("CANARY_DISCORD_TOKEN", "bot")
    monkeypatch.setenv("CANARY_DISCORD_CHANNEL_ID", "123456789012345678")
    cfg = load_config(ROOT / "config.example.yaml")
    assert cfg.proxmox.token_value == "secret"
    assert cfg.discord.channel_id == 123456789012345678
    assert cfg.check_updates is False  # needs Sys.Modify, off by default
    assert cfg.lookup.provider == "ddgs"
    assert cfg.thresholds.sustained_samples == 3
    assert cfg.logs.include  # defaults kept when the section omits them


def test_env_overrides_model_and_url(monkeypatch):
    for k, v in {"CANARY_PROXMOX_TOKEN_VALUE": "s", "CANARY_DISCORD_TOKEN": "b", "CANARY_DISCORD_CHANNEL_ID": "1",
                 "CANARY_OLLAMA_URL": "http://gpu.lan:11434", "CANARY_OLLAMA_MODEL": "llama3.1:8b"}.items():
        monkeypatch.setenv(k, v)
    cfg = load_config(ROOT / "config.example.yaml")
    assert cfg.ollama.url == "http://gpu.lan:11434" and cfg.ollama.model == "llama3.1:8b"


MINIMAL = """
proxmox: {host: pve, user: u@pve, token_name: t, token_value: v}
ollama: {url: "http://o:11434", model: m}
discord: {token: x, channel_id: 5}
"""


def test_minimal_config(tmp_path):
    cfg = load_config(_write(tmp_path, MINIMAL))
    assert cfg.proxmox.port == 8006 and cfg.proxmox.verify_ssl is True
    assert cfg.poll_interval_seconds == 300


@pytest.mark.parametrize("bad, match", [
    (MINIMAL + "pol_interval_seconds: 60\n", "unknown top-level"),
    (MINIMAL + "thresholds: {node_cpu: 80}\n", "unknown key"),
    (MINIMAL + "poll_interval_seconds: 5\n", "at least 30"),
    (MINIMAL + "logs: {include: ['([']}\n", "invalid regex"),
    (MINIMAL + "lookup: {provider: google}\n", "provider"),
    (MINIMAL + "lookup: {provider: searxng}\n", "searxng_url"),
    (MINIMAL + "lookup: {provider: brave}\n", "brave_api_key"),
    (MINIMAL.replace("channel_id: 5", "channel_id: abc"), "not a number"),
    (MINIMAL.replace("token_value: v", "token_value: CHANGE_ME"), "token_value"),
    ("proxmox: [1, 2]\n", "must be a mapping"),
    ("- just a list\n", "top level"),
    ("proxmox: {host: [unclosed\n", "cannot parse"),
])
def test_bad_configs(tmp_path, bad, match):
    with pytest.raises(ConfigError, match=match):
        load_config(_write(tmp_path, bad))


def test_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_discord_optional_for_once(tmp_path):
    text = MINIMAL.replace("discord: {token: x, channel_id: 5}\n", "")
    with pytest.raises(ConfigError, match="discord.token"):
        load_config(_write(tmp_path, text))
    cfg = load_config(_write(tmp_path, text), require_discord=False)
    assert cfg.discord.channel_id == 0
