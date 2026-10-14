"""Configuration loading and validation."""
from __future__ import annotations

import os
import re
from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """The configuration file is missing, malformed or incomplete."""


@dataclass
class ProxmoxConfig:
    host: str
    user: str
    token_name: str
    token_value: str
    port: int = 8006
    verify_ssl: bool = True
    timeout: int = 15


@dataclass
class OllamaConfig:
    url: str
    model: str
    timeout: int = 300
    temperature: float = 0.2
    num_ctx: int = 12288
    keep_alive: str = "10m"
    # Thinking models (qwen3, deepseek-r1 and similar) can spend the whole context window
    # reasoning and never answer. Off by default; ignored by models that cannot think.
    think: bool = False


@dataclass
class DiscordConfig:
    token: str
    channel_id: int
    # Optional text added to critical alerts, e.g. "<@&123456789>" (a role) or "<@123456789>" (a user).
    mention_on_critical: str = ""


@dataclass
class Thresholds:
    node_cpu_pct: float = 90.0
    node_mem_pct: float = 90.0
    node_rootfs_pct: float = 85.0
    guest_cpu_pct: float = 95.0
    guest_mem_pct: float = 95.0
    storage_warn_pct: float = 80.0
    storage_crit_pct: float = 90.0
    storage_days_to_full: float = 7.0
    storage_trend_window_hours: float = 6.0
    # Proxmox reports SSD wearout as remaining life (100 = new). Alert at or below this.
    disk_life_remaining_pct: int = 10
    # CPU/RAM must stay over the threshold for this many consecutive checks.
    sustained_samples: int = 3


DEFAULT_LOG_INCLUDE = [
    r"\berror\b",
    r"\bfail(ed|ure|ing)?\b",
    r"\bcritical\b",
    r"\bpanic\b",
    r"segfault",
    r"out of memory|oom-kill",
    r"i/o error",
    r"\btimed? ?out\b",
    r"\bcorrupt",
    r"call trace",
    r"\bmce:|machine check",
    r"\bdegraded\b",
]

DEFAULT_LOG_CRITICAL = [
    r"kernel panic",
    r"out of memory|oom-kill",
    r"i/o error",
    r"\bcorrupt",
    r"call trace",
    r"\bmce:|machine check",
    r"(ext4|xfs|btrfs)-fs error",
    r"zfs.*(fault|degraded|suspended)",
    r"segfault",
]

DEFAULT_LOG_IGNORE = [
    r"proxy detected vanished client connection",
    r"failed to load local private key \(key_file or key\) at",  # harmless spiceproxy noise on some setups
]


@dataclass
class LogConfig:
    enabled: bool = True
    max_lines_per_node: int = 2000
    include: list[str] = field(default_factory=lambda: list(DEFAULT_LOG_INCLUDE))
    critical: list[str] = field(default_factory=lambda: list(DEFAULT_LOG_CRITICAL))
    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_LOG_IGNORE))
    # Recognised issues (failed logins, disk I/O errors, OOM kills) stay one open alert
    # while they continue, and clear after this long without a new occurrence.
    quiet_minutes: int = 60
    # Failed logins only alert once this many attempts have been seen in that window,
    # so a mistyped password doesn't.
    failed_login_threshold: int = 5


@dataclass
class LookupConfig:
    """Web lookup of log errors so the model can suggest root causes with sources."""

    enabled: bool = True
    # ddgs (DuckDuckGo, no key), searxng (self-hosted) or brave (API key).
    provider: str = "ddgs"
    searxng_url: str = ""
    brave_api_key: str = ""
    query_prefix: str = "proxmox"
    results_per_query: int = 5
    pages_to_read: int = 2
    max_chars_per_page: int = 2500
    max_lookups_per_check: int = 3
    cache_days: float = 7.0
    timeout: int = 15
    # Sites to rank first when choosing which results to read.
    preferred_domains: list[str] = field(
        default_factory=lambda: [
            "forum.proxmox.com",
            "pve.proxmox.com",
            "bugzilla.proxmox.com",
            "serverfault.com",
            "unix.stackexchange.com",
            "askubuntu.com",
            "superuser.com",
            "github.com",
            "reddit.com",
        ]
    )
    # Extra regexes to strip from log text before it is sent to a search engine.
    redact: list[str] = field(default_factory=list)


@dataclass
class Config:
    proxmox: ProxmoxConfig
    ollama: OllamaConfig
    discord: DiscordConfig
    thresholds: Thresholds = field(default_factory=Thresholds)
    logs: LogConfig = field(default_factory=LogConfig)
    lookup: LookupConfig = field(default_factory=LookupConfig)
    poll_interval_seconds: int = 300
    renotify_hours: float = 6.0
    initial_lookback_minutes: int = 60
    # Listing updates needs Sys.Modify, which is not read-only, so this is off by default.
    check_updates: bool = False
    send_resolved: bool = True
    ignore_storage: list[str] = field(default_factory=list)
    # Skip storage warnings for backup targets (found from backup jobs and storage content).
    # A target that also holds VM/CT disks still alerts at storage_crit_pct.
    ignore_backup_targets: bool = True
    ignore_guests: list[int] = field(default_factory=list)
    state_file: str = "canary-state.json"


SECTIONS = {
    "proxmox": ProxmoxConfig,
    "ollama": OllamaConfig,
    "discord": DiscordConfig,
    "thresholds": Thresholds,
    "logs": LogConfig,
    "lookup": LookupConfig,
}

# Secrets and endpoints can come from the environment instead of the file.
ENV_OVERRIDES = {
    "CANARY_PROXMOX_TOKEN_VALUE": ("proxmox", "token_value"),
    "CANARY_DISCORD_TOKEN": ("discord", "token"),
    "CANARY_DISCORD_CHANNEL_ID": ("discord", "channel_id"),
    "CANARY_OLLAMA_URL": ("ollama", "url"),
    "CANARY_OLLAMA_MODEL": ("ollama", "model"),
    "CANARY_BRAVE_API_KEY": ("lookup", "brave_api_key"),
}

PLACEHOLDER = "CHANGE_ME"


def _build(cls, data: Any, section: str):
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"'{section}' must be a mapping")
    known = {f.name for f in fields(cls)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ConfigError(f"unknown key(s) in '{section}': {', '.join(unknown)}")
    missing = [
        f.name for f in fields(cls)
        if f.name not in data and f.default is MISSING and f.default_factory is MISSING
    ]
    if missing:
        raise ConfigError(", ".join(f"'{section}.{m}' must be set" for m in missing))
    try:
        return cls(**data)
    except TypeError as e:
        raise ConfigError(f"'{section}': {e}") from e


def _require(value: Any, name: str) -> None:
    if value in (None, "", 0) or (isinstance(value, str) and PLACEHOLDER in value):
        raise ConfigError(f"'{name}' must be set")


def _check_regexes(patterns: list[str], name: str) -> None:
    for p in patterns:
        try:
            re.compile(p)
        except re.error as e:
            raise ConfigError(f"invalid regex in '{name}': {p!r} ({e})") from e


def load_config(path: str | os.PathLike, require_discord: bool = True) -> Config:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        raise ConfigError(f"cannot parse {p}: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError("top level of the config must be a mapping")

    for env, (section, key) in ENV_OVERRIDES.items():
        if os.environ.get(env):
            if not isinstance(raw.get(section), dict):
                raw[section] = {}
            raw[section][key] = os.environ[env]

    if not require_discord and not raw.get("discord"):
        raw["discord"] = {"token": "", "channel_id": 0}

    built = {name: _build(cls, raw.get(name), name) for name, cls in SECTIONS.items()}
    top = {k: v for k, v in raw.items() if k not in SECTIONS}
    unknown = sorted(set(top) - {f.name for f in fields(Config)})
    if unknown:
        raise ConfigError(f"unknown top-level key(s): {', '.join(unknown)}")
    cfg = Config(**built, **top)

    try:
        cfg.discord.channel_id = int(cfg.discord.channel_id or 0)
        cfg.proxmox.port = int(cfg.proxmox.port)
    except (TypeError, ValueError) as e:
        raise ConfigError(f"numeric setting is not a number: {e}") from e
    cfg.ignore_guests = [int(v) for v in cfg.ignore_guests]

    for name in ("host", "user", "token_name", "token_value"):
        _require(getattr(cfg.proxmox, name), f"proxmox.{name}")
    _require(cfg.ollama.url, "ollama.url")
    _require(cfg.ollama.model, "ollama.model")
    if require_discord:
        _require(cfg.discord.token, "discord.token")
        _require(cfg.discord.channel_id, "discord.channel_id")

    lk = cfg.lookup
    if lk.provider not in ("ddgs", "searxng", "brave"):
        raise ConfigError("lookup.provider must be ddgs, searxng or brave")
    if lk.enabled and lk.provider == "searxng":
        _require(lk.searxng_url, "lookup.searxng_url")
    if lk.enabled and lk.provider == "brave":
        _require(lk.brave_api_key, "lookup.brave_api_key")

    _check_regexes(cfg.logs.include, "logs.include")
    _check_regexes(cfg.logs.critical, "logs.critical")
    _check_regexes(cfg.logs.ignore, "logs.ignore")
    _check_regexes(cfg.lookup.redact, "lookup.redact")
    if cfg.poll_interval_seconds < 30:
        raise ConfigError("poll_interval_seconds must be at least 30")
    return cfg
