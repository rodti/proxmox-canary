"""Recognise log lines that are symptoms of one underlying issue.

A brute-force attempt can log thousands of lines from hundreds of addresses against
dozens of usernames; a failing disk logs an error per sector. Each of these is one
issue, so it should be one alert that stays open while it continues, not one alert
per address, username or sector.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

CRITICAL, WARNING = "critical", "warning"


@dataclass(frozen=True)
class Pattern:
    regex: re.Pattern
    # Several lines describe one event (an SSH failure logs ~3), so only some are counted:
    # attempts = max(tier-1 lines, tier-2 lines), falling back to tier-3 lines.
    tier: int = 1


@dataclass(frozen=True)
class Kind:
    id: str
    severity: str
    patterns: tuple[Pattern, ...]
    per_node: bool  # False: one issue across the whole cluster
    lookup: bool  # worth searching the web for a sample line


@dataclass
class Match:
    kind: Kind
    tier: int
    src: str = ""
    user: str = ""
    dev: str = ""
    proc: str = ""
    via: str = ""
    attrs: dict = field(default_factory=dict)


def _p(regex: str, tier: int = 1) -> Pattern:
    return Pattern(re.compile(regex, re.IGNORECASE), tier)


_ADDR = r"(?P<src>(?:::ffff:)?[0-9a-f]*[:.][0-9a-f:.]+)"

AUTH = Kind("auth", WARNING, (
    # sshd / sshd-session
    _p(r"\bFailed (?:password|publickey|none|keyboard-interactive(?:/pam)?) for (?:invalid user )?(?P<user>\S*) from " + _ADDR),
    _p(r"\bInvalid user (?P<user>\S*) from " + _ADDR, tier=2),
    _p(r"\b(?:Connection closed|Disconnected) (?:by|from) (?:invalid|authenticating) user (?P<user>\S*) " + _ADDR, tier=2),
    _p(r"\bmaximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S*) from " + _ADDR, tier=2),
    # PAM (ssh, sudo, su, login): user and rhost are read separately below
    _p(r"\bpam_unix\([^)]*:auth\): authentication failure", tier=3),
    _p(r"\bunix_chkpwd\b.*password check failed for user \(?(?P<user>[^)\s]+)", tier=3),
    _p(r"\bFAILED SU \(to (?P<user>[^)]+)\)", tier=1),
    # Proxmox web UI / API logins: "pvedaemon[..]: authentication failure; rhost=.. user=root@pam msg=.."
    _p(r"\b(?:pvedaemon|pveproxy)\b.*?authentication failure", tier=1),
), per_node=False, lookup=False)

DISK_IO = Kind("disk-io", CRITICAL, (
    _p(r"\b(?:I/O|critical medium|critical target|critical nexus) error,? dev (?P<dev>[a-z]+[0-9a-z]*)"),
    # Filesystem-level echo of the same failure: counted only if no block-level lines.
    _p(r"\bBuffer I/O error on (?:dev(?:ice)? )?(?P<dev>[a-z]+[0-9a-z]*)", tier=2),
), per_node=True, lookup=True)

OOM = Kind("oom", CRITICAL, (
    _p(r"\bOut of memory: Killed process \d+ \((?P<proc>[^)]+)\)"),
    _p(r"\boom-kill:.*?\btask=(?P<proc>[^,\s]+)", tier=2),
), per_node=True, lookup=False)

KINDS = (AUTH, DISK_IO, OOM)

_RHOST = re.compile(r"\brhost=(\S*)")
_PAM_USER = re.compile(r"(?<!r)\buser=(\S+)")
_IDENT = re.compile(r"^(?:\S+\s+){0,4}?([A-Za-z][\w.()/-]*?)(?:\[\d+\])?:\s")
_VIA = (("sshd", "SSH"), ("pvedaemon", "Proxmox web UI/API"), ("pveproxy", "Proxmox web UI/API"),
        ("sudo", "sudo"), ("su", "su"), ("login", "console login"))
_PAM_SERVICE = re.compile(r"pam_unix\(([^:)]+):auth\)")


def _via(line: str) -> str:
    svc = _PAM_SERVICE.search(line)
    name = svc.group(1) if svc else ""
    if not name:
        m = _IDENT.search(line)
        name = m.group(1) if m else ""
    for prefix, label in _VIA:
        if name == prefix or name.startswith(prefix + "-") or (prefix == "sshd" and name.startswith("sshd")):
            return label
    return name


def normalize_source(src: str) -> str:
    src = src.strip("[](),;")
    if src.lower().startswith("::ffff:"):
        src = src[7:]
    return src


_LAN = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",  # RFC 1918, CGNAT/Tailscale
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
)]


def is_lan(src: str) -> bool:
    """Local-network address? (Python's is_private also counts documentation ranges.)"""
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return False
    return any(ip in net for net in _LAN if net.version == ip.version)


def normalize_dev(dev: str) -> str:
    """sdb1 -> sdb, nvme0n1p2 -> nvme0n1, dm-3 stays."""
    if dev.startswith("nvme"):
        return re.sub(r"p\d+$", "", dev)
    if re.fullmatch(r"(?:sd|vd|hd|xvd)[a-z]+\d+", dev):
        return re.sub(r"\d+$", "", dev)
    return dev


def classify(line: str) -> Match | None:
    for kind in KINDS:
        for pat in kind.patterns:
            m = pat.regex.search(line)
            if not m:
                continue
            g = m.groupdict()
            match = Match(kind, pat.tier)
            if kind is AUTH:
                src = g.get("src") or ""
                user = g.get("user") or ""
                if not src:
                    r = _RHOST.search(line)
                    src = r.group(1) if r else ""
                if not user:
                    u = _PAM_USER.search(line)
                    user = u.group(1) if u else ""
                match.src = normalize_source(src) if src else ""
                match.user = user.strip("()<>;,") if user else ""
                match.via = "" if "unix_chkpwd" in line else _via(line)  # PAM helper, not a service
            elif kind is DISK_IO:
                match.dev = normalize_dev(g["dev"])
            elif kind is OOM:
                match.proc = g.get("proc") or "?"
            return match
    return None


_ACCEPTED = re.compile(
    r"\bAccepted (?P<method>password|keyboard-interactive(?:/pam)?|publickey|gssapi-with-mic|hostbased) "
    r"for (?P<user>\S+) from " + _ADDR,
    re.IGNORECASE,
)
# Credentials a brute force can guess. A key login after failures is the normal case of
# a client trying several keys, so it never raises the alarm on its own.
GUESSABLE = ("password", "keyboard-interactive")


@dataclass
class Login:
    src: str
    user: str
    method: str


def successful_login(line: str) -> Login | None:
    """A successful SSH login, e.g. 'Accepted password for root from 203.0.113.5 port 22 ssh2'."""
    m = _ACCEPTED.search(line)
    if not m:
        return None
    return Login(normalize_source(m.group("src")), m.group("user"), m.group("method").lower())


def issue_key(match: Match, node: str) -> str:
    if match.kind is DISK_IO:
        return f"{match.kind.id}:{node}:{match.dev}"
    return f"{match.kind.id}:{node}" if match.kind.per_node else match.kind.id
