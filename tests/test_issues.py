"""Recognised log issues: many lines, addresses and usernames -> one ongoing alert."""
import json
import time

import pytest

from proxmox_canary.collector import Collector, Snapshot
from proxmox_canary.issues import classify, is_lan, issue_key, normalize_dev
from proxmox_canary.rules import evaluate
from proxmox_canary.state import State

T = "Oct 13 22:02:23"


def ssh_attempt(node, ip, user, port=40000):
    """The lines one failed SSH password attempt logs on Debian/Proxmox."""
    invalid = user != "root"
    lines = []
    if invalid:
        lines.append(f"{T} {node} sshd-session[812]: Invalid user {user} from {ip} port {port}")
    lines.append(f"{T} {node} sshd-session[812]: pam_unix(sshd:auth): authentication failure; logname= uid=0 "
                 f"euid=0 tty=ssh ruser= rhost={ip}" + ("" if invalid else "  user=root"))
    if not invalid:
        lines.append(f"{T} {node} unix_chkpwd[813]: password check failed for user (root)")
    lines.append(f"{T} {node} sshd-session[812]: Failed password for {'invalid user ' if invalid else ''}{user} "
                 f"from {ip} port {port} ssh2")
    return lines


def brute_force(node, n, start=0):
    ips = [f"203.0.113.{i}" for i in range(1, 20)] + ["2001:db8::7", "::ffff:198.51.100.9"]
    users = ["root", "admin", "oracle", "ubuntu", "git", "test"]
    out = []
    for i in range(start, start + n):
        out += ssh_attempt(node, ips[i % len(ips)], users[i % len(users)], 30000 + i)
    return out


def snap(lines_by_node, at, since=None):
    return Snapshot(taken_at=at, since=since if since is not None else at - 300, log_errors=lines_by_node)


@pytest.fixture
def cfg(make_cfg):
    return make_cfg()


# ------------------------------------------------------------------ classify

@pytest.mark.parametrize("line,kind,src,user,via", [
    (f"{T} n sshd-session[1]: Failed password for root from 203.0.113.5 port 22 ssh2", "auth", "203.0.113.5", "root", "SSH"),
    (f"{T} n sshd[1]: Failed password for invalid user oracle from 2001:db8::1 port 22 ssh2", "auth", "2001:db8::1", "oracle", "SSH"),
    (f"{T} n sshd[1]: Failed publickey for git from 203.0.113.5 port 22 ssh2: RSA SHA256:abc", "auth", "203.0.113.5", "git", "SSH"),
    (f"{T} n sshd-session[1]: Invalid user test from 203.0.113.6 port 5", "auth", "203.0.113.6", "test", "SSH"),
    (f"{T} n sshd[1]: Connection closed by authenticating user root 203.0.113.7 port 5 [preauth]", "auth", "203.0.113.7", "root", "SSH"),
    (f"{T} n sshd[1]: error: maximum authentication attempts exceeded for root from 203.0.113.8 port 5 ssh2 [preauth]", "auth", "203.0.113.8", "root", "SSH"),
    (f"{T} n sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9  user=root", "auth", "203.0.113.9", "root", "SSH"),
    (f"{T} n sudo[1]: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice", "auth", "", "alice", "sudo"),
    (f"{T} n unix_chkpwd[1]: password check failed for user (root)", "auth", "", "root", ""),
    (f"{T} n pvedaemon[4410]: authentication failure; rhost=::ffff:192.168.1.20 user=root@pam msg=Authentication failure",
     "auth", "192.168.1.20", "root@pam", "Proxmox web UI/API"),
    (f"{T} n su[1]: FAILED SU (to root) alice on pts/0", "auth", "", "root", "su"),
])
def test_classify_logins(line, kind, src, user, via):
    m = classify(line)
    assert m and m.kind.id == kind and (m.src, m.user, m.via) == (src, user, via)


@pytest.mark.parametrize("line,kind,detail", [
    (f"{T} n kernel: blk_update_request: I/O error, dev sdb, sector 123 op 0x0:(READ)", "disk-io", "sdb"),
    (f"{T} n kernel: I/O error, dev nvme0n1, sector 9 op 0x1:(WRITE) flags 0x0", "disk-io", "nvme0n1"),
    (f"{T} n kernel: Buffer I/O error on dev sdc1, logical block 7, async page read", "disk-io", "sdc"),
    (f"{T} n kernel: critical medium error, dev sda, sector 77 op 0x0:(READ)", "disk-io", "sda"),
    (f"{T} n kernel: Out of memory: Killed process 4242 (kvm) total-vm:9000kB", "oom", "kvm"),
    (f"{T} n kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),task=java,pid=99,uid=0", "oom", "java"),
])
def test_classify_hardware(line, kind, detail):
    m = classify(line)
    assert m and m.kind.id == kind and detail in (m.dev, m.proc)


@pytest.mark.parametrize("line", [
    f"{T} n sshd[1]: Accepted publickey for root from 192.168.1.20 port 5 ssh2",
    f"{T} n pvestatd[1]: storage 'nas' is not online",
    f"{T} n kernel: EXT4-fs error (device dm-1): ext4_find_entry",
])
def test_classify_other_lines(line):
    assert classify(line) is None


def test_helpers():
    assert normalize_dev("sdb1") == "sdb" and normalize_dev("nvme0n1p3") == "nvme0n1" and normalize_dev("dm-3") == "dm-3"
    assert is_lan("192.168.1.2") and is_lan("10.1.2.3") and is_lan("100.101.102.103") and is_lan("fd00::1")
    assert not is_lan("203.0.113.5") and not is_lan("2001:db8::1") and not is_lan("8.8.8.8") and not is_lan("")
    m = classify(f"{T} n kernel: I/O error, dev sdb, sector 1")
    assert issue_key(m, "pve1") == "disk-io:pve1:sdb"
    assert issue_key(classify(f"{T} n sshd[1]: Invalid user x from 203.0.113.1 port 1"), "pve1") == "auth"


# ------------------------------------------------------------ one ongoing alert

def run(st, cfg, lines_by_node, at, notify=True):
    f = evaluate(snap(lines_by_node, at), cfg, st)
    new, repeat, resolved = st.diff(f, at, cfg.renotify_hours * 3600, True)
    if notify:
        st.commit(f, {x.key for x in new + repeat}, at, at, True)
    return f, new, repeat, resolved


def test_brute_force_is_one_alert_across_checks(cfg):
    st, t0 = State(None), time.time()
    f, new, _, _ = run(st, cfg, {"pve1": brute_force("pve1", 30), "pve2": brute_force("pve2", 12, 30)}, t0)
    auth = [x for x in f if x.key == "auth"]
    assert len(auth) == 1 and [x.key for x in new] == ["auth"]
    a = auth[0]
    assert a.kind == "condition" and a.severity == "warning"
    assert a.title == "Repeated failed logins on pve1 and pve2"
    # Counts attempts, not log lines (each attempt here logs 3 lines).
    assert a.detail.startswith("About 42 failed login attempt(s) in the last 5 min via SSH, from 21 address(es) against 6 username(s).")
    assert "198.51.100.9 (" in a.detail and "::ffff:" not in a.detail
    assert "Usernames tried: " in a.detail and a.lookup_messages == []
    assert len(a.context) <= 5

    # Next checks: new addresses and usernames keep coming, but nothing new is posted.
    for i in range(1, 4):
        f, new, repeat, _ = run(st, cfg, {"pve1": brute_force("pve1", 20, 100 * i)}, t0 + 300 * i)
        assert new == [] and repeat == []
    a = next(x for x in f if x.key == "auth")
    assert a.detail.startswith("About 102 failed login attempt(s) in the last 20 min")

    # Still going after renotify_hours: one reminder with the up-to-date numbers.
    later = t0 + cfg.renotify_hours * 3600 + 60
    f, new, repeat, _ = run(st, cfg, {"pve1": brute_force("pve1", 5)}, later)
    assert new == [] and [x.key for x in repeat] == ["auth"]

    # Quiet for logs.quiet_minutes: the issue clears and "resolved" goes out once.
    f, new, repeat, resolved = run(st, cfg, {}, later + cfg.logs.quiet_minutes * 60 + 60)
    assert [r["key"] for r in resolved] == ["auth"] and "auth" not in st.log_issues
    # A new wave later is a new alert.
    f, new, *_ = run(st, cfg, {"pve1": brute_force("pve1", 10)}, later + 7200)
    assert [x.key for x in new] == ["auth"]


def test_failed_login_threshold_accumulates(cfg):
    st, t0 = State(None), time.time()
    cfg.logs.failed_login_threshold = 5
    f, *_ = run(st, cfg, {"pve1": ssh_attempt("pve1", "192.168.1.20", "root") * 2}, t0)  # a couple of typos
    assert f == []
    f, new, *_ = run(st, cfg, {"pve1": brute_force("pve1", 3)}, t0 + 300)
    assert [x.key for x in new] == ["auth"] and "About 5 failed" in new[0].detail


def test_lan_only_sources_are_called_out(cfg):
    st = State(None)
    lines = []
    for i in range(6):
        lines += ssh_attempt("pve1", f"192.168.1.{20 + i % 2}", "root")
    f, *_ = run(st, cfg, {"pve1": lines}, time.time())
    assert "All attempts came from your local network." in f[0].detail and "(LAN, 3)" in f[0].detail


def test_undelivered_check_does_not_double_count(cfg):
    st, t0 = State(None), time.time()
    lines = {"pve1": brute_force("pve1", 8)}
    run(st, cfg, lines, t0, notify=False)  # Discord down: nothing committed
    f, *_ = run(st, cfg, lines, t0 + 300)  # the same lines are read again
    assert "About 8 failed" in next(x for x in f if x.key == "auth").detail


def test_disk_and_oom_issues(cfg):
    st, t0 = State(None), time.time()
    io = [f"{T} pve1 kernel: blk_update_request: I/O error, dev sdb, sector {i} op 0x0:(READ)" for i in range(40)]
    io += [f"{T} pve1 kernel: Buffer I/O error on dev sdb1, logical block {i}" for i in range(3)]
    io += [f"{T} pve1 kernel: I/O error, dev sdc, sector 5 op 0x0:(READ)"]
    oom = [f"{T} pve1 kernel: Out of memory: Killed process 1{i} (kvm) total-vm:1kB" for i in range(2)]
    oom += [f"{T} pve1 kernel: oom-kill:constraint=CONSTRAINT_NONE,task=kvm,pid=10,uid=0"]
    f, new, *_ = run(st, cfg, {"pve1": io + oom}, t0)
    by_key = {x.key: x for x in new}
    assert set(by_key) == {"disk-io:pve1:sdb", "disk-io:pve1:sdc", "oom:pve1"}
    assert by_key["disk-io:pve1:sdb"].severity == "critical"
    assert by_key["disk-io:pve1:sdb"].detail.startswith("40 I/O error(s)")  # Buffer lines aren't extra errors
    assert by_key["disk-io:pve1:sdb"].lookup_messages
    assert "killed 2 process(es)" in by_key["oom:pve1"].detail and "kvm (2)" in by_key["oom:pve1"].detail
    f, new, *_ = run(st, cfg, {"pve1": io}, t0 + 300)
    assert new == []


def test_log_issues_persist(tmp_path, cfg):
    path = tmp_path / "state.json"
    st, t0 = State(path), time.time()
    run(st, cfg, {"pve1": brute_force("pve1", 6)}, t0)
    saved = json.loads(path.read_text())["log_issues"]
    assert saved["auth"]["count"] == 6
    st2 = State.load(path)
    f, new, *_ = run(st2, cfg, {"pve1": brute_force("pve1", 1)}, t0 + 300)
    assert new == [] and "About 7 failed" in next(x for x in f if x.key == "auth").detail


def test_source_list_is_bounded(cfg):
    st = State(None)
    lines = [f"{T} pve1 sshd[1]: Failed password for root from 10.{i // 250}.{i % 250}.1 port 1 ssh2" for i in range(700)]
    f, *_ = run(st, cfg, {"pve1": lines}, time.time())
    a = next(x for x in f if x.key == "auth")
    assert "from 500+ address(es)" in a.detail and "+ more" in a.detail
    assert len(st.log_issues["auth"]["src"]) == 500


# ---------------------------------------------------------------- collector

class _Api:
    def __init__(self, routes, path=()):
        self.routes, self.path = routes, path

    def __getattr__(self, name):
        return _Api(self.routes, self.path + (name,))

    def __call__(self, arg):
        return _Api(self.routes, self.path + (str(arg),))

    def get(self, **kw):
        return self.routes.get("/".join(self.path), [])


def test_collector_keeps_recognised_lines_beyond_include_and_cap(make_cfg):
    cfg = make_cfg()
    cfg.logs.max_lines_per_node = 2
    journal = (brute_force("pve1", 50)
               + [f"{T} pve1 cron[1]: job {i} failed" for i in range(5)]
               + [f"{T} pve1 sshd[1]: Invalid user noisy from 203.0.113.1 port 1"])
    cfg.logs.ignore.append("noisy")
    routes = {"cluster/resources": [{"type": "node", "node": "pve1", "status": "online"}],
              "nodes/pve1/journal": journal}
    lines = Collector(cfg, api=_Api(routes)).collect(time.time() - 60).log_errors["pve1"]
    assert sum("Invalid user" in line for line in lines) == len([x for x in journal if "Invalid user" in x]) - 1
    assert [line for line in lines if "cron" in line] == [f"{T} pve1 cron[1]: job 3 failed", f"{T} pve1 cron[1]: job 4 failed"]
    assert not any("noisy" in line for line in lines)


# --------------------------------------------------------- whole service

def test_service_posts_one_alert_for_a_brute_force(pve, discord, make_cfg):
    from test_end_to_end import embeds, run_service_until
    pve.scenario["journal"]["pve1"] = brute_force("pve1", 40)
    cfg = make_cfg(pve=pve, discord=discord)
    cfg.poll_interval_seconds = 1
    calls = lambda: len([r for r in pve.server.requests if "cluster/resources" in r[1]])  # noqa: E731
    run_service_until(cfg, lambda: calls() >= 4)
    titles = [e["title"] for e in embeds(discord)]
    assert titles.count("🟡 Repeated failed logins on pve1") == 1, titles


# ------------------------------------------------- login after failed attempts

def accepted(node, ip, user, method="password"):
    return f"{T} {node} sshd-session[900]: Accepted {method} for {user} from {ip} port 51000 ssh2"


def test_password_login_after_brute_force_is_danger(cfg):
    st, t0 = State(None), time.time()
    lines = []
    for i in range(6):
        lines += ssh_attempt("pve1", "203.0.113.66", "root", 40000 + i)
    lines.append(accepted("pve1", "203.0.113.66", "root"))
    f, new, *_ = run(st, cfg, {"pve1": lines}, t0)
    b = next(x for x in new if x.key.startswith("breach:"))
    assert b.key == "breach:pve1:203.0.113.66:root" and b.severity == "critical" and b.kind == "event"
    assert b.title == "Successful login after failed attempts: root on pve1"
    assert b.detail.startswith("203.0.113.66 made about 6 failed login attempt(s), then logged in to pve1 as root with a password over SSH.")
    assert b.context[-1] == "sshd-session: Accepted password for root from 203.0.113.66 port 51000 ssh2"
    assert len(b.context) == 4
    # The failed logins are still their own (single) alert.
    assert {x.key for x in new} == {"auth", b.key}
    # It logs in again: no second alert for the same address, account and node.
    f, new, *_ = run(st, cfg, {"pve1": [accepted("pve1", "203.0.113.66", "root")]}, t0 + 300)
    assert not any(x.key.startswith("breach:") for x in new)


def test_failures_from_earlier_checks_count(cfg):
    st, t0 = State(None), time.time()
    run(st, cfg, {"pve1": brute_force("pve1", 5 * 21)}, t0)  # every address fails 5 times
    f, new, *_ = run(st, cfg, {"pve2": [accepted("pve2", "::ffff:198.51.100.9", "admin", "keyboard-interactive/pam")]}, t0 + 300)
    b = [x for x in new if x.key.startswith("breach:")]
    assert [x.key for x in b] == ["breach:pve2:198.51.100.9:admin"]
    assert "about 5 failed" in b[0].detail


@pytest.mark.parametrize("case", ["key_login", "below_threshold", "success_first", "other_address", "issue_expired"])
def test_no_false_danger(cfg, case):
    st, t0 = State(None), time.time()
    fails = []
    for i in range(6):
        fails += ssh_attempt("pve1", "192.168.1.20", "root", 40000 + i)
    if case == "key_login":  # a client trying several keys, or a typo then a key
        lines = fails + [accepted("pve1", "192.168.1.20", "root", "publickey")]
    elif case == "below_threshold":  # a couple of typos, then the right password
        lines = fails[:6] + [accepted("pve1", "192.168.1.20", "root")]
    elif case == "success_first":  # logged in, then later typos in the same check
        lines = [accepted("pve1", "192.168.1.20", "root")] + fails
    elif case == "other_address":
        lines = fails + [accepted("pve1", "192.168.1.99", "root")]
    else:  # failures long ago: the auth issue already cleared
        run(st, cfg, {"pve1": fails}, t0)
        run(st, cfg, {}, t0 + cfg.logs.quiet_minutes * 60 + 600)
        lines = [accepted("pve1", "192.168.1.20", "root")]
        t0 += cfg.logs.quiet_minutes * 60 + 900
    f, *_ = run(st, cfg, {"pve1": lines}, t0)
    assert not any(x.key.startswith("breach:") for x in f)


def test_lan_breach_says_so(cfg):
    lines = []
    for i in range(5):
        lines += ssh_attempt("pve1", "192.168.1.20", "root", 40000 + i)
    f, *_ = run(State(None), cfg, {"pve1": lines + [accepted("pve1", "192.168.1.20", "root")]}, time.time())
    assert next(x for x in f if x.key.startswith("breach:")).detail.startswith("192.168.1.20 (on your LAN) made about 5")


def test_collector_keeps_successful_logins(make_cfg):
    routes = {"cluster/resources": [{"type": "node", "node": "pve1", "status": "online"}],
              "nodes/pve1/journal": [accepted("pve1", "203.0.113.5", "root"), f"{T} pve1 cron[1]: job ran"]}
    lines = Collector(make_cfg(), api=_Api(routes)).collect(time.time() - 60).log_errors["pve1"]
    assert lines == [accepted("pve1", "203.0.113.5", "root")]


def test_service_breach_is_danger_with_ping(pve, discord, make_cfg):
    from test_end_to_end import run_service_until
    lines = []
    for i in range(8):
        lines += ssh_attempt("pve1", "203.0.113.66", "root", 40000 + i)
    pve.scenario["journal"]["pve1"] = lines + [accepted("pve1", "203.0.113.66", "root")]
    cfg = make_cfg(pve=pve, discord=discord)
    cfg.poll_interval_seconds = 1
    calls = lambda: len([r for r in pve.server.requests if "cluster/resources" in r[1]])  # noqa: E731
    run_service_until(cfg, lambda: calls() >= 3)
    titles = [e["title"] for m in discord.messages for e in m.get("embeds", [])]
    assert titles.count("🔴 Successful login after failed attempts: root on pve1") == 1, titles
    assert discord.messages[0]["content"].startswith("<@&555>\n🚨 **Danger!**")
