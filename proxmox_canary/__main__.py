"""Entry point: `python -m proxmox_canary [--once | --test-alert]`."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import sys
import time

from . import __version__
from .config import Config, ConfigError, load_config
from .collector import CollectorError
from .discord_alerts import OOPS, DiscordAlerter, build_messages, oops_message, recovered_message
from .monitor import Monitor, Report
from .rules import Finding

log = logging.getLogger("proxmox_canary")


def format_report(report: Report) -> str:
    if not report.findings:
        return "✅ All good: no issues found."
    lines = []
    if report.overview:
        lines += [f"Overview: {report.overview}", ""]
    order = {"critical": 0, "warning": 1, "info": 2}
    for f in sorted(report.findings, key=lambda f: order.get(f.severity, 3)):
        lines.append(f"[{f.severity.upper()}] {f.title}")
        lines.append(f"    {f.detail}")
        d = report.diagnoses.get(f.key)
        if d:
            if d.get("root_cause"):
                lines.append(f"    cause ({d.get('confidence') or '?'}): {d['root_cause']}")
            if d.get("fix"):
                lines.append(f"    fix: {d['fix']}")
            for s in d.get("sources", []):
                lines.append(f"    source: {s['title']} <{s['url']}>")
        for c in f.context[:5]:
            lines.append(f"    | {c[:160]}")
        lines.append("")
    return "\n".join(lines).rstrip()


async def run_once(cfg: Config) -> int:
    cfg.thresholds.sustained_samples = 1  # a single sample is all we get
    monitor = Monitor(cfg, persist=False)
    try:
        await monitor.diagnoser.check_model()
        report = await monitor.check(explain_all=True)
    except Exception as e:
        _log_failure("Check failed", e)
        print(OOPS)
        return 1
    print(format_report(report))
    return 0


async def send_test_alert(cfg: Config) -> int:
    try:
        return await _send_test_alert(cfg)
    except Exception as e:
        _log_failure("Could not send the test alert", e)
        print(OOPS)
        return 1


async def _send_test_alert(cfg: Config) -> int:
    alerter = DiscordAlerter(cfg.discord)
    await alerter.verify()
    sample = Finding(
        "test", "warning", "Test alert from proxmox-canary",
        "If you can read this, the canary can reach this channel. No action needed.",
        context=["this is what log evidence will look like"],
    )
    report = Report([sample], [sample], [], [], True, time.time(),
                    overview="Setup check: Discord delivery works.",
                    diagnoses={"test": {"root_cause": "You asked for a test alert.", "fix": "Nothing to fix.",
                                        "confidence": "high", "sources": []}})
    await alerter.send(build_messages(report, {}, ""))
    print("Test alert sent.")
    return 0


async def run_service(cfg: Config) -> int:
    # Handle stop signals first, so `docker stop` during startup exits cleanly too.
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    monitor = Monitor(cfg)
    alerter = DiscordAlerter(cfg.discord)
    log.info("proxmox-canary %s watching %s every %ss", __version__, cfg.proxmox.host, cfg.poll_interval_seconds)

    async def startup() -> None:
        try:
            await monitor.diagnoser.check_model()
            await alerter.verify()
        except Exception as e:
            _log_failure("Setup check failed (will keep trying)", e)

    delivering = {"now": False}

    async def cycle() -> None:
        async with monitor.lock:
            report = await monitor.check()
            delivering["now"] = True
            try:
                if monitor.state.broken_since is not None:
                    await alerter.send([recovered_message()])
                    log.info("Recovered after failing since %s", time.ctime(monitor.state.broken_since))
                    monitor.state.broken_since = None  # saved by commit() below
                if report.has_news:
                    messages = build_messages(report, monitor.state.active, cfg.discord.mention_on_critical)
                    await alerter.send(messages)
                    log.info("Sent %d new, %d reminder(s), %d resolved",
                             len(report.new), len(report.repeat), len(report.resolved))
                else:
                    log.info("Check done: nothing new (%d active)", len(monitor.state.active))
                # Only reached if Discord accepted the alerts; otherwise they are retried next cycle.
                monitor.commit(report)
            finally:
                delivering["now"] = False

    # Startup and each check can take minutes (Ollama timeouts), longer than `docker stop`
    # waits before killing, so both are cancelled as soon as a stop signal arrives —
    # except while alerts are being delivered, which is given a few seconds to finish so
    # alerts already posted are recorded and not repeated after a restart.
    async def report_failure(e: Exception) -> None:
        """Full details to the log; Discord gets one friendly notice per failure streak."""
        _log_failure("Check failed; retrying next cycle", e)
        if monitor.state.broken_since is not None:
            return
        try:
            await alerter.send([oops_message()])
        except Exception as send_error:
            _log_failure("Could not post the failure notice to Discord", send_error)
            return
        monitor.state.broken_since = time.time()
        monitor.state.save()

    await _unless_stopped(startup(), stop, monitor)
    while not stop.is_set():
        started = time.monotonic()
        try:
            await _unless_stopped(cycle(), stop, monitor, lambda: delivering["now"])
        except Exception as e:
            if not stop.is_set():
                with contextlib.suppress(Exception):
                    await _unless_stopped(report_failure(e), stop, monitor, lambda: True)
        delay = max(5.0, cfg.poll_interval_seconds - (time.monotonic() - started))
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=delay)
    log.info("Stopping")
    return 0


def _log_failure(what: str, e: BaseException) -> None:
    # Expected outages (API unreachable) get one line; anything else gets a traceback.
    if isinstance(e, CollectorError):
        log.error("%s: %s", what, e)
    else:
        log.error("%s: %s", what, e, exc_info=e)


DELIVERY_GRACE_S = 7.0  # `docker stop` waits 10 s before SIGKILL


async def _unless_stopped(coro, stop: asyncio.Event, monitor: Monitor,
                          delivering=lambda: False, grace: float = DELIVERY_GRACE_S) -> None:
    """Run `coro`, cancelling it (and any Proxmox calls in flight) if `stop` is set first."""
    task = asyncio.ensure_future(coro)
    waiter = asyncio.ensure_future(stop.wait())
    try:
        await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        waiter.cancel()
    if not task.done() and delivering():
        log.info("Stop requested; finishing alert delivery first (up to %.0fs)", grace)
        await asyncio.wait({task}, timeout=grace)
    if task.done():
        task.result()  # re-raise errors from the work itself
        return
    monitor.collector.cancel()
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    log.info("Interrupted by stop signal; unsent alerts will go out on the next start")


def main() -> int:
    ap = argparse.ArgumentParser(prog="proxmox-canary", description="Read-only Proxmox monitoring with Ollama diagnosis and Discord alerts.")
    ap.add_argument("-c", "--config", default=os.environ.get("CANARY_CONFIG", "config.yaml"))
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="run one check, print the result and exit (no Discord, no state saved)")
    mode.add_argument("--test-alert", action="store_true", help="send a sample alert to Discord and exit")
    ap.add_argument("--log-level", default=os.environ.get("CANARY_LOG_LEVEL", "INFO"))
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    for noisy in ("httpx", "httpcore", "websockets", "primp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    try:
        cfg = load_config(args.config, require_discord=not args.once)
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    if args.once:
        return asyncio.run(run_once(cfg))
    if args.test_alert:
        return asyncio.run(send_test_alert(cfg))
    return asyncio.run(run_service(cfg))


if __name__ == "__main__":
    sys.exit(main())
