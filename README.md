# 🐤 proxmox-canary

A read-only canary for your Proxmox VE cluster. Every few minutes it checks the
API for overloaded nodes and guests, filling or failing storage, unhealthy disks,
failed tasks and errors in the system journal. When something is wrong it looks
the error up on the web, asks a local Ollama model for the likely root cause and
a fix, and posts an alert to Discord.

```
Proxmox API (read-only) ──► rules ──► web lookup ──► Ollama ──► Discord channel
```

Problems are found by plain threshold and trend rules, not by the model. The model
explains what the rules found and cites the pages it used, so it can't invent alerts.

## What it watches

| Check | Alert when |
|---|---|
| Nodes | offline; CPU or RAM high for 3 checks in a row; root filesystem filling |
| VMs and containers | CPU-bound or at their memory limit for 3 checks in a row |
| Storage | over 80% / 90%; projected full within 7 days at the current growth rate; unavailable |
| ZFS pools | any state other than ONLINE |
| Disks | SMART health failing; SSD life remaining ≤ 10% |
| Tasks | backups, migrations, snapshots etc. that failed or finished with warnings |
| Journal | error lines (critical patterns such as I/O errors, OOM kills and call traces raise the severity) |
| Updates | pending package updates (info only, off by default; see below) |

Ongoing conditions alert once, remind every `renotify_hours`, and post a
"✅ All good" message when they clear. Repeated log messages are grouped
and only re-reported after `renotify_hours`.

## Setup

### 1. A read-only Proxmox API token

On any node, as root:

```bash
pveum role add CanaryAudit -privs "Sys.Audit,Sys.Syslog,VM.Audit,Datastore.Audit"
pveum user add canary@pve --comment "proxmox-canary (read-only)"
pveum acl modify / --users canary@pve --roles CanaryAudit
pveum user token add canary@pve monitor --privsep 0
```

Copy the token secret it prints. `Sys.Syslog` is needed to read the journal; the
built-in `PVEAuditor` role does not include it. None of these privileges can change
anything.

The pending-updates check is off by default because Proxmox only lets a token list
updates with `Sys.Modify`, which also allows changing node settings. If you want it
anyway, add `Sys.Modify` to the role and set `check_updates: true`.

### 2. Ollama on the other machine

```bash
ollama pull qwen2.5:7b
# Make Ollama listen on the network, e.g. for systemd:
#   systemctl edit ollama  →  [Service] Environment="OLLAMA_HOST=0.0.0.0"
```

On a Mac, run Ollama natively rather than in Docker so it can use the GPU. Any
7–8B instruct model works; a 14B model gives noticeably better diagnoses if you
have the memory. If Ollama is down, alerts still go out, just without the diagnosis.

### 3. A Discord bot

**Create the bot**

1. Open the [Discord Developer Portal](https://discord.com/developers/applications) and click
   **New Application**. Name it, e.g. "Proxmox Canary". This is the name alerts are posted under.
2. Go to **Bot**:
   - Click **Reset Token** and copy the token straight away. Discord only shows it once;
     if you lose it, reset it again and update your config.
   - Turn off **Public Bot**, so only you can add it to servers.
   - Leave all three **Privileged Gateway Intents** off. The bot only posts alerts and
     listens to nothing.
   - Optionally set an avatar.

**Add it to your server**

3. Go to **OAuth2 → URL Generator**. Tick the **bot** scope, then these permissions:
   **View Channels**, **Send Messages** and **Embed Links**.
4. Open the generated URL, pick your server and click **Authorize**. You need the
   **Manage Server** permission on that server.

**Choose the alerts channel**

5. In Discord, turn on **User Settings → Advanced → Developer Mode**.
6. Right-click the channel the alerts should go to and click **Copy Channel ID**.
7. If the channel is private, the bot can't see it yet. Open the channel's settings →
   **Permissions** → **Add members or roles**, add the bot, and allow **View Channel**,
   **Send Messages** and **Embed Links**.

**Optional: ping someone on critical alerts**

8. To ping a role, go to **Server Settings → Roles**, right-click the role and click
   **Copy Role ID**. In the config, write it as `mention_on_critical: "<@&ROLE_ID>"`.
   To ping just yourself, right-click your name, click **Copy User ID**, and write
   `"<@USER_ID>"`.
   The ping only works if the role has **Allow anyone to @mention this role** turned on,
   or if the bot has the **Mention @everyone, @here, and All Roles** permission.

**Check it works**

9. Put the token and channel ID in `config.yaml` (step 4), then run:

   ```bash
   python -m proxmox_canary --test-alert
   # or, with Docker:
   docker compose run --rm proxmox-canary python -m proxmox_canary --test-alert
   ```

   A sample alert should appear in the channel. If it doesn't, the terminal prints
   "🐤💫 Oops! Something broke." and the log says why. Common causes:
   - **401**: wrong token. Reset it and copy it again.
   - **403 / Missing Access**: the bot can't see the channel. Recheck step 7.
   - **404**: wrong channel ID. Copy the channel ID, not the server ID.

### 4. Configure

```bash
cp config.example.yaml config.yaml   # fill in the CHANGE_ME values
```

## Run

**Docker** (recommended):

```bash
# in config.yaml set: state_file: /data/canary-state.json
docker compose up -d --build
docker compose logs -f
```

**Directly** (Python 3.9 or newer; 3.11+ recommended):

On macOS, the built-in `python3` is 3.9 and uses LibreSSL, which makes urllib3 print a
`NotOpenSSLWarning` at startup. It works, but a newer Python avoids the warning:
`brew install python@3.12`, then create the venv with `python3.12 -m venv .venv`.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m proxmox_canary --once        # one check printed to the terminal, nothing sent
python -m proxmox_canary --test-alert  # posts a sample alert to Discord
python -m proxmox_canary               # run continuously
```

Run `--once` first. It checks the Proxmox token, Ollama and web lookup without
touching Discord, and treats a single sample as "sustained" so you see everything
that is currently over a threshold.

**With a process manager** such as [pyker](https://github.com/mrvi0/pyker) or pm2, point it at
`run.py`. It runs the canary from the project folder, so `config.yaml` and the state
file are found wherever the manager starts it. Use absolute paths:

```bash
cd ~/git/proxmox-canary
pyker start proxmox-canary "$PWD/run.py" --venv "$PWD/.venv" --auto-restart
pyker logs proxmox-canary -f      # follow the log
pyker list                        # status
pyker restart proxmox-canary      # after a git pull or config change
pyker stop proxmox-canary
```

## Web lookups and privacy

For journal errors and failed tasks, the canary searches the error text (up to
`max_lookups_per_check` new searches per check, cached for `cache_days`), reads the
top couple of pages, preferring forum.proxmox.com, the Proxmox wiki and bug tracker,
and the Stack Exchange sites, and gives the excerpts to the model. Only sources the
model actually used are linked in the alert.

Before anything is sent to a search engine it is scrubbed of IP and MAC addresses,
e-mail and `user@realm` strings, UUIDs, long hex and number runs, home paths, and
your node, guest, storage and pool names. Add your own patterns under
`lookup.redact`. To keep searches entirely on your network, point
`provider: searxng` at a self-hosted SearXNG instance, or set `lookup.enabled: false`.

## Tuning

- **Too noisy?** Raise thresholds, add `ignore_guests` / `ignore_storage`, or add
  regexes to `logs.ignore`. Setting `logs.include`, `logs.critical` or
  `logs.ignore` replaces the built-in list for that key.
- **VM memory alerts:** for VMs without the QEMU guest agent or ballooning, Proxmox
  counts the guest's page cache as used, so they can sit near 100%. Install the
  agent or add the VM to `ignore_guests`.
- **Node memory with ZFS:** the ARC counts as used RAM. The alert says so, but
  you may want `node_mem_pct` a little higher.
- **State:** `canary-state.json` holds active alerts, storage trends and the lookup
  cache. Delete it to start fresh.

## When the canary itself breaks

The canary's own errors never appear in Discord. If a check fails (the Proxmox API
can't be reached, a bug, Discord rejecting a message), the full error and traceback go
to the log (`docker compose logs`), and the channel gets one message for the whole
failure streak:

> 🐤💫 Oops! Something broke.

When the next check succeeds it posts "✅ **All good.** Monitoring is working again." This is remembered across restarts, so an outage doesn't repeat the notice.
Alerts that couldn't be delivered aren't marked as sent, so they go out on the next
successful check rather than being lost.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The suite needs no real Proxmox, Ollama, search engine or Discord. It starts local fakes
of each (an HTTPS Proxmox API, the Ollama chat API, a SearXNG/Brave search, and Discord's
REST API and gateway websocket) and runs the real libraries against them. It covers
the rules, alert formatting and Discord limits, outages and retries, restarts with saved
state, and the service stopping promptly on SIGTERM. It takes about a minute.
