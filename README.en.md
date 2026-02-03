# Paqet Auto Installer/Runner (Ubuntu 22) — by LR4

This repo provides a **one-file installer** that:

- Downloads and extracts paqet to `/root`
- Copies the **FULL original** YAML templates:
  - `example/server.yaml.example` → `/root/server.yaml`
  - `example/client.yaml.example` → `/root/client.yaml`
- Applies ONLY the required edits (interface, MAC, IPs, ports, secret, IPv6 comments, socks5 disable + forward enable)
- Runs paqet in a **screen** session
- Adds a **cron watchdog** (every 1 minute) to restart paqet if it stops (including “Killed” / process not running)

---

## Quick Start

### 1) Download / clone
Put `install.sh` in `/root` (or clone repo and copy it there).

### 2) Run
```bash
cd /root
chmod +x install.sh
sudo ./install.sh

```

It will ask simple questions:

Mode: 1 Outside Server or 2 Iran Client

Ports / secret key / outside IP (for client)

Screen session name

Logs

Installer log:

```/root/paqet-install.log```

Runtime log (paqet output):

```/root/paqet-runtime.log```

Watchdog log:

```/root/paqet-watchdog.log```

View logs:

``` tail -f /root/paqet-runtime.log
tail -f /root/paqet-watchdog.log```

Screen usage

List screens:

```screen -ls```
Attach:

```screen -r LR4-paqet```

Detach:

```Press: Ctrl + A then D```

Watchdog (Auto restart)

The installer adds a cron line like:

```* * * * * /root/paqet-watchdog.sh ... ```




