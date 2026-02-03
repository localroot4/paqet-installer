# Paqet Auto Installer/Runner (Linux) — by LR4

This repository provides a **single-file installer** that:

- Downloads and extracts Paqet to `/root`
- Copies the **full original** YAML templates:
  - `example/server.yaml.example` → `/root/server.yaml`
  - `example/client.yaml.example` → `/root/client.yaml`
- Applies only the required edits (interface, MAC, IPs, ports, secret, IPv6 comments, SOCKS5 disable + forward enable)
- Runs Paqet in a **screen** session
- Adds a **watchdog** (every 1 minute via systemd or cron) to restart Paqet if it stops

---

## Compatibility

- **OS:** Linux distributions with a supported package manager (`apt`, `dnf`, `yum`, `apk`, `pacman`, `zypper`).
- **CPU:** `amd64`, `arm64`, `armhf` (auto-detected).

> If your distro is not listed, install dependencies manually (curl, wget, screen, iproute2, iputils/ping, perl, file, tar, procps/pgrep).

---

## Quick Start (Interactive)

```bash
cd /root
chmod +x install.sh
sudo ./install.sh
```

The script will ask:

- Mode: **Outside Server** or **Iran Client**
- Ports and **secret key**
- Outside IP (for client)

---

## One-Line Commands

### Interactive (asks all questions)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

### Non-Interactive with ENV (single line)

**Server (Outside):**

```bash
MODE=server SECRET='change-me' TUNNEL_PORT=9999 bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

**Client (Iran):**

```bash
MODE=client SECRET='change-me' TUNNEL_PORT=9999 SERVICE_PORT=8080 OUTSIDE_IP='1.2.3.4' bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

---

## Quick Start (Non-Interactive / Pipe Mode)

When running via `curl | bash`, you must pass required variables:

```bash
MODE=server SECRET='change-me' TUNNEL_PORT=9999 \
  bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

**Client example:**

```bash
MODE=client SECRET='change-me' TUNNEL_PORT=9999 SERVICE_PORT=8080 OUTSIDE_IP='1.2.3.4' \
  bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

---

## Environment Variables

- `MODE=server|client`
- `SECRET='...'`
- `TUNNEL_PORT=9999`
- `SERVICE_PORT=8080` (client)
- `OUTSIDE_IP='x.x.x.x'` (client)
- `PUBLIC_IP='x.x.x.x'` (server; optional override)
- `LOCAL_IP='x.x.x.x'` (client; optional override)
- `SCREEN_NAME=LR4-paqet`
- `AUTO_START=1|0`
- `AUTO_ATTACH=1|0` (auto-attach to screen at the end when TTY is available)
- `SKIP_PKG_INSTALL=1|0` (skip dependency installation if set to 1)
- `WATCHDOG=1|0`
- `WATCHDOG_METHOD=auto|cron|systemd`

---

## Logs

- Installer log: `/root/paqet-install.log`
- Runtime log: `/root/paqet-runtime.log`
- Watchdog log: `/root/paqet-watchdog.log`

View logs:

```bash
tail -f /root/paqet-runtime.log
```

---

## Screen Usage

- List sessions: `screen -ls`
- Attach: `screen -r LR4-paqet`
- Detach: `Ctrl + A`, then `D`

---

## Troubleshooting

- **“Killed” in runtime log:** likely OOM (low memory).
  - Use a larger server
  - Stop other services
  - Add swap (optional)

- **No gateway MAC detected:** try setting up networking or check `ip r` output.
