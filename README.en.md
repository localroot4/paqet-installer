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
