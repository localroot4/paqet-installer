#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# Paqet Auto Installer/Configurator (Ubuntu 22)
# - Keeps FULL original example YAML structure
# - Copies example/*.yaml.example to /root/*.yaml
# - Applies ONLY requested modifications
# - Runs inside GNU screen + watchdog (every 1 minute)
# - Works reliably with: curl ... | bash   (NO interactive prompts in pipe mode)
# - Supports interactive mode only when run with a real TTY (local file execution)
# - Logs to screen + /root/paqet-install.log + /root/paqet-runtime.log
# - Written by Atil (LR4) / localroot4
############################################

# ===== Defaults (override via ENV) =====
PAQET_VERSION="${PAQET_VERSION:-v1.0.0-alpha.11}"   # you can set v1.0.0-alpha.12 etc
MODE="${MODE:-}"                                    # server | client (REQUIRED in pipe mode)
TUNNEL_PORT="${TUNNEL_PORT:-9999}"
SERVICE_PORT="${SERVICE_PORT:-8080}"                # client only
OUTSIDE_IP="${OUTSIDE_IP:-}"                        # client only
PUBLIC_IP="${PUBLIC_IP:-}"                          # server only (optional)
LOCAL_IP="${LOCAL_IP:-}"                            # client only (optional)
SECRET="${SECRET:-}"                                # REQUIRED in pipe mode
SCREEN_NAME="${SCREEN_NAME:-LR4-paqet}"
AUTO_START="${AUTO_START:-1}"                       # 1=run in screen automatically
WATCHDOG="${WATCHDOG:-1}"                           # 1=enable watchdog
WATCHDOG_METHOD="${WATCHDOG_METHOD:-auto}"          # auto | cron | systemd
FORCE_IPV6_DISABLE="${FORCE_IPV6_DISABLE:-1}"       # 1=comment ipv6 block as requested

# ===== Paths =====
ROOT_DIR="/root"
LOG_INSTALL="${ROOT_DIR}/paqet-install.log"
LOG_RUNTIME="${ROOT_DIR}/paqet-runtime.log"
LOG_WATCHDOG="${ROOT_DIR}/paqet-watchdog.log"

EXTRACT_DIR="${ROOT_DIR}/paqet"
BIN_LOCAL="${ROOT_DIR}/paqet_linux_amd64"           # keep name stable for your docs
SERVER_YAML="${ROOT_DIR}/server.yaml"
CLIENT_YAML="${ROOT_DIR}/client.yaml"
WATCHDOG_SH="${ROOT_DIR}/paqet-watchdog.sh"

# ===== GitHub release URL pattern (we try multiple arch names) =====
RELEASE_BASE="https://github.com/hanselime/paqet/releases/download/${PAQET_VERSION}"

# ===== Pretty logs =====
ts() { date +"%Y-%m-%d %H:%M:%S"; }
C_RED="\033[0;31m"; C_GRN="\033[0;32m"; C_YLW="\033[1;33m"; C_CYN="\033[0;36m"; C_RST="\033[0m"
log()  { echo -e "$(ts) ${C_CYN}[LOG]${C_RST} $*" | tee -a "$LOG_INSTALL"; }
ok()   { echo -e "$(ts) ${C_GRN}[OK]${C_RST}  $*" | tee -a "$LOG_INSTALL"; }
warn() { echo -e "$(ts) ${C_YLW}[WARN]${C_RST} $*" | tee -a "$LOG_INSTALL"; }
err()  { echo -e "$(ts) ${C_RED}[ERR]${C_RST} $*" | tee -a "$LOG_INSTALL" >&2; }
die()  { err "$*"; exit 1; }

on_error() {
  local code=$?
  err "Installer failed (exit code: $code)."
  err "Last 120 install log lines:"
  tail -n 120 "$LOG_INSTALL" 2>/dev/null || true
  exit "$code"
}
trap on_error ERR

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root. (sudo -i)"
}

is_pipe_mode() {
  # true when running: curl ... | bash
  [[ ! -t 0 ]]
}

has_tty() {
  [[ -t 0 && -t 1 ]]
}

# ===== Strict rule: NO prompts in pipe mode =====
require_env_in_pipe() {
  if is_pipe_mode; then
    [[ -n "${MODE}" ]] || die "PIPE mode detected. Set MODE=server or MODE=client. (No interactive prompts in pipe mode)"
    [[ -n "${SECRET}" ]] || die "PIPE mode detected. Set SECRET='...'. (No interactive prompts in pipe mode)"
    if [[ "${MODE}" == "client" ]]; then
      [[ -n "${OUTSIDE_IP}" ]] || die "MODE=client requires OUTSIDE_IP='x.x.x.x' in pipe mode."
    fi
  fi
}

# ===== Optional interactive prompts (ONLY when running locally, not via pipe) =====
prompt() {
  local __var="$1" __text="$2" __def="${3:-}" __val=""
  if ! has_tty; then
    die "Interactive prompt requested but no TTY. Use ENV vars."
  fi
  if [[ -n "$__def" ]]; then
    read -r -p "$__text [$__def]: " __val
    __val="${__val:-$__def}"
  else
    read -r -p "$__text: " __val
  fi
  printf -v "$__var" "%s" "$__val"
}

# ===== APT resiliency (Hetzner ARM mirror 404 fix) =====
apt_fix_sources_if_needed() {
  local arch
  arch="$(dpkg --print-architecture 2>/dev/null || echo "")"
  [[ "$arch" == "arm64" || "$arch" == "armhf" ]] || return 0

  # If sources incorrectly point to /ubuntu/ instead of /ubuntu-ports/
  local changed=0
  if grep -Rqs "mirror\.hetzner\.com/ubuntu/security" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
    sed -i 's#mirror\.hetzner\.com/ubuntu/security#mirror.hetzner.com/ubuntu-ports/security#g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
    changed=1
  fi
  if grep -Rqs "mirror\.hetzner\.com/ubuntu/packages" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
    sed -i 's#mirror\.hetzner\.com/ubuntu/packages#mirror.hetzner.com/ubuntu-ports/packages#g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
    changed=1
  fi

  if [[ "$changed" -eq 1 ]]; then
    warn "ARM architecture detected; adjusted Hetzner sources to ubuntu-ports to avoid 404."
  fi
}

apt_update_retry() {
  export DEBIAN_FRONTEND=noninteractive
  local tries=3
  local i=1
  while (( i <= tries )); do
    log "apt update... (try $i/$tries)"
    set +e
    apt-get update -y 2>&1 | tee -a "$LOG_INSTALL" >/dev/null
    local rc=${PIPESTATUS[0]}
    set -e
    if [[ "$rc" -eq 0 ]]; then
      return 0
    fi
    warn "apt update failed (rc=$rc). Attempting sources fix + retry..."
    apt_fix_sources_if_needed
    sleep $((i*2))
    i=$((i+1))
  done
  return 1
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive

  apt_fix_sources_if_needed
  apt_update_retry || die "apt update failed. Check /etc/apt/sources.list and network."

  log "Installing packages: wget curl screen net-tools iproute2 ping libpcap-dev perl..."
  apt-get install -y wget curl ca-certificates screen net-tools iproute2 iputils-ping libpcap-dev perl \
    2>&1 | tee -a "$LOG_INSTALL" >/dev/null
  ok "Packages installed."
}

# ===== Networking detect =====
get_default_if() { ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1 || true; }
get_gateway_ip() { ip -4 route | awk '/default/ {print $3; exit}' || true; }
get_local_ipv4() { local iface="$1"; ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true; }

get_public_ipv4() {
  local ip=""
  ip="$(curl -4 -s --max-time 6 https://api.ipify.org || true)"
  [[ -n "$ip" ]] && { echo "$ip"; return; }
  ip="$(curl -4 -s --max-time 6 https://ifconfig.me/ip || true)"
  [[ -n "$ip" ]] && { echo "$ip"; return; }
  ip="$(curl -4 -s --max-time 6 https://icanhazip.com | tr -d '\n\r' || true)"
  echo "$ip"
}

get_gateway_mac() {
  local gw="$1"
  ping -c 1 -W 1 "$gw" >/dev/null 2>&1 || true
  local mac=""
  mac="$(ip neigh show "$gw" 2>/dev/null | awk '{print $5}' | head -n1 || true)"
  if [[ -n "$mac" && "$mac" != "FAILED" && "$mac" != "INCOMPLETE" ]]; then
    echo "$mac"; return
  fi
  mac="$(arp -n "$gw" 2>/dev/null | awk 'NR==2{print $3}' | head -n1 || true)"
  echo "$mac"
}

# ===== Download logic (multi-arch attempt) =====
uname_arch() {
  local m
  m="$(uname -m 2>/dev/null || echo unknown)"
  case "$m" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armhf) echo "armhf" ;;
    *) echo "$m" ;;
  esac
}

download_with_retry() {
  local url="$1" out="$2"
  local tries=6 wait=2
  for i in $(seq 1 $tries); do
    log "Downloading ($i/$tries): $url"
    if wget -q --show-progress --timeout=20 --tries=2 "$url" -O "$out"; then
      ok "Downloaded: $out"
      return 0
    fi
    warn "Download failed. Retry in ${wait}s..."
    sleep "$wait"
    wait=$((wait*2))
  done
  return 1
}

download_release_tarball() {
  mkdir -p "$ROOT_DIR"

  local arch
  arch="$(uname_arch)"

  # Candidate names (we try many so it works on any VPS hardware as long as asset exists)
  local candidates=(
    "paqet-linux-${arch}-${PAQET_VERSION}.tar.gz"
    "paqet-linux-${arch}-${PAQET_VERSION#v}.tar.gz"
    "paqet-linux-${arch}-v${PAQET_VERSION#v}.tar.gz"
    "paqet-linux-amd64-${PAQET_VERSION}.tar.gz"
    "paqet-linux-amd64-${PAQET_VERSION#v}.tar.gz"
    "paqet-linux-amd64-v${PAQET_VERSION#v}.tar.gz"
    "paqet-linux-arm64-${PAQET_VERSION}.tar.gz"
    "paqet-linux-arm64-${PAQET_VERSION#v}.tar.gz"
    "paqet-linux-aarch64-${PAQET_VERSION}.tar.gz"
    "paqet-linux-aarch64-${PAQET_VERSION#v}.tar.gz"
  )

  local tarball=""
  for name in "${candidates[@]}"; do
    local url="${RELEASE_BASE}/${name}"
    tarball="${ROOT_DIR}/${name}"
    if [[ -f "$tarball" ]]; then
      warn "Tarball already exists: $tarball"
      echo "$tarball"
      return 0
    fi
    if download_with_retry "$url" "$tarball"; then
      echo "$tarball"
      return 0
    fi
  done

  die "Could not download paqet tarball for arch=$(uname -m). Set PAQET_VERSION or check release assets."
}

extract_and_prepare_binary() {
  local tarball="$1"
  mkdir -p "$EXTRACT_DIR"
  log "Extracting tarball to: $EXTRACT_DIR"
  tar zxvf "$tarball" -C "$EXTRACT_DIR" 2>&1 | tee -a "$LOG_INSTALL" >/dev/null
  ok "Extract done."

  log "Searching for paqet binary in extracted files..."
  local found=""
  found="$(find "$EXTRACT_DIR" -maxdepth 5 -type f \( -name "paqet_linux_amd64" -o -name "paqet_linux_arm64" -o -name "paqet" -o -name "*paqet*" \) 2>/dev/null | head -n1 || true)"
  [[ -z "$found" ]] && die "Could not find paqet binary inside extracted folder: $EXTRACT_DIR"

  # Keep stable name BIN_LOCAL
  cp -f "$found" "$BIN_LOCAL"
  chmod +x "$BIN_LOCAL"
  ok "Binary ready: $BIN_LOCAL"
}

find_example_dir() {
  local d=""
  d="$(find "$EXTRACT_DIR" -type d -name "example" -maxdepth 6 2>/dev/null | head -n1 || true)"
  if [[ -z "$d" ]]; then
    local f=""
    f="$(find "$EXTRACT_DIR" -type f -name "client.yaml.example" -maxdepth 7 2>/dev/null | head -n1 || true)"
    [[ -n "$f" ]] && d="$(dirname "$f")"
  fi
  echo "$d"
}

# ===== YAML edits (keep full template, change only requested parts) =====
set_interface_line() {
  local file="$1" iface="$2"
  sed -i "s/^\([[:space:]]*interface:[[:space:]]*\)\"[^\"]*\"/\1\"${iface}\"/" "$file"
}

set_router_mac_all_occurrences() {
  local file="$1" mac="$2"
  perl -0777 -i -pe "s/router_mac: \"[^\"]*\"/router_mac: \"$mac\"/g" "$file"
}

comment_ipv6_block() {
  local file="$1"
  # Your requested style (comment header stays, three lines commented)
  sed -i 's/^\([[:space:]]*\)ipv6:/\1#ipv6:/' "$file"
  sed -i 's/^\([[:space:]]*\)addr: \"\[\(::1\|2001:db8::1\).*\"/\1#addr: "[::1]:9999"/' "$file" || true
  sed -i 's/^\([[:space:]]*\)router_mac: \"[^\"]*\"/\1#router_mac: "aa:bb:cc:dd:ee:ff"/' "$file" || true
}

set_server_listen_port() {
  local file="$1" port="$2"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\":9999\"/\1\":${port}\"/" "$file"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\":\([0-9]\+\)\"/\1\":${port}\"/" "$file"
}

set_server_ipv4_addr_public() {
  local file="$1" ip="$2" port="$3"
  # Replace the example addr line
  sed -i "s/\"10\.0\.0\.100:9999\"/\"${ip}:${port}\"/" "$file"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\"[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+:[0-9]\+\"/\1\"${ip}:${port}\"/" "$file"
}

set_secret_key() {
  local file="$1" secret="$2"
  sed -i "s/^\([[:space:]]*key:[[:space:]]*\)\"[^\"]*\"/\1\"${secret}\"/" "$file"
}

disable_socks5_enable_forward_client() {
  local file="$1"
  # Comment socks5 block
  sed -i 's/^socks5:/#socks5:/' "$file"
  sed -i 's/^[[:space:]]\{2\}- listen:/#  - listen:/' "$file"
  sed -i 's/^[[:space:]]\{4\}username:/#    username:/' "$file"
  sed -i 's/^[[:space:]]\{4\}password:/#    password:/' "$file"

  # Enable forward block
  sed -i 's/^# forward:/forward:/' "$file"
  sed -i 's/^#   - listen:/  - listen:/' "$file"
  sed -i 's/^#     target:/    target:/' "$file"
  sed -i 's/^#     protocol:/    protocol:/' "$file"
}

set_client_ipv4_addr_local() {
  local file="$1" local_ip="$2"
  sed -i "s/\"192\.168\.1\.100:0\"/\"${local_ip}:0\"/" "$file"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\"[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+:0\"/\1\"${local_ip}:0\"/" "$file"
}

set_client_server_addr() {
  local file="$1" outside_ip="$2" tunnel_port="$3"
  sed -i "s/\"10\.0\.0\.100:9999\"/\"${outside_ip}:${tunnel_port}\"/" "$file"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\"[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+:[0-9]\+\"/\1\"${outside_ip}:${tunnel_port}\"/" "$file"
}

set_forward_listen_target_client() {
  local file="$1" service_port="$2" outside_ip="$3"
  sed -i "s/\"127\.0\.0\.1:8080\"/\"0.0.0.0:${service_port}\"/" "$file"
  sed -i "s/\"127\.0\.0\.1:80\"/\"${outside_ip}:${service_port}\"/" "$file"
}

# ===== screen runner =====
screen_exists() { screen -ls 2>/dev/null | grep -q "[[:space:]]${SCREEN_NAME}[[:space:]]"; }

start_in_screen() {
  local mode="$1" cfg="$2"
  screen -wipe >/dev/null 2>&1 || true
  : >> "$LOG_RUNTIME"

  if screen_exists; then
    warn "Screen session already exists: ${SCREEN_NAME} (not starting a second one)"
    return 0
  fi

  log "Starting paqet in screen session: ${SCREEN_NAME}"
  log "Command: ${BIN_LOCAL} run -c ${cfg}"
  screen -dmS "$SCREEN_NAME" bash -lc "
    cd '$ROOT_DIR'
    echo '--- $(ts) START ${mode} ---' >> '$LOG_RUNTIME'
    chmod +x '$BIN_LOCAL'
    '$BIN_LOCAL' run -c '$cfg' 2>&1 | tee -a '$LOG_RUNTIME'
    echo '--- $(ts) STOP ${mode} (process ended) ---' >> '$LOG_RUNTIME'
    sleep 2
  "
  ok "Screen started. Attach: screen -r ${SCREEN_NAME}"
}

# ===== watchdog (systemd timer preferred, cron fallback) =====
write_watchdog_script() {
  cat > "$WATCHDOG_SH" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-}"
SCREEN_NAME="${2:-}"
BIN="${3:-}"
CFG="${4:-}"
RUNTIME_LOG="${5:-/root/paqet-runtime.log}"
WD_LOG="${6:-/root/paqet-watchdog.log}"

ts(){ date +"%Y-%m-%d %H:%M:%S"; }
wlog(){ echo "$(ts) [WD] $*" >> "$WD_LOG"; }

screen_exists(){ screen -ls 2>/dev/null | grep -q "[[:space:]]${SCREEN_NAME}[[:space:]]"; }
proc_running(){ pgrep -fa "${BIN} run -c ${CFG}" >/dev/null 2>&1; }
killed_tail(){ tail -n 5 "$RUNTIME_LOG" 2>/dev/null | grep -qiE "(killed|out of memory|oom)"; }

restart() {
  wlog "Restarting... mode=${MODE} screen=${SCREEN_NAME}"
  screen -wipe >/dev/null 2>&1 || true
  if screen_exists; then
    screen -S "$SCREEN_NAME" -X quit >/dev/null 2>&1 || true
    sleep 1
  fi
  screen -dmS "$SCREEN_NAME" bash -lc "
    cd /root
    echo '--- '\"\$(ts)\"' RESTART ${MODE} ---' >> '${RUNTIME_LOG}'
    chmod +x '${BIN}'
    '${BIN}' run -c '${CFG}' 2>&1 | tee -a '${RUNTIME_LOG}'
    echo '--- '\"\$(ts)\"' STOP ${MODE} (process ended) ---' >> '${RUNTIME_LOG}'
    sleep 2
  "
  wlog "Restart triggered."
}

main(){
  [[ -n "$MODE" && -n "$SCREEN_NAME" && -n "$BIN" && -n "$CFG" ]] || exit 0

  if proc_running; then
    exit 0
  fi

  if killed_tail; then
    wlog "Detected killed/OOM in runtime log tail."
    restart
    exit 0
  fi

  if ! screen_exists; then
    wlog "Screen session missing."
    restart
    exit 0
  fi

  wlog "Process not running. Restarting."
  restart
}
main
EOF
  chmod +x "$WATCHDOG_SH"
  ok "Watchdog script ready: $WATCHDOG_SH"
}

install_watchdog_systemd() {
  local cfg="$1"
  local svc="/etc/systemd/system/paqet-watchdog.service"
  local tmr="/etc/systemd/system/paqet-watchdog.timer"

  cat > "$svc" <<EOF
[Unit]
Description=Paqet Watchdog (LR4)
After=network.target

[Service]
Type=oneshot
ExecStart=${WATCHDOG_SH} ${MODE} ${SCREEN_NAME} ${BIN_LOCAL} ${cfg} ${LOG_RUNTIME} ${LOG_WATCHDOG}
EOF

  cat > "$tmr" <<EOF
[Unit]
Description=Run Paqet Watchdog every 1 minute

[Timer]
OnBootSec=30
OnUnitActiveSec=60
AccuracySec=5

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now paqet-watchdog.timer >/dev/null 2>&1 || true
  ok "Watchdog enabled via systemd timer: paqet-watchdog.timer"
}

install_watchdog_cron() {
  local cfg="$1"
  local line="* * * * * ${WATCHDOG_SH} ${MODE} ${SCREEN_NAME} ${BIN_LOCAL} ${cfg} ${LOG_RUNTIME} ${LOG_WATCHDOG}"
  ( crontab -l 2>/dev/null | grep -v "paqet-watchdog.sh" || true; echo "$line" ) | crontab -
  ok "Watchdog enabled via cron (every 1 minute)."
}

install_watchdog() {
  local cfg="$1"
  [[ "$WATCHDOG" == "1" ]] || { warn "WATCHDOG=0 (skipped)"; return 0; }

  write_watchdog_script

  if [[ "$WATCHDOG_METHOD" == "systemd" ]]; then
    install_watchdog_systemd "$cfg"
    return 0
  fi
  if [[ "$WATCHDOG_METHOD" == "cron" ]]; then
    install_watchdog_cron "$cfg"
    return 0
  fi

  # auto
  if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    install_watchdog_systemd "$cfg"
  else
    install_watchdog_cron "$cfg"
  fi
}

# ===== main =====
main() {
  : > "$LOG_INSTALL"
  : >> "$LOG_RUNTIME"
  : >> "$LOG_WATCHDOG"

  need_root

  log "==== Paqet Installer Started ===="
  log "Version: ${PAQET_VERSION}"
  log "Install log : ${LOG_INSTALL}"
  log "Runtime log : ${LOG_RUNTIME}"
  log "Input mode  : $(is_pipe_mode && echo 'PIPE (ENV required)' || echo 'TTY (interactive allowed)')"

  require_env_in_pipe

  # If not pipe and missing vars, ask interactively (ONLY local/tty)
  if ! is_pipe_mode; then
    if [[ -z "$MODE" ]]; then
      log "Choose mode:"
      echo "  1) Outside Server  (server.yaml + run in screen)"
      echo "  2) Iran Client     (client.yaml + forward + run in screen)"
      echo
      local choice
      prompt choice "Enter 1 or 2" "1"
      [[ "$choice" == "1" ]] && MODE="server" || MODE="client"
    fi

    [[ -n "$SECRET" ]] || prompt SECRET "Secret key (must match both sides)" "change-me-please"
    [[ -n "$TUNNEL_PORT" ]] || prompt TUNNEL_PORT "Tunnel port" "9999"

    if [[ "$MODE" == "client" ]]; then
      [[ -n "$OUTSIDE_IP" ]] || prompt OUTSIDE_IP "Outside server PUBLIC IPv4" ""
      [[ -n "$SERVICE_PORT" ]] || prompt SERVICE_PORT "Service port to expose (0.0.0.0:PORT)" "8080"
    fi
  fi

  [[ "$MODE" == "server" || "$MODE" == "client" ]] || die "Invalid MODE. Use MODE=server or MODE=client"
  [[ -n "$SECRET" ]] || die "SECRET is required."
  [[ "$MODE" != "client" || -n "$OUTSIDE_IP" ]] || die "MODE=client requires OUTSIDE_IP."

  apt_install

  local tarball
  tarball="$(download_release_tarball)"
  extract_and_prepare_binary "$tarball"

  local example_dir
  example_dir="$(find_example_dir)"
  [[ -n "$example_dir" ]] || die "Could not find example directory inside extracted files."
  ok "Found example dir: $example_dir"

  log "Detecting network info..."
  local iface gw gw_mac local_ip public_ip
  iface="$(get_default_if)"
  gw="$(get_gateway_ip)"
  [[ -n "$iface" ]] || die "No default interface detected. (ip r)"
  [[ -n "$gw" ]] || die "No default gateway detected. (ip r)"

  gw_mac="$(get_gateway_mac "$gw" || true)"
  local_ip="$(get_local_ipv4 "$iface" || true)"
  public_ip="$(get_public_ipv4 || true)"

  log "Detected:"
  log "  interface  = ${iface}"
  log "  gateway    = ${gw}"
  log "  gatewayMAC = ${gw_mac:-UNKNOWN}"
  log "  localIPv4  = ${local_ip:-UNKNOWN}"
  log "  publicIPv4 = ${public_ip:-UNKNOWN}"

  [[ -n "$gw_mac" ]] || die "Gateway MAC not detected. Set it manually (not supported in pipe unless you fix L2)."

  if [[ "$MODE" == "server" ]]; then
    local ip_final
    ip_final="${PUBLIC_IP:-$public_ip}"
    [[ -n "$ip_final" ]] || die "Public IPv4 not detected. Set PUBLIC_IP='x.x.x.x'."

    log "Copying FULL server example -> ${SERVER_YAML}"
    cp -f "${example_dir}/server.yaml.example" "$SERVER_YAML"
    ok "Copied full template: $SERVER_YAML"

    log "Applying ONLY requested edits to server.yaml..."
    set_interface_line "$SERVER_YAML" "$iface"
    set_server_listen_port "$SERVER_YAML" "$TUNNEL_PORT"
    set_server_ipv4_addr_public "$SERVER_YAML" "$ip_final" "$TUNNEL_PORT"
    set_router_mac_all_occurrences "$SERVER_YAML" "$gw_mac"
    [[ "$FORCE_IPV6_DISABLE" == "1" ]] && comment_ipv6_block "$SERVER_YAML"
    set_secret_key "$SERVER_YAML" "$SECRET"
    ok "server.yaml ready."

    if [[ "$AUTO_START" == "1" ]]; then
      start_in_screen "server" "$SERVER_YAML"
      install_watchdog "$SERVER_YAML"
    fi

    ok "DONE (Outside Server)."
    log "Config: $SERVER_YAML"
    log "Attach: screen -r ${SCREEN_NAME}"
    log "Runtime log: $LOG_RUNTIME"
    exit 0
  fi

  # MODE=client
  local lip_final
  lip_final="${LOCAL_IP:-$local_ip}"
  [[ -n "$lip_final" ]] || die "Local IPv4 not detected. Set LOCAL_IP='x.x.x.x'."

  log "Copying FULL client example -> ${CLIENT_YAML}"
  cp -f "${example_dir}/client.yaml.example" "$CLIENT_YAML"
  ok "Copied full template: $CLIENT_YAML"

  log "Applying ONLY requested edits to client.yaml..."
  set_interface_line "$CLIENT_YAML" "$iface"
  set_client_ipv4_addr_local "$CLIENT_YAML" "$lip_final"
  set_router_mac_all_occurrences "$CLIENT_YAML" "$gw_mac"
  [[ "$FORCE_IPV6_DISABLE" == "1" ]] && comment_ipv6_block "$CLIENT_YAML"
  disable_socks5_enable_forward_client "$CLIENT_YAML"
  set_forward_listen_target_client "$CLIENT_YAML" "$SERVICE_PORT" "$OUTSIDE_IP"
  set_client_server_addr "$CLIENT_YAML" "$OUTSIDE_IP" "$TUNNEL_PORT"
  set_secret_key "$CLIENT_YAML" "$SECRET"
  ok "client.yaml ready."

  if [[ "$AUTO_START" == "1" ]]; then
    start_in_screen "client" "$CLIENT_YAML"
    install_watchdog "$CLIENT_YAML"
  fi

  ok "DONE (Iran Client)."
  log "Config: $CLIENT_YAML"
  log "Attach: screen -r ${SCREEN_NAME}"
  log "Runtime log: $LOG_RUNTIME"
}
main "$@"
