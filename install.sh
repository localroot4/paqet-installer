#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# Paqet Auto Installer/Runner (Ubuntu 22)
# - Uses FULL original example YAML templates
# - Copies example/*.yaml.example to /root/*.yaml
# - Applies ONLY requested modifications
# - Runs inside GNU screen + adds cron watchdog (1 min)
# - Works with: curl ... | bash   (TTY-safe prompts via /dev/tty when available)
# - Supports non-interactive mode via ENV vars
# - Logs to screen + /root/paqet-install.log + /root/paqet-runtime.log
# - Written by Atil (LR4)  /  https://github.com/localroot4
############################################

VERSION="v1.0.0-alpha.11"
TARBALL_URL="https://github.com/hanselime/paqet/releases/download/${VERSION}/paqet-linux-amd64-${VERSION}.tar.gz"
TARBALL_NAME="paqet-linux-amd64-${VERSION}.tar.gz"

ROOT_DIR="/root"
EXTRACT_DIR="${ROOT_DIR}/paqet"
BIN_LOCAL="${ROOT_DIR}/paqet_linux_amd64"

LOG_INSTALL="${ROOT_DIR}/paqet-install.log"
LOG_RUNTIME="${ROOT_DIR}/paqet-runtime.log"

SERVER_YAML="${ROOT_DIR}/server.yaml"
CLIENT_YAML="${ROOT_DIR}/client.yaml"

WATCHDOG="${ROOT_DIR}/paqet-watchdog.sh"
SCREEN_NAME_DEFAULT="LR4-paqet"

# ---- ENV (non-interactive) support ----
# MODE: "server" or "client"
# TUNNEL_PORT: default 9999
# SECRET: required (or prompt if TTY exists)
# SCREEN_NAME: default LR4-paqet
# OUTSIDE_IP: required for client
# SERVICE_PORT: default 8080 (client only)
# PUBLIC_IP: optional for server; autodetect
# LOCAL_IP: optional for client; autodetect
#
# Examples:
#   MODE=server TUNNEL_PORT=9999 SECRET=abc curl -fsSL <url> | bash
#   MODE=client OUTSIDE_IP=1.2.3.4 TUNNEL_PORT=9999 SERVICE_PORT=8080 SECRET=abc curl -fsSL <url> | bash

ts() { date +"%Y-%m-%d %H:%M:%S"; }
C_RED="\033[0;31m"; C_GRN="\033[0;32m"; C_YLW="\033[1;33m"; C_CYN="\033[0;36m"; C_RST="\033[0m"
log()  { echo -e "$(ts) ${C_CYN}[LOG]${C_RST} $*" | tee -a "$LOG_INSTALL"; }
ok()   { echo -e "$(ts) ${C_GRN}[OK]${C_RST}  $*" | tee -a "$LOG_INSTALL"; }
warn() { echo -e "$(ts) ${C_YLW}[WARN]${C_RST} $*" | tee -a "$LOG_INSTALL"; }
err()  { echo -e "$(ts) ${C_RED}[ERR]${C_RST} $*" | tee -a "$LOG_INSTALL" >&2; }
die() { err "$*"; exit 1; }

on_error() {
  local code=$?
  err "Installer failed (exit code: $code)."
  err "Last 120 install log lines:"
  tail -n 120 "$LOG_INSTALL" 2>/dev/null || true
  exit $code
}
trap on_error ERR

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root. Example: sudo -i ; then ./install.sh"
  fi
}

# ---- TTY handling (works for curl|bash when controlling TTY exists) ----
TTY_OK=0
if [[ -t 0 || -t 1 || -t 2 ]]; then
  TTY_OK=1
fi

# try opening /dev/tty on FD 3 for robust prompts
TTY_FD=3
if [[ -r /dev/tty && -w /dev/tty ]]; then
  exec 3</dev/tty 3>/dev/tty || true
fi

prompt() {
  local __var="$1"
  local __text="$2"
  local __def="${3:-}"
  local __val=""

  # If no TTY and no /dev/tty FD, do not crash: ask user to use ENV mode
  if [[ "$TTY_OK" -ne 1 && ! -t "$TTY_FD" ]]; then
    err "No interactive TTY available for prompts."
    err "Use ENV mode. Example:"
    err "  MODE=server TUNNEL_PORT=9999 SECRET='...' curl -fsSL <url> | bash"
    exit 2
  fi

  # Print prompt to TTY FD when piping
  if [[ -n "$__def" ]]; then
    printf "%s [%s]: " "$__text" "$__def" >&"$TTY_FD"
  else
    printf "%s: " "$__text" >&"$TTY_FD"
  fi

  if ! IFS= read -r __val <&"$TTY_FD"; then
    err "Failed to read input from TTY."
    exit 2
  fi

  if [[ -n "$__def" && -z "$__val" ]]; then
    __val="$__def"
  fi

  printf -v "$__var" "%s" "$__val"
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  log "apt update..."
  apt-get update -y | tee -a "$LOG_INSTALL" >/dev/null

  log "Installing packages: wget curl screen net-tools iproute2 ping libpcap-dev perl..."
  apt-get install -y wget curl ca-certificates screen net-tools iproute2 iputils-ping libpcap-dev perl \
    | tee -a "$LOG_INSTALL" >/dev/null
  ok "Packages installed."
}

download_with_retry() {
  local url="$1"
  local out="$2"
  local tries=6
  local wait=2

  for i in $(seq 1 $tries); do
    log "Downloading ($i/$tries): $url"
    if wget -q --show-progress --timeout=20 --tries=2 "$url" -O "$out"; then
      ok "Downloaded: $out"
      return 0
    fi
    warn "Download attempt $i failed. Retrying in ${wait}s..."
    sleep "$wait"
    wait=$((wait*2))
  done
  return 1
}

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
  local mac=""
  ping -c 1 -W 1 "$gw" >/dev/null 2>&1 || true

  mac="$(ip neigh show "$gw" 2>/dev/null | awk '{print $5}' | head -n1 || true)"
  if [[ -n "$mac" && "$mac" != "FAILED" && "$mac" != "INCOMPLETE" ]]; then
    echo "$mac"; return
  fi

  mac="$(arp -n "$gw" 2>/dev/null | awk 'NR==2{print $3}' | head -n1 || true)"
  echo "$mac"
}

extract_and_prepare_binary() {
  mkdir -p "$EXTRACT_DIR"
  cd "$ROOT_DIR"

  if [[ ! -f "$ROOT_DIR/$TARBALL_NAME" ]]; then
    download_with_retry "$TARBALL_URL" "$ROOT_DIR/$TARBALL_NAME" || die "Could not download tarball."
  else
    warn "Tarball already exists: $ROOT_DIR/$TARBALL_NAME"
  fi

  log "Extracting tarball to: $EXTRACT_DIR"
  tar zxvf "$ROOT_DIR/$TARBALL_NAME" -C "$EXTRACT_DIR" | tee -a "$LOG_INSTALL" >/dev/null
  ok "Extract done."

  log "Searching for paqet binary in extracted files..."
  local found=""
  found="$(find "$EXTRACT_DIR" -maxdepth 5 -type f \( -name "paqet_linux_amd64" -o -name "paqet" -o -name "paqet-linux-amd64" -o -name "*paqet*amd64*" \) 2>/dev/null | head -n1 || true)"
  if [[ -z "$found" ]]; then
    found="$(find "$EXTRACT_DIR" -maxdepth 5 -type f -perm -111 2>/dev/null | head -n1 || true)"
  fi
  [[ -z "$found" ]] && die "Could not find paqet binary in extracted folder: $EXTRACT_DIR"

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

set_interface_line() {
  local file="$1" iface="$2"
  sed -i "s/^\([[:space:]]*interface:[[:space:]]*\)\"[^\"]*\"/\1\"${iface}\"/" "$file"
}

set_router_mac_ipv4_only() {
  local file="$1" mac="$2"
  perl -0777 -i -pe "s/router_mac: \"[^\"]*\"/router_mac: \"$mac\"/s" "$file"
}

comment_ipv6_block_server() {
  local file="$1"
  sed -i '0,/^[[:space:]]\{2\}ipv6:/s//  #ipv6:/' "$file"
  sed -i '0,/^[[:space:]]\{4\}addr: /s//    #addr: /' "$file" || true
  sed -i '0,/^[[:space:]]\{4\}router_mac: /s//    #router_mac: /' "$file" || true
}

comment_ipv6_block_client() {
  local file="$1"
  sed -i '0,/^[[:space:]]\{2\}ipv6:/s//  #ipv6:/' "$file"
  sed -i '0,/^[[:space:]]\{4\}addr: /s//    #addr: /' "$file" || true
  sed -i '0,/^[[:space:]]\{4\}router_mac: /s//    #router_mac: /' "$file" || true
}

set_server_listen_port() {
  local file="$1" port="$2"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\":9999\"/\1\":${port}\"/" "$file"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\":\([0-9]\+\)\"/\1\":${port}\"/" "$file"
}

set_server_ipv4_addr_public() {
  local file="$1" ip="$2" port="$3"
  sed -i "s/\"10\.0\.0\.100:9999\"/\"${ip}:${port}\"/" "$file"
  sed -i "s/^\([[:space:]]*addr:[[:space:]]*\)\"[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+:9999\"/\1\"${ip}:${port}\"/" "$file"
}

set_secret_key() {
  local file="$1" secret="$2"
  sed -i "s/^\([[:space:]]*key:[[:space:]]*\)\"[^\"]*\"/\1\"${secret}\"/" "$file"
}

disable_socks5_enable_forward_client() {
  local file="$1"
  sed -i 's/^socks5:/#socks5:/' "$file"
  sed -i 's/^[[:space:]]\{2\}- listen:/#  - listen:/' "$file"
  sed -i 's/^[[:space:]]\{4\}username:/#    username:/' "$file"
  sed -i 's/^[[:space:]]\{4\}password:/#    password:/' "$file"

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

screen_exists() { local name="$1"; screen -ls 2>/dev/null | grep -q "[[:space:]]${name}[[:space:]]"; }

start_in_screen() {
  local screen_name="$1" mode="$2" cfg="$3"
  screen -wipe >/dev/null 2>&1 || true

  if screen_exists "$screen_name"; then
    warn "Screen session already exists: $screen_name (not starting a second one)"
    return 0
  fi

  : >> "$LOG_RUNTIME"
  log "Starting paqet in screen session: $screen_name"
  log "Command: ${BIN_LOCAL} run -c ${cfg}"

  screen -dmS "$screen_name" bash -lc "
    cd '$ROOT_DIR'
    echo '--- $(ts) START ${mode} ---' >> '$LOG_RUNTIME'
    chmod +x '$BIN_LOCAL'
    '$BIN_LOCAL' run -c '$cfg' 2>&1 | tee -a '$LOG_RUNTIME'
    echo '--- $(ts) STOP ${mode} (process ended) ---' >> '$LOG_RUNTIME'
    sleep 2
  "

  ok "Screen started. Attach with: screen -r ${screen_name}"
}

write_watchdog() {
  cat > "$WATCHDOG" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-}"
SCREEN_NAME="${2:-}"
BIN="${3:-}"
CFG="${4:-}"
RUNTIME_LOG="${5:-/root/paqet-runtime.log}"

ts(){ date +"%Y-%m-%d %H:%M:%S"; }
log(){ echo "$(ts) [WD] $*" >> /root/paqet-watchdog.log; }

screen_exists(){ screen -ls 2>/dev/null | grep -q "[[:space:]]${SCREEN_NAME}[[:space:]]"; }
proc_running(){ pgrep -fa "${BIN} run -c ${CFG}" >/dev/null 2>&1; }
last_line_killed(){ tail -n 3 "$RUNTIME_LOG" 2>/dev/null | grep -qi "killed"; }

restart() {
  log "Restarting... mode=${MODE} screen=${SCREEN_NAME}"
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

  log "Restart triggered."
}

main(){
  if [[ -z "$MODE" || -z "$SCREEN_NAME" || -z "$BIN" || -z "$CFG" ]]; then
    log "Invalid args."
    exit 0
  fi

  if proc_running; then
    exit 0
  fi

  if ! screen_exists; then
    log "Screen missing. Restart needed."
    restart
    exit 0
  fi

  if last_line_killed; then
    log "Detected 'Killed' in runtime log tail. Restart needed."
    restart
    exit 0
  fi

  log "Process not running. Restart needed."
  restart
}
main
EOF

  chmod +x "$WATCHDOG"
  ok "Watchdog created: $WATCHDOG"
}

install_cron_watchdog() {
  local mode="$1" screen_name="$2" cfg="$3"
  local cron_line="* * * * * ${WATCHDOG} ${mode} ${screen_name} ${BIN_LOCAL} ${cfg} ${LOG_RUNTIME}"
  log "Installing cron watchdog (every 1 minute)..."
  ( crontab -l 2>/dev/null | grep -v "paqet-watchdog.sh" || true; echo "$cron_line" ) | crontab -
  ok "Cron installed."
}

env_get() {
  local k="$1"
  local v="${!k:-}"
  [[ -n "$v" ]] && echo "$v" || true
}

main() {
  : > "$LOG_INSTALL"
  : >> "$LOG_RUNTIME"

  need_root
  log "==== Paqet Installer Started ===="
  log "Version: ${VERSION}"
  log "Install log : ${LOG_INSTALL}"
  log "Runtime log : ${LOG_RUNTIME}"
  log "Input mode  : $( [[ -t 0 ]] && echo 'TTY OK' || echo 'PIPE detected (ENV recommended; prompts use /dev/tty if available)' )"

  apt_install
  extract_and_prepare_binary

  local example_dir
  example_dir="$(find_example_dir)"
  [[ -z "$example_dir" ]] && die "Could not find example directory inside extracted files: $EXTRACT_DIR"
  ok "Found example dir: $example_dir"

  log "Detecting network info..."
  local iface gw local_ip public_ip gw_mac
  iface="$(get_default_if)"
  gw="$(get_gateway_ip)"
  [[ -z "$iface" ]] && die "No default interface detected. Run: ip r"
  [[ -z "$gw" ]] && die "No default gateway detected. Run: ip r"

  local_ip="$(get_local_ipv4 "$iface")"
  public_ip="$(get_public_ipv4 || true)"
  gw_mac="$(get_gateway_mac "$gw" || true)"

  log "Detected:"
  log "  interface  = $iface"
  log "  gateway    = $gw"
  log "  gatewayMAC = ${gw_mac:-UNKNOWN}"
  log "  localIPv4  = ${local_ip:-UNKNOWN}"
  log "  publicIPv4 = ${public_ip:-UNKNOWN}"

  if [[ -z "${gw_mac}" || "${gw_mac}" == "00:00:00:00:00:00" ]]; then
    warn "Gateway MAC not detected automatically."
    prompt gw_mac "Enter gateway/router MAC (example: 40:71:83:c8:9b:a0)"
  fi

  write_watchdog

  local mode
  mode="$(env_get MODE)"

  if [[ -z "$mode" ]]; then
    echo
    log "Choose mode:"
    echo "  1) Outside Server  (server.yaml + run in screen)"
    echo "  2) Iran Client     (client.yaml + forward + run in screen)"
    echo
    local choice
    prompt choice "Enter 1 or 2" "1"
    [[ "$choice" == "1" ]] && mode="server" || mode="client"
  fi

  local screen_name
  screen_name="$(env_get SCREEN_NAME)"
  [[ -z "$screen_name" ]] && prompt screen_name "Screen session name" "$SCREEN_NAME_DEFAULT"

  local tunnel_port
  tunnel_port="$(env_get TUNNEL_PORT)"
  [[ -z "$tunnel_port" ]] && prompt tunnel_port "Tunnel port (listen)" "9999"

  local secret
  secret="$(env_get SECRET)"
  if [[ -z "$secret" ]]; then
    if [[ -n "$(env_get MODE)" ]]; then
      die "SECRET is required in ENV mode."
    fi
    prompt secret "Secret key (must match both sides)" "change-me-please"
  fi

  if [[ "$mode" == "server" ]]; then
    local public_ip_final
    public_ip_final="$(env_get PUBLIC_IP)"
    [[ -z "$public_ip_final" ]] && public_ip_final="$public_ip"
    [[ -z "$public_ip_final" ]] && prompt public_ip_final "Enter public IPv4 of THIS outside server"

    log "Copying FULL server example -> ${SERVER_YAML}"
    cp -f "${example_dir}/server.yaml.example" "$SERVER_YAML"
    ok "Copied full template: $SERVER_YAML"

    log "Applying ONLY requested edits to server.yaml..."
    set_interface_line "$SERVER_YAML" "$iface"
    set_server_listen_port "$SERVER_YAML" "$tunnel_port"
    set_server_ipv4_addr_public "$SERVER_YAML" "$public_ip_final" "$tunnel_port"
    set_router_mac_ipv4_only "$SERVER_YAML" "$gw_mac"
    comment_ipv6_block_server "$SERVER_YAML"
    set_secret_key "$SERVER_YAML" "$secret"
    ok "server.yaml ready."

    start_in_screen "$screen_name" "server" "$SERVER_YAML"
    install_cron_watchdog "server" "$screen_name" "$SERVER_YAML"

    ok "DONE (Outside Server)."

  elif [[ "$mode" == "client" ]]; then
    local outside_ip
    outside_ip="$(env_get OUTSIDE_IP)"
    if [[ -z "$outside_ip" ]]; then
      if [[ -n "$(env_get MODE)" ]]; then
        die "OUTSIDE_IP is required in ENV mode (client)."
      fi
      prompt outside_ip "Outside server PUBLIC IPv4"
    fi

    local service_port
    service_port="$(env_get SERVICE_PORT)"
    [[ -z "$service_port" ]] && prompt service_port "Service port to expose on Iran (0.0.0.0:PORT)" "8080"

    local local_ip_final
    local_ip_final="$(env_get LOCAL_IP)"
    [[ -z "$local_ip_final" ]] && local_ip_final="$local_ip"
    [[ -z "$local_ip_final" ]] && prompt local_ip_final "Enter local IPv4 of THIS Iran server (example: 192.168.1.100)"

    log "Copying FULL client example -> ${CLIENT_YAML}"
    cp -f "${example_dir}/client.yaml.example" "$CLIENT_YAML"
    ok "Copied full template: $CLIENT_YAML"

    log "Applying ONLY requested edits to client.yaml..."
    set_interface_line "$CLIENT_YAML" "$iface"
    set_client_ipv4_addr_local "$CLIENT_YAML" "$local_ip_final"
    set_router_mac_ipv4_only "$CLIENT_YAML" "$gw_mac"
    comment_ipv6_block_client "$CLIENT_YAML"
    disable_socks5_enable_forward_client "$CLIENT_YAML"
    set_forward_listen_target_client "$CLIENT_YAML" "$service_port" "$outside_ip"
    set_client_server_addr "$CLIENT_YAML" "$outside_ip" "$tunnel_port"
    set_secret_key "$CLIENT_YAML" "$secret"
    ok "client.yaml ready."

    start_in_screen "$screen_name" "client" "$CLIENT_YAML"
    install_cron_watchdog "client" "$screen_name" "$CLIENT_YAML"

    ok "DONE (Iran Client)."

  else
    die "Invalid MODE. Use MODE=server or MODE=client."
  fi

  ok "All steps completed successfully."
  ok "Install log:  $LOG_INSTALL"
  ok "Runtime log:  $LOG_RUNTIME"
}
main "$@"
