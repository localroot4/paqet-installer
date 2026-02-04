#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# Paqet Auto Installer/Configurator (Linux)
# - Keeps FULL original example YAML structure
# - Copies example/*.yaml.example to /root/*.yaml
# - Applies ONLY requested modifications
# - AUTO-detects CPU arch (amd64/arm64) and downloads correct release asset
# - Works with: curl ... | bash  (NO interactive prompts in pipe mode)
# - Interactive prompts ONLY when run from a real TTY (local file execution)
# - Runs inside GNU screen + watchdog (every 1 minute)
# - Logs to screen + /root/paqet-install.log + /root/paqet-runtime.log
# - Written by Atil (LR4) / localroot4
############################################

# ===== Hard init (prevents "unbound variable" with set -u) =====
: "${PAQET_VERSION:=v1.0.0-alpha.11}"
: "${MODE:=}"            # server | client
: "${TUNNEL_PORT:=}"
: "${SERVICE_PORT:=}"
: "${OUTSIDE_IP:=}"
: "${PUBLIC_IP:=}"
: "${LOCAL_IP:=}"
: "${SECRET:=}"
: "${SCREEN_NAME:=}"
: "${KEEP_SCREEN_OPEN:=1}"
: "${AUTO_START:=1}"
: "${AUTO_ATTACH:=1}"
: "${SKIP_PKG_INSTALL:=0}"
: "${CLIENT_COUNT:=1}"
: "${WATCHDOG:=1}"
: "${WATCHDOG_METHOD:=auto}"  # auto | cron | systemd
: "${FORCE_IPV6_DISABLE:=1}"

# ===== Paths =====
ROOT_DIR="/root"
LOG_INSTALL="${ROOT_DIR}/paqet-install.log"
LOG_RUNTIME="${ROOT_DIR}/paqet-runtime.log"
LOG_WATCHDOG="${ROOT_DIR}/paqet-watchdog.log"
EXTRACT_DIR="${ROOT_DIR}/paqet"
SERVER_YAML="${ROOT_DIR}/server.yaml"
CLIENT_YAML="${ROOT_DIR}/client.yaml"
WATCHDOG_SH="${ROOT_DIR}/paqet-watchdog.sh"

RELEASE_BASE="https://github.com/hanselime/paqet/releases/download/${PAQET_VERSION}"

# ===== Pretty logs =====
ts() { date +"%Y-%m-%d %H:%M:%S"; }
C_RED="\033[0;31m"; C_GRN="\033[0;32m"; C_YLW="\033[1;33m"; C_CYN="\033[0;36m"; C_RST="\033[0m"
log()  { echo -e "$(ts) ${C_CYN}[LOG]${C_RST} $*" | tee -a "$LOG_INSTALL"; }
ok()   { echo -e "$(ts) ${C_GRN}[OK]${C_RST}  $*" | tee -a "$LOG_INSTALL"; }
warn() { echo -e "$(ts) ${C_YLW}[WARN]${C_RST} $*" | tee -a "$LOG_INSTALL"; }
err()  { echo -e "$(ts) ${C_RED}[ERR]${C_RST} $*" | tee -a "$LOG_INSTALL" >&2; }
loge() { echo -e "$(ts) ${C_CYN}[LOG]${C_RST} $*" | tee -a "$LOG_INSTALL" >&2; }
oke()  { echo -e "$(ts) ${C_GRN}[OK]${C_RST}  $*" | tee -a "$LOG_INSTALL" >&2; }
warne(){ echo -e "$(ts) ${C_YLW}[WARN]${C_RST} $*" | tee -a "$LOG_INSTALL" >&2; }
die()  { err "$*"; exit 1; }

on_error() {
  local code=$?
  local line="${1:-unknown}"
  err "Installer failed (exit code: $code)."
  err "Failed command: ${BASH_COMMAND}"
  err "At line: ${line}"
  err "Last 200 install log lines:"
  tail -n 200 "$LOG_INSTALL" 2>/dev/null || true
  exit "$code"
}
trap 'on_error $LINENO' ERR

need_root() { [[ "${EUID}" -eq 0 ]] || die "Run as root. (sudo -i)"; }
is_pipe_mode() { [[ ! -t 0 ]]; }
has_tty() { [[ -t 0 && -t 1 ]]; }

# ===== Strict rule: NO prompts in pipe mode =====
require_env_in_pipe() {
  if is_pipe_mode; then
    [[ -n "${MODE:-}" ]]   || die "PIPE mode detected. Set MODE=server or MODE=client (no prompts in pipe mode)."
    [[ -n "${SECRET:-}" ]] || die "PIPE mode detected. Set SECRET='...' (no prompts in pipe mode)."
    if [[ "${MODE}" == "client" ]]; then
      [[ -n "${OUTSIDE_IP:-}" ]] || die "MODE=client requires OUTSIDE_IP='x.x.x.x' in pipe mode."
    fi
  fi
}

prompt() {
  local __var="$1" __text="$2" __def="${3:-}" __val=""
  has_tty || die "Interactive prompt requested but no TTY. Use ENV vars."
  if [[ -n "$__def" ]]; then
    read -r -p "$__text [$__def]: " __val || true
    __val="${__val:-$__def}"
  else
    read -r -p "$__text: " __val || true
  fi
  printf -v "$__var" "%s" "$__val"
}

ensure_unique_value() {
  local value="$1" label="$2" list="$3"
  local item
  for item in $list; do
    [[ "$item" == "$value" ]] && die "${label} must be unique. '${value}' is already used."
  done
}

get_indexed_value() {
  local base="$1" idx="$2" prompt_text="$3" default_val="$4" out_var="$5"
  local var_name="$base"
  [[ "$idx" -gt 1 ]] && var_name="${base}_${idx}"
  local value="${!var_name:-}"
  if [[ -z "$value" ]]; then
    if has_tty; then
      prompt value "$prompt_text" "$default_val"
    else
      if [[ -n "$default_val" ]]; then
        value="$default_val"
      else
        die "Missing ${var_name} in pipe mode."
      fi
    fi
  fi
  printf -v "$out_var" "%s" "$value"
}

# ===== Arch detect + stable BIN path =====
detect_arch() {
  local a=""
  a="$(dpkg --print-architecture 2>/dev/null || true)"
  [[ -n "$a" ]] || a="$(uname -m 2>/dev/null || echo unknown)"
  case "$a" in
    amd64|x86_64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    armhf|armv7l) echo "armhf" ;;
    *) echo "$a" ;;
  esac
}
ARCH="$(detect_arch)"
BIN_LOCAL="${ROOT_DIR}/paqet_linux_${ARCH}"

# ===== Package manager helpers =====
detect_pkg_manager() {
  local mgr=""
  for mgr in apt-get dnf yum apk pacman zypper; do
    command -v "$mgr" >/dev/null 2>&1 && { echo "$mgr"; return 0; }
  done
  echo ""
}

# APT resiliency (Hetzner ARM mirror 404 fix)
apt_fix_sources_if_needed() {
  [[ "$ARCH" == "arm64" || "$ARCH" == "armhf" ]] || return 0

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
    warn "ARM detected; adjusted Hetzner sources to ubuntu-ports to avoid 404."
  fi
}

apt_update_retry() {
  export DEBIAN_FRONTEND=noninteractive
  local tries=3
  for i in $(seq 1 $tries); do
    log "apt update... (try $i/$tries)"
    set +e
    apt-get update -y 2>&1 | tee -a "$LOG_INSTALL" >/dev/null
    local rc=${PIPESTATUS[0]}
    set -e
    if [[ "$rc" -eq 0 ]]; then
      return 0
    fi
    warn "apt update failed (rc=$rc). Fixing sources + retry..."
    apt_fix_sources_if_needed
    sleep $((i*2))
  done
  return 1
}

install_packages() {
  local mgr="$1"
  if [[ -z "$mgr" ]]; then
    warn "No supported package manager found; skipping dependency install."
    return 0
  fi
  case "$mgr" in
    apt-get)
      export DEBIAN_FRONTEND=noninteractive
      apt_fix_sources_if_needed
      apt_update_retry || die "apt update failed. Check sources/network."
      log "Installing packages (apt): wget curl screen net-tools iproute2 ping perl file tar procps..."
      apt-get install -y wget curl ca-certificates screen net-tools iproute2 iputils-ping perl file tar procps \
        2>&1 | tee -a "$LOG_INSTALL" >/dev/null
      ;;
    dnf)
      log "Installing packages (dnf): wget curl screen net-tools iproute iputils perl file tar procps-ng..."
      dnf -y install wget curl ca-certificates screen net-tools iproute iputils perl file tar procps-ng \
        2>&1 | tee -a "$LOG_INSTALL" >/dev/null
      ;;
    yum)
      log "Installing packages (yum): wget curl screen net-tools iproute iputils perl file tar procps-ng..."
      yum -y install wget curl ca-certificates screen net-tools iproute iputils perl file tar procps-ng \
        2>&1 | tee -a "$LOG_INSTALL" >/dev/null
      ;;
    apk)
      log "Installing packages (apk): wget curl screen net-tools iproute2 iputils perl file tar procps..."
      apk add --no-cache wget curl ca-certificates screen net-tools iproute2 iputils perl file tar procps \
        2>&1 | tee -a "$LOG_INSTALL" >/dev/null
      ;;
    pacman)
      log "Installing packages (pacman): wget curl screen net-tools iproute2 iputils perl file tar procps-ng..."
      pacman -Sy --noconfirm wget curl ca-certificates screen net-tools iproute2 iputils perl file tar procps-ng \
        2>&1 | tee -a "$LOG_INSTALL" >/dev/null
      ;;
    zypper)
      log "Installing packages (zypper): wget curl screen net-tools iproute2 iputils perl file tar procps..."
      zypper --non-interactive install wget curl ca-certificates screen net-tools iproute2 iputils perl file tar procps \
        2>&1 | tee -a "$LOG_INSTALL" >/dev/null
      ;;
    *)
      warn "Unsupported package manager: ${mgr}. Install dependencies manually: curl, wget, screen, iproute2, iputils/ping, perl, file, tar, procps/pgrep."
      return 0
      ;;
  esac
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

# ===== Download logic =====
download_with_retry() {
  local url="$1" out="$2"
  local tries=5 wait=2
  for i in $(seq 1 $tries); do
    loge "Downloading ($i/$tries): $url"
    if wget -q --show-progress --timeout=20 --tries=2 "$url" -O "$out"; then
      oke "Downloaded: $out"
      return 0
    fi
    warne "Download failed. Retry in ${wait}s..."
    sleep "$wait"
    wait=$((wait*2))
  done
  return 1
}

download_release_tarball() {
  mkdir -p "$ROOT_DIR"
  local v="${PAQET_VERSION}"
  local vnv="${PAQET_VERSION#v}"

  local candidates=(
    "paqet-linux-${ARCH}-${v}.tar.gz"
    "paqet-linux-${ARCH}-v${vnv}.tar.gz"
    "paqet-linux-${ARCH}-${vnv}.tar.gz"
    "paqet-linux-${ARCH}-${v}.tgz"
    "paqet-linux-${ARCH}-v${vnv}.tgz"
    "paqet-linux-${ARCH}-${vnv}.tgz"
  )

  if [[ "$ARCH" == "arm64" ]]; then
    candidates+=(
      "paqet-linux-aarch64-${v}.tar.gz"
      "paqet-linux-aarch64-v${vnv}.tar.gz"
      "paqet-linux-aarch64-${vnv}.tar.gz"
    )
  fi

  local out=""
  for name in "${candidates[@]}"; do
    local url="${RELEASE_BASE}/${name}"
    out="${ROOT_DIR}/${name}"
    if [[ -f "$out" ]]; then
      warne "Tarball already exists: $out"
      echo "$out"
      return 0
    fi
    if download_with_retry "$url" "$out"; then
      echo "$out"
      return 0
    fi
  done

  die "Could not download tarball for ARCH=${ARCH}. Check release assets or set PAQET_VERSION."
}

extract_and_prepare_binary() {
  local tarball="$1"
  mkdir -p "$EXTRACT_DIR"
  log "Extracting tarball to: $EXTRACT_DIR"
  tar zxvf "$tarball" -C "$EXTRACT_DIR" 2>&1 | tee -a "$LOG_INSTALL" >/dev/null
  ok "Extract done."

  log "Searching for paqet binary in extracted files..."
  local found=""
  found="$(find "$EXTRACT_DIR" -maxdepth 5 -type f -name "paqet*" 2>/dev/null | head -n1 || true)"
  [[ -n "$found" ]] || die "Could not find paqet binary in extracted folder."

  cp -f "$found" "$BIN_LOCAL"
  chmod +x "$BIN_LOCAL"

  local finfo
  finfo="$(file "$BIN_LOCAL" 2>/dev/null || true)"
  log "Binary file(): ${finfo}"

  if [[ "$ARCH" == "arm64" ]] && echo "$finfo" | grep -qi "x86-64"; then
    die "Wrong binary (x86-64) on arm64. Release asset naming mismatch."
  fi
  if [[ "$ARCH" == "amd64" ]] && echo "$finfo" | grep -qiE "aarch64|ARM aarch64"; then
    die "Wrong binary (arm64) on amd64. Release asset naming mismatch."
  fi

  ok "Binary ready: $BIN_LOCAL (ARCH=$ARCH)"
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

# ===== YAML edits =====
set_interface_line() {
  local file="$1" iface="$2"
  sed -i "s/^\([[:space:]]*interface:[[:space:]]*\)\"[^\"]*\"/\1\"${iface}\"/" "$file"
}

set_router_mac_all_occurrences() {
  local file="$1" mac="$2"
  perl -0777 -i -pe "s/router_mac: \"[^\"]*\"/router_mac: \"$mac\"/g" "$file"
}

comment_ipv6_block_requested_style() {
  local file="$1"
  perl -i -pe '
    if (/^\s*ipv6:/) { $in=1; s/^(\s*)ipv6:/$1#ipv6:/; next; }
    if ($in && /^\s*addr:/) { s/^(\s*)addr:/$1#addr:/; next; }
    if ($in && /^\s*router_mac:/) { s/^(\s*)router_mac:/$1#router_mac:/; $in=0; next; }
    if ($in && /^\s*\S/ && !/^\s*#/) { $in=0; }
  ' "$file"
}

set_server_listen_port() {
  local file="$1" port="$2"
  sed -i -E "s/^([[:space:]]*)#?[[:space:]]*addr:[[:space:]]*\":[0-9]+\"/\1addr: \":${port}\"/" "$file"
}

set_server_ipv4_addr_public() {
  local file="$1" ip="$2" port="$3"
  sed -i "s/\"10\.0\.0\.100:9999\"/\"${ip}:${port}\"/" "$file"
  perl -0777 -i -pe "s/(ipv4:\\n\\s+addr: )\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+\"/\\1\"${ip}:${port}\"/s" "$file"
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
  perl -0777 -i -pe "s/(server:\\n\\s+addr: )\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+\"/\\1\"${outside_ip}:${tunnel_port}\"/s" "$file"
}

set_forward_listen_target_client() {
  local file="$1" service_port="$2" outside_ip="$3"
  sed -i "s/\"127\.0\.0\.1:8080\"/\"0.0.0.0:${service_port}\"/" "$file"
  sed -i "s/\"127\.0\.0\.1:80\"/\"${outside_ip}:${service_port}\"/" "$file"
}

# ===== screen runner =====
screen_exists() { local name="$1"; screen -ls 2>/dev/null | grep -q "[[:space:]]${name}[[:space:]]"; }

start_in_screen() {
  local mode="$1" cfg="$2" screen_name="$3"
  screen -wipe >/dev/null 2>&1 || true
  : >> "$LOG_RUNTIME"

  if screen_exists "$screen_name"; then
    warn "Screen session already exists: ${screen_name} (not starting a second one)"
    return 0
  fi

  log "Starting paqet in screen session: ${screen_name}"
  log "Command: ${BIN_LOCAL} run -c ${cfg}"
  screen -dmS "$screen_name" bash -lc "
    cd '$ROOT_DIR'
    echo '--- $(ts) START ${mode} ---' >> '$LOG_RUNTIME'
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y libpcap-dev >/dev/null 2>&1 || true
    fi
    chmod +x '$BIN_LOCAL'
    '$BIN_LOCAL' run -c '$cfg' 2>&1 | tee -a '$LOG_RUNTIME'
    echo '--- $(ts) STOP ${mode} (process ended) ---' >> '$LOG_RUNTIME'
    if [[ '${KEEP_SCREEN_OPEN}' == '1' ]]; then
      echo 'Process ended. Keeping screen open for debugging...' | tee -a '$LOG_RUNTIME'
      exec bash
    fi
    sleep 2
  "
  ok "Screen started. Attach: screen -r ${screen_name}"
}

# ===== watchdog =====
write_watchdog_script() {
  cat > "$WATCHDOG_SH" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
MODE="${1:-}"; SCREEN_NAME="${2:-}"; BIN="${3:-}"; CFG="${4:-}"
RUNTIME_LOG="${5:-/root/paqet-runtime.log}"
WD_LOG="${6:-/root/paqet-watchdog.log}"
ts(){ date +"%Y-%m-%d %H:%M:%S"; }
wlog(){ echo "$(ts) [WD] $*" >> "$WD_LOG"; }
screen_exists(){ screen -ls 2>/dev/null | grep -q "[[:space:]]${SCREEN_NAME}[[:space:]]"; }
proc_running(){ pgrep -fa "${BIN} run -c ${CFG}" >/dev/null 2>&1; }
killed_tail(){ tail -n 10 "$RUNTIME_LOG" 2>/dev/null | grep -qiE "(killed|out of memory|oom)"; }

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
  if proc_running; then exit 0; fi
  if killed_tail; then wlog "Detected killed/OOM."; restart; exit 0; fi
  if ! screen_exists; then wlog "Screen missing."; restart; exit 0; fi
  wlog "Process not running. Restarting."; restart
}
main
EOF
  chmod +x "$WATCHDOG_SH"
  ok "Watchdog script ready: $WATCHDOG_SH"
}

install_watchdog_systemd() {
  local cfg="$1" screen_name="$2"
  local unit="paqet-watchdog-${screen_name}"
  cat > "/etc/systemd/system/${unit}.service" <<EOF
[Unit]
Description=Paqet Watchdog (LR4) ${screen_name}
After=network.target
[Service]
Type=oneshot
ExecStart=${WATCHDOG_SH} ${MODE} ${screen_name} ${BIN_LOCAL} ${cfg} ${LOG_RUNTIME} ${LOG_WATCHDOG}
EOF

  cat > "/etc/systemd/system/${unit}.timer" <<EOF
[Unit]
Description=Run Paqet Watchdog every 1 minute (${screen_name})
[Timer]
OnBootSec=30
OnUnitActiveSec=60
AccuracySec=5
[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${unit}.timer" >/dev/null 2>&1 || true
  ok "Watchdog enabled via systemd timer (${screen_name})."
}

install_watchdog_cron() {
  local cfg="$1" screen_name="$2"
  local line="* * * * * ${WATCHDOG_SH} ${MODE} ${screen_name} ${BIN_LOCAL} ${cfg} ${LOG_RUNTIME} ${LOG_WATCHDOG}"
  ( crontab -l 2>/dev/null | grep -v "${WATCHDOG_SH} ${MODE} ${screen_name}" || true; echo "$line" ) | crontab -
  ok "Watchdog enabled via cron (every 1 minute) for ${screen_name}."
}

install_watchdog() {
  local cfg="$1" screen_name="$2"
  [[ "${WATCHDOG}" == "1" ]] || { warn "WATCHDOG=0 (skipped)"; return 0; }
  write_watchdog_script
  if [[ "${WATCHDOG_METHOD}" == "systemd" ]]; then install_watchdog_systemd "$cfg" "$screen_name"; return 0; fi
  if [[ "${WATCHDOG_METHOD}" == "cron" ]]; then install_watchdog_cron "$cfg" "$screen_name"; return 0; fi
  if command -v systemctl >/dev/null 2>&1; then install_watchdog_systemd "$cfg" "$screen_name" || install_watchdog_cron "$cfg" "$screen_name"
  else install_watchdog_cron "$cfg" "$screen_name"
  fi
}

main() {
  : > "$LOG_INSTALL"; : >> "$LOG_RUNTIME"; : >> "$LOG_WATCHDOG"
  need_root

  log "==== Paqet Installer Started ===="
  log "Version: ${PAQET_VERSION}"
  log "Arch   : ${ARCH}"
  log "Binary : ${BIN_LOCAL}"
  log "Install log : ${LOG_INSTALL}"
  log "Runtime log : ${LOG_RUNTIME}"
  log "Input mode  : $(is_pipe_mode && echo 'PIPE (ENV required)' || echo 'TTY (interactive allowed)')"

  require_env_in_pipe

  if ! is_pipe_mode; then
    if [[ -z "${MODE:-}" ]]; then
      log "Choose mode:"
      echo "  1) Outside Server  (server.yaml + run in screen)"
      echo "  2) Iran Client     (client.yaml + forward + run in screen)"
      echo
      local choice
      prompt choice "Enter 1 or 2" "1"
      [[ "$choice" == "1" ]] && MODE="server" || MODE="client"
    fi

    [[ -n "${SECRET:-}" ]] || prompt SECRET "Secret key (must match both sides)" "change-me-please"

    if [[ "${MODE}" == "server" ]]; then
      if [[ -z "${TUNNEL_PORT:-}" ]]; then
        prompt TUNNEL_PORT "Tunnel port" "9999"
      fi
      if [[ -z "${SCREEN_NAME:-}" ]]; then
        prompt SCREEN_NAME "Screen session name" "LR4-paqet"
      fi
    fi

    if [[ "${MODE}" == "client" ]]; then
      if [[ -z "${CLIENT_COUNT:-}" ]]; then
        prompt CLIENT_COUNT "How many Iran clients? (1-3)" "1"
      fi
    fi
  fi

  # ---- VALIDATION (safe with set -u) ----
  TUNNEL_PORT="${TUNNEL_PORT:-9999}"
  SERVICE_PORT="${SERVICE_PORT:-8080}"
  SCREEN_NAME="${SCREEN_NAME:-LR4-paqet}"
  CLIENT_COUNT="${CLIENT_COUNT:-1}"
  log "Validating inputs..."
  [[ "${MODE:-}" == "server" || "${MODE:-}" == "client" ]] || die "Invalid MODE. Use server/client."
  [[ -n "${SECRET:-}" ]] || die "SECRET is required."
  if [[ "${MODE}" == "client" ]]; then
    [[ "$CLIENT_COUNT" =~ ^[1-3]$ ]] || die "CLIENT_COUNT must be 1-3."
  fi
  ok "Inputs OK. (MODE=${MODE}, TUNNEL_PORT=${TUNNEL_PORT}, SERVICE_PORT=${SERVICE_PORT})"

  local pkg_mgr detect_rc
  log "Detecting package manager..."
  set +e
  pkg_mgr="$(detect_pkg_manager 2>/dev/null)"
  detect_rc=$?
  set -e
  log "Detected package manager: ${pkg_mgr:-none} (rc=${detect_rc})"
  if [[ "${SKIP_PKG_INSTALL}" == "1" ]]; then
    warn "SKIP_PKG_INSTALL=1 (skipping dependency install)."
  else
    install_packages "$pkg_mgr"
  fi

  local tarball; tarball="$(download_release_tarball)"
  extract_and_prepare_binary "$tarball"

  local example_dir; example_dir="$(find_example_dir)"
  [[ -n "$example_dir" ]] || die "Could not find example directory."
  ok "Found example dir: $example_dir"

  log "Detecting network info..."
  local iface gw gw_mac local_ip public_ip
  iface="$(get_default_if)"; gw="$(get_gateway_ip)"
  [[ -n "$iface" ]] || die "No default interface detected. (ip r)"
  [[ -n "$gw" ]]    || die "No default gateway detected. (ip r)"

  gw_mac="$(get_gateway_mac "$gw" || true)"
  local_ip="$(get_local_ipv4 "$iface" || true)"
  public_ip="$(get_public_ipv4 || true)"

  log "Detected:"
  log "  interface  = ${iface}"
  log "  gateway    = ${gw}"
  log "  gatewayMAC = ${gw_mac:-UNKNOWN}"
  log "  localIPv4  = ${local_ip:-UNKNOWN}"
  log "  publicIPv4 = ${public_ip:-UNKNOWN}"
  [[ -n "$gw_mac" ]] || die "Gateway MAC not detected automatically."

  if [[ "$MODE" == "server" ]]; then
    local ip_final="${PUBLIC_IP:-$public_ip}"
    [[ -n "$ip_final" ]] || die "Public IPv4 not detected. Set PUBLIC_IP='x.x.x.x'."

    log "Copying FULL server example -> ${SERVER_YAML}"
    cp -f "${example_dir}/server.yaml.example" "$SERVER_YAML"
    ok "Copied full template: $SERVER_YAML"

    log "Applying requested edits to server.yaml..."
    set_interface_line "$SERVER_YAML" "$iface"
    set_server_listen_port "$SERVER_YAML" "$TUNNEL_PORT"
    set_server_ipv4_addr_public "$SERVER_YAML" "$ip_final" "$TUNNEL_PORT"
    set_router_mac_all_occurrences "$SERVER_YAML" "$gw_mac"
    [[ "$FORCE_IPV6_DISABLE" == "1" ]] && comment_ipv6_block_requested_style "$SERVER_YAML"
    set_secret_key "$SERVER_YAML" "$SECRET"
    ok "server.yaml ready."

    if [[ "$AUTO_START" == "1" ]]; then
      start_in_screen "server" "$SERVER_YAML" "$SCREEN_NAME"
      install_watchdog "$SERVER_YAML" "$SCREEN_NAME"
    fi

    ok "DONE (Outside Server)."
    log "Config      : $SERVER_YAML"
    log "Attach      : screen -r ${SCREEN_NAME}"
    log "Runtime log : $LOG_RUNTIME"
    log "Watchdog log: $LOG_WATCHDOG"
    if has_tty && [[ "${AUTO_ATTACH}" == "1" ]]; then
      log "Auto-attaching to screen session: ${SCREEN_NAME}"
      screen -r "${SCREEN_NAME}"
    fi
    exit 0
  fi

  # MODE=client
  local lip_final="${LOCAL_IP:-$local_ip}"
  [[ -n "$lip_final" ]] || die "Local IPv4 not detected. Set LOCAL_IP='x.x.x.x'."

  local used_tunnel_ports="" used_service_ports="" used_screen_names=""
  local i
  for i in $(seq 1 "$CLIENT_COUNT"); do
    local outside_ip_i tunnel_port_i service_port_i screen_name_i secret_i
    local client_yaml_i

    if [[ "$i" -eq 1 ]]; then
      client_yaml_i="$CLIENT_YAML"
    else
      client_yaml_i="${ROOT_DIR}/client${i}.yaml"
    fi

    get_indexed_value "OUTSIDE_IP" "$i" "Outside server PUBLIC IPv4 (client ${i})" "" outside_ip_i
    get_indexed_value "TUNNEL_PORT" "$i" "Tunnel port (client ${i})" "9999" tunnel_port_i
    get_indexed_value "SERVICE_PORT" "$i" "Service port to expose (client ${i}, 0.0.0.0:PORT)" "8080" service_port_i

    local screen_default="LR4-paqet"
    [[ "$i" -gt 1 ]] && screen_default="LR4-paqet-${i}"
    get_indexed_value "SCREEN_NAME" "$i" "Screen session name (client ${i})" "$screen_default" screen_name_i

    secret_i="$SECRET"
    if [[ "$i" -gt 1 ]]; then
      local secret_var="SECRET_${i}"
      [[ -n "${!secret_var:-}" ]] && secret_i="${!secret_var}"
    fi

    ensure_unique_value "$tunnel_port_i" "Tunnel port" "$used_tunnel_ports"
    used_tunnel_ports="${used_tunnel_ports} ${tunnel_port_i}"
    ensure_unique_value "$service_port_i" "Service port" "$used_service_ports"
    used_service_ports="${used_service_ports} ${service_port_i}"
    ensure_unique_value "$screen_name_i" "Screen name" "$used_screen_names"
    used_screen_names="${used_screen_names} ${screen_name_i}"

    log "Copying FULL client example -> ${client_yaml_i}"
    cp -f "${example_dir}/client.yaml.example" "$client_yaml_i"
    ok "Copied full template: $client_yaml_i"

    log "Applying requested edits to client${i}.yaml..."
    set_interface_line "$client_yaml_i" "$iface"
    set_client_ipv4_addr_local "$client_yaml_i" "$lip_final"
    set_router_mac_all_occurrences "$client_yaml_i" "$gw_mac"
    [[ "$FORCE_IPV6_DISABLE" == "1" ]] && comment_ipv6_block_requested_style "$client_yaml_i"
    disable_socks5_enable_forward_client "$client_yaml_i"
    set_forward_listen_target_client "$client_yaml_i" "$service_port_i" "$outside_ip_i"
    set_client_server_addr "$client_yaml_i" "$outside_ip_i" "$tunnel_port_i"
    set_secret_key "$client_yaml_i" "$secret_i"
    ok "client${i}.yaml ready."

    if [[ "$AUTO_START" == "1" ]]; then
      start_in_screen "client" "$client_yaml_i" "$screen_name_i"
      install_watchdog "$client_yaml_i" "$screen_name_i"
    fi

    ok "DONE (Iran Client ${i})."
    log "Config      : $client_yaml_i"
    log "Attach      : screen -r ${screen_name_i}"
    log "Runtime log : $LOG_RUNTIME"
    log "Watchdog log: $LOG_WATCHDOG"
    if has_tty && [[ "${AUTO_ATTACH}" == "1" ]]; then
      log "Auto-attaching to screen session: ${screen_name_i}"
      screen -r "${screen_name_i}"
    fi
  done
}
main "$@"
