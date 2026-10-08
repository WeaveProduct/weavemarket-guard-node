#!/usr/bin/env bash
# =============================================================================
#  node-guard.sh — защита ноды Remnawave
#
#   1. Аудит открытых портов (ss) и опубликованных портов Docker
#   2. UFW: SSH и VPN-порты — для всех, порт ноды — только с IP панели
#   3. fail2ban: SSH + recidive, IP панели в белом списке
#   4. Уведомления в Telegram (по желанию): отчёт, баны fail2ban, входы по SSH
#   5. Разбор портов Docker, которые идут в обход UFW, и как их закрыть
#
#  Запуск:
#    sudo bash node-guard.sh                      # интерактивно
#    sudo bash node-guard.sh --audit              # только проверка, без изменений
#    sudo bash node-guard.sh --panel-ip 1.2.3.4 --node-port 2222 --ports 443/tcp -y
#    sudo bash node-guard.sh ... --tg-token 123:AA... --tg-id 123456789 -y
#
#  Debian 11+ / Ubuntu 20.04+
# =============================================================================
set -uo pipefail
export LC_ALL=C LANG=C   # стабильный вывод ufw/ss/fail2ban независимо от локали
shopt -u patsub_replacement 2>/dev/null || true   # bash 5.2+: «&» в ${x//a/b} — не подстановка

readonly VERSION="1.1.0"
readonly F2B_JAIL="/etc/fail2ban/jail.d/node-guard.local"
readonly TG_CONF="/etc/node-guard/telegram.conf"
readonly NOTIFY_BIN="/usr/local/bin/node-guard-notify"
readonly F2B_TG_ACTION="/etc/fail2ban/action.d/node-guard-telegram.conf"
readonly PAM_SSHD="/etc/pam.d/sshd"
readonly RB_UNIT="node-guard-rollback-$$"

# Процессы, чьи публичные порты предлагается открыть для всех
readonly VPN_PROC_RE='^(xray|rw-core|v2ray|sing-box|hysteria|hysteria2|tuic-server|naive|caddy|nginx|angie|haproxy|trojan|trojan-go|ocserv|openvpn|telemt|mtg|mtproto-proxy|mtprotoproxy|gost|ss-server|ssserver|wstunnel)$'
# DHCP-клиенты: ответы им UFW пропускает сам
readonly DHCP_RE='^(dhclient|dhcpcd|systemd-network|systemd-networkd|NetworkManager)$'

# ── параметры (можно задать флагами) ─────────────────────────────────────────
PANEL_IPS=""      # IP панели, через запятую
NODE_PORT=""      # порт ноды (NODE_PORT / APP_PORT в remnanode), обычно 2222
VPN_PORTS=""      # порты для всех: 443,8443,80/tcp,2053/udp,10000:10100/tcp
SSH_PORTS=""      # пусто — определить автоматически
RESET_UFW=""      # yes | no | "" — спросить
ASSUME_YES=0
AUDIT_ONLY=0
SKIP_F2B=0
NO_ROLLBACK=0
ROLLBACK_SEC=180
TG_TOKEN=""       # токен бота от @BotFather
TG_CHAT_ID=""     # USER_ID в Telegram (или ID группы, с минусом)
TG_NODE_NAME=""   # подпись ноды в уведомлениях, по умолчанию hostname
TG_API="https://api.telegram.org"
TG_NOTIFY_BANS=1
TG_NOTIFY_LOGINS=1
TG_DISABLE=0

# ── состояние ────────────────────────────────────────────────────────────────
L_PROTO=(); L_PORT=(); L_PROC=(); L_SCOPE=(); L_ADDR=()   # scope: 1 lo, 2 LAN, 3 наружу, 4 Docker
D_HOST=(); D_LOCAL=(); D_EXP=()
declare -A DOCKER_PORTS=()
DOCKER_OK=0; REMNANODE=""; NODE_PORT_DET=""
SSH_ARR=(); PANEL_ARR=(); VPN_ARR=(); CLOSED=()
APT_UPDATED=0; RB_MODE=""; RB_PID=""; F2B_OK=0; SEC=0
TG_ENABLED=0; TG_REMOVE=0; TG_ERR=""
NL=$'\n'

# ── вывод ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' B=$'\e[34m' C=$'\e[36m' BD=$'\e[1m' DIM=$'\e[2m' N=$'\e[0m'
else
  R='' G='' Y='' B='' C='' BD='' DIM='' N=''
fi
say()  { printf '%s\n' "$*"; }
info() { printf '%s[i]%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$Y" "$N" "$*"; }
err()  { printf '%s[✗]%s %s\n' "$R" "$N" "$*" >&2; }
die()  { err "$*"; exit 1; }
hdr()  { printf '\n%s%s━━ %s%s\n' "$BD" "$C" "$*" "$N"; }
step() { SEC=$((SEC + 1)); hdr "$SEC. $*"; }
html() { local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; printf '%s' "$s"; }
sq()   { printf "'%s'" "${1//\'/\'\\\'\'}"; }
yn()   { if (( $1 )); then printf 'да'; else printf 'нет'; fi; }
join() { local sep=$1 out="" x; shift; for x in "$@"; do out+="${out:+$sep}$x"; done; printf '%s' "$out"; }
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }
in_list() { local x=$1 y; shift; for y in "$@"; do [[ $x == "$y" ]] && return 0; done; return 1; }
split_list() { tr ', ;' '\n\n\n' <<<"$1" | sed '/^$/d'; }

# ── ввод (работает и при запуске через curl | bash) ───────────────────────────
HAVE_TTY=0
if [[ -t 0 ]] || { : </dev/tty; } 2>/dev/null; then HAVE_TTY=1; fi
noninteractive() { (( ASSUME_YES || !HAVE_TTY )); }

ask() {   # ask "вопрос" "по умолчанию"  → $REPLY
  local q=$1 def=${2:-} a
  REPLY=$def
  noninteractive && return 0
  if [[ -n $def ]]; then printf '%s?%s %s [%s%s%s]: ' "$C" "$N" "$q" "$BD" "$def" "$N" >/dev/tty
  else printf '%s?%s %s: ' "$C" "$N" "$q" >/dev/tty; fi
  IFS= read -r a </dev/tty || a=""
  a=$(trim "$a")
  [[ -n $a ]] && REPLY=$a
  return 0
}

confirm() {   # confirm "вопрос" Y|N
  local q=$1 def=${2:-N} a hint="[y/N]"
  if noninteractive; then [[ $def == Y ]]; return; fi
  [[ $def == Y ]] && hint="[Y/n]"
  while :; do
    printf '%s?%s %s %s: ' "$C" "$N" "$q" "$hint" >/dev/tty
    IFS= read -r a </dev/tty || a=""
    a=$(trim "$a"); [[ -z $a ]] && a=$def
    case ${a,,} in
      y|yes|д|да|Д|Да|ДА) return 0 ;;
      n|no|н|нет|Н|Нет|НЕТ) return 1 ;;
    esac
  done
}

# ── валидация ────────────────────────────────────────────────────────────────
is_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

valid_ip() {
  local ip=${1%/*} mask="" o
  [[ $1 == */* ]] && mask=${1#*/}
  if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
    [[ -z $mask ]] && return 0
    [[ $mask =~ ^[0-9]{1,2}$ ]] && (( 10#$mask <= 32 ))
  elif [[ $ip == *:* && $ip =~ ^[0-9a-fA-F:.]+$ ]]; then
    [[ -z $mask ]] && return 0
    [[ $mask =~ ^[0-9]{1,3}$ ]] && (( 10#$mask <= 128 ))
  else
    return 1
  fi
}

is_private_ip() { [[ $1 =~ ^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|f[cd]|fe80) ]]; }

# Нормализует «443», «443/tcp», «10000:10100/udp» (или 10000-10100/udp)
norm_item() {
  local it=${1,,} proto="" ports a b
  if [[ $it == */* ]]; then
    proto=${it##*/}; ports=${it%/*}
    [[ $proto == tcp || $proto == udp ]] || return 1
  else
    ports=$it
  fi
  if [[ $ports == *[-:]* ]]; then
    ports=${ports/-/:}; a=${ports%%:*}; b=${ports##*:}
    { is_port "$a" && is_port "$b"; } || return 1
    a=$((10#$a)); b=$((10#$b))
    { (( a < b )) && [[ -n $proto ]]; } || return 1
    printf '%s:%s/%s' "$a" "$b" "$proto"
  else
    is_port "$ports" || return 1
    printf '%s%s' "$((10#$ports))" "${proto:+/$proto}"
  fi
}

# Покрывает ли список правил (443, 443/tcp, 1000:2000/udp) порт proto/port
port_in_items() {
  local proto=$1 port=$2 it p pr; shift 2
  for it in "$@"; do
    if [[ $it == */* ]]; then pr=${it##*/}; p=${it%/*}; else pr=""; p=$it; fi
    [[ -n $pr && $pr != "$proto" ]] && continue
    if [[ $p == *:* ]]; then
      (( port >= ${p%%:*} && port <= ${p##*:} )) && return 0
    else
      (( port == p )) && return 0
    fi
  done
  return 1
}

# ── сбор данных ──────────────────────────────────────────────────────────────
read -r -d '' AWK_LISTEN <<'AWK'
function scope(a) {
  if (a ~ /^127\./ || a == "::1" || a ~ /^::ffff:127\./) return 1
  if (a ~ /^(10|169\.254|192\.168)\./ || a ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ ||
      a ~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./ || a ~ /^f[cd]/ || a ~ /^fe80/) return 2
  return 3
}
{
  loc = ""; proc = "-"
  for (i = 1; i <= NF; i++) if ($i ~ /:[0-9]+$/) { loc = $i; break }
  if (loc == "") next
  for (i = 1; i <= NF; i++) if (match($i, /\(\("[^"]+"/)) { proc = substr($i, RSTART + 3, RLENGTH - 4); break }
  n = split(loc, p, ":"); port = p[n]
  addr = substr(loc, 1, length(loc) - length(port) - 1)
  gsub(/\[|\]/, "", addr); sub(/%.*/, "", addr)
  if (addr == "") addr = "*"
  k = port SUBSEP proc
  s = scope(addr)
  if (!(k in sc) || s > sc[k]) sc[k] = s
  if (index("," ad[k] ",", "," addr ",") == 0) ad[k] = (ad[k] == "" ? addr : ad[k] "," addr)
}
END { for (k in sc) { split(k, f, SUBSEP); print proto "|" f[1] "|" f[2] "|" sc[k] "|" ad[k] } }
AWK

collect_listeners() {
  local proto port proc scope addr
  while IFS='|' read -r proto port proc scope addr; do
    [[ -n $port ]] || continue
    [[ $proc == docker-proxy && $scope == 3 ]] && scope=4
    L_PROTO+=("$proto"); L_PORT+=("$port"); L_PROC+=("$proc"); L_SCOPE+=("$scope"); L_ADDR+=("$addr")
  done < <(
    { ss -H -tlnp 2>/dev/null | awk -v proto=tcp "$AWK_LISTEN"
      ss -H -ulnp 2>/dev/null | awk -v proto=udp "$AWK_LISTEN"; } | sort -t'|' -k2,2n -k1,1
  )
}

collect_docker() {
  command -v docker >/dev/null 2>&1 || return 0
  if ! docker info >/dev/null 2>&1; then
    warn "Docker установлен, но демон не отвечает — контейнеры не проверены"
    return 0
  fi
  DOCKER_OK=1
  local -a ids; mapfile -t ids < <(docker ps -q)
  ((${#ids[@]})) || return 0

  local fmt name mode binds cfg wd svc image b cport hip hport key i
  local -A seen=()
  fmt='{{.Name}}|{{.HostConfig.NetworkMode}}|{{range $p, $c := .NetworkSettings.Ports}}{{range $c}}{{$p}}>{{.HostIp}}>{{.HostPort}} {{end}}{{end}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.Config.Image}}'

  while IFS='|' read -r name mode binds cfg wd svc image; do
    name=${name#/}
    if [[ $mode == host ]]; then D_HOST+=("$name|$image"); continue; fi
    # shellcheck disable=SC2086  # binds — список через пробел
    for b in $binds; do
      cport=${b%%>*}; b=${b#*>}; hip=${b%%>*}; hport=${b#*>}
      [[ -n $hport ]] || continue
      if [[ $hip =~ ^(127\.|::1$) ]]; then
        key="L|$name|$hport|$cport"; [[ -n ${seen[$key]:-} ]] && continue; seen[$key]=1
        D_LOCAL+=("$name|$hip|$hport|$cport")
      else
        [[ -z $hip || $hip == "::" ]] && hip="0.0.0.0"
        key="E|$name|$hport|$cport|$hip"; [[ -n ${seen[$key]:-} ]] && continue; seen[$key]=1
        D_EXP+=("$name|$hip|$hport|$cport|$cfg|$wd|$svc")
        DOCKER_PORTS["$hport/${cport#*/}"]=$name
      fi
    done
  done < <(docker inspect --format "$fmt" "${ids[@]}" 2>/dev/null)

  for i in "${!L_PORT[@]}"; do
    [[ ${L_SCOPE[i]} == 3 && -n ${DOCKER_PORTS["${L_PORT[i]}/${L_PROTO[i]}"]:-} ]] && L_SCOPE[i]=4
  done
}

detect_ssh_ports() {
  local -a ports=() tcp_listen=()
  local p i
  for i in "${!L_PORT[@]}"; do
    [[ ${L_PROTO[i]} == tcp ]] || continue
    tcp_listen+=("${L_PORT[i]}")
    [[ ${L_PROC[i]} == sshd* ]] && ports+=("${L_PORT[i]}")
  done
  if command -v sshd >/dev/null 2>&1; then
    while read -r p; do ports+=("$p"); done < <(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}')
  fi
  # порт текущего SSH-подключения (учитываем только реально слушающие порты)
  while read -r p; do
    in_list "$p" "${tcp_listen[@]}" && ports+=("$p")
  done < <(ss -H -tnp state established 2>/dev/null |
           awk '/"sshd/{for(i=1;i<=NF;i++) if ($i ~ /:[0-9]+$/) {n=split($i,a,":"); print a[n]; break}}')
  [[ -n ${SSH_CONNECTION:-} ]] && ports+=("$(awk '{print $4}' <<<"$SSH_CONNECTION")")
  ((${#ports[@]})) || ports=(22)
  printf '%s\n' "${ports[@]}" | grep -E '^[0-9]+$' | sort -un | paste -sd, -
}

detect_node_port() {
  local v="" i
  local -a np=()
  if (( DOCKER_OK )); then
    REMNANODE=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null |
                awk '$1=="remnanode" || $2 ~ /remnawave\/node/ {print $1; exit}')
    if [[ -n $REMNANODE ]]; then
      v=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$REMNANODE" 2>/dev/null |
          awk -F= '$1=="NODE_PORT" || $1=="APP_PORT" {gsub(/[^0-9]/, "", $2); print $2; exit}')
    fi
  fi
  if [[ -z $v ]]; then
    v=$(grep -hsE '(NODE_PORT|APP_PORT)[[:space:]]*[=:]' /opt/remnanode/.env \
          /opt/remnanode/docker-compose.yml /opt/remnanode/docker-compose.yaml 2>/dev/null | head -n1 |
        sed -E 's/.*(NODE_PORT|APP_PORT)[[:space:]]*[=:][[:space:]]*["'\'']?([0-9]+).*/\2/')
  fi
  if [[ -z $v ]]; then   # единственный публичный TCP-порт процесса node
    for i in "${!L_PORT[@]}"; do
      [[ ${L_PROC[i]} == node && ${L_PROTO[i]} == tcp && ${L_SCOPE[i]} == 3 ]] && np+=("${L_PORT[i]}")
    done
    ((${#np[@]} == 1)) && v=${np[0]}
  fi
  if is_port "${v:-x}"; then NODE_PORT_DET=$((10#$v)); fi
}

detect_panel_ips() {
  ss -H -tn state established "( sport = :$NODE_PORT )" 2>/dev/null |
    awk '{c=0; for(i=1;i<=NF;i++) if ($i ~ /:[0-9]+$/) { if (++c==2) { print $i; break } } }' |
    sed -E 's/:[0-9]+$//; s/^\[//; s/\]$//; s/^::ffff://' |
    grep -vE '^(127\.|::1$)' | sort -u | paste -sd, -
}

needs_http01() {   # есть сертификаты, продлевающиеся через 80-й порт
  local f
  for f in /etc/letsencrypt/renewal/*.conf; do
    [[ -f $f ]] && grep -qE '^[[:space:]]*authenticator[[:space:]]*=[[:space:]]*(standalone|webroot|nginx|apache)' "$f" && return 0
  done
  for f in /root/.acme.sh/*/*.conf; do
    [[ -f $f ]] || continue
    grep -qE "^Le_Webroot='?dns" "$f" && continue
    grep -q '^Le_Webroot=' "$f" && return 0
  done
  return 1
}

ufw_state() {
  command -v ufw >/dev/null 2>&1 || { printf 'не установлен'; return; }
  if ufw status 2>/dev/null | grep -q '^Status: active'; then printf '%sактивен%s' "$G" "$N"
  else printf '%sвыключен%s' "$Y" "$N"; fi
}
f2b_state() {
  command -v fail2ban-client >/dev/null 2>&1 || { printf 'не установлен'; return; }
  if systemctl is-active --quiet fail2ban 2>/dev/null; then printf '%sработает%s' "$G" "$N"
  else printf '%sостановлен%s' "$Y" "$N"; fi
}

# ── 1. аудит ─────────────────────────────────────────────────────────────────
print_audit() {
  step "Открытые порты"
  if ((${#L_PORT[@]} == 0)); then warn "Не удалось получить список портов (ss)"; return; fi
  local i addr lbl pub=0
  printf '  %s%-5s %-6s %-24s %-16s %s%s\n' "$BD" PROTO PORT ADDRESS PROCESS "доступ" "$N"
  for i in "${!L_PORT[@]}"; do
    addr=${L_ADDR[i]}; (( ${#addr} > 24 )) && addr="${addr:0:21}..."
    if [[ ${L_SCOPE[i]} == 3 && ${L_PROC[i]} =~ $DHCP_RE ]]; then
      lbl="${DIM}DHCP-клиент, это нормально${N}"
    else
    case ${L_SCOPE[i]} in
      1) lbl="${G}только localhost${N}" ;;
      2) lbl="${DIM}внутренняя сеть${N}" ;;
      3) lbl="${Y}слушает наружу${N}"; ((pub++)) ;;
      4) lbl="${R}наружу через Docker — мимо UFW${N}"; ((pub++)) ;;
    esac
    fi
    printf '  %-5s %-6s %-24s %-16s %s\n' "${L_PROTO[i]}" "${L_PORT[i]}" "$addr" "${L_PROC[i]:0:16}" "$lbl"
  done
  say ""
  say "  Слушают наружу: ${BD}$pub${N}    UFW: $(ufw_state)    fail2ban: $(f2b_state)"
  if (( DOCKER_OK )); then
    say "  Docker: host-сеть ${#D_HOST[@]}, локальных публикаций ${#D_LOCAL[@]}, ${R}открыто в интернет мимо UFW: ${#D_EXP[@]}${N}"
  fi
}

# ── 2. параметры ─────────────────────────────────────────────────────────────
parse_ports() {   # parse_ports "строка" ИМЯ_МАССИВА
  local -n _out=$2
  local p
  _out=()
  while read -r p; do is_port "$p" || return 1; _out+=("$((10#$p))"); done < <(split_list "$1")
  ((${#_out[@]})) || return 1
  mapfile -t _out < <(printf '%s\n' "${_out[@]}" | sort -un)
}

ask_ssh_ports() {
  local v
  v=${SSH_PORTS:-$(detect_ssh_ports)}
  while :; do
    if [[ -z $SSH_PORTS ]]; then ask "SSH-порт(ы) — будут открыты для всех" "$v"; v=$REPLY; fi
    parse_ports "$v" SSH_ARR && break
    warn "Некорректный порт: $v"
    noninteractive && die "Проверьте --ssh-port"
    SSH_PORTS=""
  done
  ok "SSH: $(join ', ' "${SSH_ARR[@]}")"
}

ask_node_port() {
  local def i found=0
  detect_node_port
  def=${NODE_PORT:-${NODE_PORT_DET:-2222}}
  if [[ -n $NODE_PORT_DET && -z $NODE_PORT ]]; then
    info "Порт из настроек ${REMNANODE:-remnanode}: $NODE_PORT_DET"
  fi
  [[ -z $REMNANODE ]] && (( DOCKER_OK )) && warn "Контейнер remnanode не найден — проверьте, что это нода"
  while :; do
    if [[ -z $NODE_PORT ]]; then ask "Порт ноды, к которому подключается панель" "$def"; NODE_PORT=$REPLY; fi
    if is_port "$NODE_PORT"; then NODE_PORT=$((10#$NODE_PORT)); break; fi
    warn "Некорректный порт: $NODE_PORT"
    noninteractive && die "Проверьте --node-port"
    NODE_PORT=""
  done
  for i in "${!L_PORT[@]}"; do
    [[ ${L_PROTO[i]} == tcp && ${L_PORT[i]} == "$NODE_PORT" ]] && found=1
  done
  (( found )) || warn "На $NODE_PORT/tcp сейчас ничего не слушает — нода запущена?"
  if in_list "$NODE_PORT" "${SSH_ARR[@]}"; then
    die "Порт ноды $NODE_PORT совпадает с SSH — так нельзя, проверьте значения"
  fi
}

ask_panel_ips() {
  local det v ip bad
  det=$(detect_panel_ips)
  [[ -n $det ]] && info "Сейчас к порту $NODE_PORT подключены: $det — похоже на панель"
  while :; do
    v=$PANEL_IPS
    if [[ -z $v ]]; then
      if noninteractive; then
        [[ -n $det ]] || die "Укажите IP панели: --panel-ip 1.2.3.4"
        v=$det; warn "IP панели взят из активных подключений: $det"
      else
        ask "IP сервера панели (именно IP, не домен; несколько — через запятую)" "$det"; v=$REPLY
      fi
    fi
    PANEL_ARR=(); bad=""
    while read -r ip; do
      if valid_ip "$ip"; then PANEL_ARR+=("$ip"); else bad+=" $ip"; fi
    done < <(split_list "$v")
    [[ -z $bad && ${#PANEL_ARR[@]} -gt 0 ]] && break
    warn "Некорректный IP:${bad:- (пусто)}. Нужен IP сервера панели — домен может смотреть на CDN."
    noninteractive && die "Проверьте --panel-ip"
    PANEL_IPS=""
  done
  for ip in "${PANEL_ARR[@]}"; do
    is_private_ip "$ip" && warn "$ip — локальный/частный адрес. Панель точно подключается с него?"
  done
  ok "Панель: $(join ', ' "${PANEL_ARR[@]}") → $NODE_PORT/tcp"
}

ask_vpn_ports() {
  local -a cand=() other=() items=()
  local i port proto proc v it n bad
  for i in "${!L_PORT[@]}"; do
    [[ ${L_SCOPE[i]} == 3 ]] || continue
    port=${L_PORT[i]} proto=${L_PROTO[i]} proc=${L_PROC[i]}
    [[ $proto == tcp ]] && in_list "$port" "${SSH_ARR[@]}" && continue
    [[ $proto == tcp && $port == "$NODE_PORT" ]] && continue
    [[ $proc =~ $DHCP_RE ]] && continue
    if [[ $proc =~ $VPN_PROC_RE ]]; then cand+=("$port/$proto"); else other+=("$port/$proto ($proc)"); fi
  done
  if needs_http01 && ! in_list "80/tcp" "${cand[@]}"; then
    cand+=("80/tcp")
    info "Есть сертификаты Let's Encrypt с HTTP-проверкой — 80/tcp нужен для их продления"
  fi
  if ((${#cand[@]})); then
    mapfile -t cand < <(printf '%s\n' "${cand[@]}" | sort -t/ -k1,1n -k2,2 -u)
  else
    cand=("443/tcp")
    info "Xray сейчас не слушает публичные порты (нода ещё не подключена?). Укажите порты инбаундов из профиля."
  fi
  if ((${#other[@]})); then
    warn "Слушают наружу, но по умолчанию будут закрыты: $(join ', ' "${other[@]}")"
    say "    Если какой-то из них нужен снаружи — допишите его в список ниже."
  fi
  ((${#D_EXP[@]})) && info "Порты Docker в этот список добавлять не нужно — UFW на них не действует (разбор в конце)."

  v=${VPN_PORTS:-$(join ',' "${cand[@]}")}
  while :; do
    if [[ -z $VPN_PORTS ]]; then
      ask "Порты для всех (инбаунды VPN и т.п.; «-» — ни одного)" "$v"; v=$REPLY
    fi
    items=(); bad=""
    if [[ $v != "-" && ${v,,} != none ]]; then
      while read -r it; do
        if n=$(norm_item "$it"); then items+=("$n"); else bad+=" $it"; fi
      done < <(split_list "$v")
    fi
    [[ -z $bad ]] && break
    warn "Не понял:${bad}. Формат: 443, 443/tcp, 2053/udp, 10000:10100/tcp (у диапазона нужен протокол)"
    noninteractive && die "Проверьте --ports"
    VPN_PORTS=""
  done

  VPN_ARR=()
  for it in "${items[@]}"; do
    if [[ $it == "$NODE_PORT" || $it == "$NODE_PORT/tcp" ]]; then
      warn "$it — это порт ноды, для всех его не открываю (только для панели)"; continue
    fi
    if [[ $it == *:* ]] && port_in_items tcp "$NODE_PORT" "$it"; then
      warn "Диапазон $it включает порт ноды $NODE_PORT — он станет доступен всем!"
    fi
    in_list "$it" "${VPN_ARR[@]}" || VPN_ARR+=("$it")
  done
  if ((${#VPN_ARR[@]})); then ok "Для всех: $(join ', ' "${VPN_ARR[@]}")"; else warn "Публичных VPN-портов не будет"; fi
}

compute_closed() {
  local i port proto proc
  CLOSED=()
  for i in "${!L_PORT[@]}"; do
    [[ ${L_SCOPE[i]} == 3 ]] || continue
    port=${L_PORT[i]} proto=${L_PROTO[i]} proc=${L_PROC[i]}
    [[ $proc =~ $DHCP_RE ]] && continue
    [[ $proto == tcp ]] && in_list "$port" "${SSH_ARR[@]}" && continue
    [[ $proto == tcp && $port == "$NODE_PORT" ]] && continue
    port_in_items "$proto" "$port" "${VPN_ARR[@]}" && continue
    in_list "$port/$proto ($proc)" "${CLOSED[@]}" || CLOSED+=("$port/$proto ($proc)")
  done
}

# ── Telegram: ввод и проверка ────────────────────────────────────────────────
tg_send() {   # tg_send "HTML-текст" → 0 при успехе, иначе причина в TG_ERR
  local resp
  TG_ERR=""
  resp=$(curl -sS -m 15 -K - \
           --data-urlencode "chat_id=$TG_CHAT_ID" --data-urlencode "text=$1" \
           -d parse_mode=HTML -d disable_web_page_preview=true \
           2>&1 <<<"url = \"${TG_API%/}/bot$TG_TOKEN/sendMessage\"")
  [[ $resp == *'"ok":true'* ]] && return 0
  TG_ERR=$(sed -nE 's/.*"description":"([^"]*)".*/\1/p' <<<"$resp" | head -n1)
  [[ -n $TG_ERR ]] || TG_ERR=$(head -n1 <<<"${resp:-нет ответа}")
  return 1
}

tg_hint() {
  case $TG_ERR in
    *Unauthorized*|*"Not Found"*)
      say "    → Неверный токен. Скопируйте его ещё раз у @BotFather." ;;
    *"chat not found"*)
      say "    → Откройте своего бота в Telegram и нажмите /start (с аккаунта $TG_CHAT_ID), потом повторите." ;;
    *blocked*)
      say "    → Бот у вас заблокирован — разблокируйте его и нажмите /start." ;;
    *curl*|*resolve*|*"timed out"*|*onnect*)
      say "    → Нет связи с $TG_API — проверьте сеть и DNS сервера." ;;
  esac
}

load_tg_conf() {
  local name_flag=$TG_NODE_NAME
  [[ -r $TG_CONF ]] || return 1
  # shellcheck source=/dev/null
  . "$TG_CONF" 2>/dev/null || return 1
  [[ -n $name_flag ]] && TG_NODE_NAME=$name_flag
  [[ -n $TG_TOKEN && -n $TG_CHAT_ID ]]
}

ask_telegram() {
  local def_token="" def_id=""
  if (( TG_DISABLE )); then
    [[ -e $TG_CONF ]] && TG_REMOVE=1
    return 0
  fi
  if [[ -n $TG_TOKEN || -n $TG_CHAT_ID ]]; then
    [[ -n $TG_TOKEN && -n $TG_CHAT_ID ]] || die "Для Telegram нужны оба флага: --tg-token и --tg-id"
  elif load_tg_conf; then
    if confirm "Уведомления в Telegram уже настроены (ID $TG_CHAT_ID, нода «$TG_NODE_NAME»). Оставить как есть?" Y; then
      TG_ENABLED=1
      ok "Telegram: текущие настройки сохранены"
      return 0
    fi
    def_token=$TG_TOKEN def_id=$TG_CHAT_ID TG_TOKEN="" TG_CHAT_ID=""
    if ! confirm "Перенастроить уведомления? (n — отключить их)" Y; then TG_REMOVE=1; return 0; fi
  else
    noninteractive && return 0
    confirm "Присылать уведомления в Telegram? (отчёт, баны fail2ban, входы по SSH)" N || return 0
  fi

  if [[ -z $TG_TOKEN ]]; then
    say "    Бот: создайте его в @BotFather (/newbot) и скопируйте токен. Свой USER_ID покажет @userinfobot."
    say "    Перед проверкой откройте своего бота и нажмите /start — иначе он не сможет вам писать."
  fi
  if ! command -v curl >/dev/null 2>&1 && ! install_pkgs curl; then
    warn "Без curl уведомления не настроить — пропускаю"; TG_TOKEN="" TG_CHAT_ID=""; return 0
  fi
  while :; do
    if [[ -z $TG_TOKEN ]]; then ask "TOKEN бота" "$def_token"; TG_TOKEN=$REPLY; fi
    if [[ ! $TG_TOKEN =~ ^[0-9]{5,}:[A-Za-z0-9_-]{30,}$ ]]; then
      warn "Это не похоже на токен бота (вид: 123456789:AAH...)"
      if noninteractive; then warn "Telegram не настроен — проверьте --tg-token"; TG_TOKEN="" TG_CHAT_ID=""; return 0; fi
      TG_TOKEN=""; continue
    fi
    if [[ -z $TG_CHAT_ID ]]; then ask "Ваш USER_ID в Telegram" "$def_id"; TG_CHAT_ID=$REPLY; fi
    if [[ ! $TG_CHAT_ID =~ ^-?[0-9]{3,}$ ]]; then
      warn "USER_ID — это число, например 123456789 (у групп — с минусом)"
      if noninteractive; then warn "Telegram не настроен — проверьте --tg-id"; TG_TOKEN="" TG_CHAT_ID=""; return 0; fi
      TG_CHAT_ID=""; continue
    fi
    if [[ -z $TG_NODE_NAME ]]; then ask "Подпись этой ноды в уведомлениях" "$(hostname)"; TG_NODE_NAME=$REPLY; fi
    info "Отправляю тестовое сообщение…"
    if tg_send "✅ <b>$(html "$TG_NODE_NAME")</b> · node-guard${NL}Уведомления подключены, тест прошёл."; then
      ok "Тестовое сообщение доставлено — проверьте Telegram"
      break
    fi
    err "Telegram ответил: $TG_ERR"
    tg_hint
    if noninteractive || ! confirm "Попробовать ещё раз? (данные можно поправить)" Y; then
      warn "Уведомления в Telegram не будут настроены"; TG_TOKEN="" TG_CHAT_ID=""
      return 0
    fi
    def_token=$TG_TOKEN def_id=$TG_CHAT_ID TG_TOKEN="" TG_CHAT_ID=""
  done

  TG_ENABLED=1
  if (( SKIP_F2B )); then
    TG_NOTIFY_BANS=0
  elif confirm "Присылать баны fail2ban? (на публичном сервере их бывает несколько в час)" Y; then
    TG_NOTIFY_BANS=1
  else
    TG_NOTIFY_BANS=0
  fi
  if confirm "Присылать уведомления о входе по SSH?" Y; then TG_NOTIFY_LOGINS=1; else TG_NOTIFY_LOGINS=0; fi
}

# ── 3. план ──────────────────────────────────────────────────────────────────
print_plan() {
  local p it ip
  step "План"
  say "  ${BD}Для всех:${N}"
  for p in "${SSH_ARR[@]}"; do say "    • $p/tcp — SSH"; done
  for it in "${VPN_ARR[@]}"; do
    if [[ $it == */* ]]; then say "    • $it"; else say "    • $it (tcp+udp)"; fi
  done
  say "  ${BD}Только для панели:${N}"
  for ip in "${PANEL_ARR[@]}"; do say "    • $NODE_PORT/tcp ← $ip"; done
  say "  ${BD}Остальное входящее:${N} запрещено (исходящее разрешено)"
  ((${#CLOSED[@]})) && say "  ${BD}Закроются${N} (сейчас слушают наружу): $(join ', ' "${CLOSED[@]}")"
  if (( !SKIP_F2B )); then
    say "  ${BD}fail2ban:${N} SSH — 5 ошибок за 10 мин → бан 1 ч, повторно дольше (до недели); IP панели в белом списке"
  fi
  if (( TG_ENABLED )); then
    local -a what=("отчёт")
    (( TG_NOTIFY_BANS )) && what+=("баны fail2ban")
    (( TG_NOTIFY_LOGINS )) && what+=("входы по SSH")
    say "  ${BD}Telegram:${N} ID $TG_CHAT_ID — $(join ', ' "${what[@]}")"
  elif (( TG_REMOVE )); then
    say "  ${BD}Telegram:${N} уведомления будут отключены"
  fi
  ((${#D_EXP[@]})) && say "  ${Y}Docker-порты (${#D_EXP[@]} шт.) UFW не закроет — инструкция в конце${N}"
  return 0
}

# ── 4. UFW ───────────────────────────────────────────────────────────────────
APT() { apt-get -o DPkg::Lock::Timeout=120 "$@"; }

install_pkgs() {
  local -a missing=(); local p out
  for p in "$@"; do
    # shellcheck disable=SC2016  # ${Status} — формат dpkg-query, не переменная bash
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed' || missing+=("$p")
  done
  ((${#missing[@]})) || return 0
  info "Устанавливаю: ${missing[*]}"
  export DEBIAN_FRONTEND=noninteractive
  if (( !APT_UPDATED )); then
    APT update -qq >/dev/null 2>&1 || warn "apt-get update завершился с ошибкой"
    APT_UPDATED=1
  fi
  if ! out=$(APT install -y -qq "${missing[@]}" 2>&1); then
    err "Не удалось установить: ${missing[*]}"
    printf '%s\n' "$out" | tail -n 8 | sed 's/^/    /' >&2
    return 1
  fi
}

ufwq() {
  local out
  if ! out=$(ufw "$@" 2>&1); then err "ufw $* → $out"; return 1; fi
}

arm_rollback() {
  local ufw_bin; ufw_bin=$(command -v ufw)
  if command -v systemd-run >/dev/null 2>&1 &&
     systemd-run --quiet --unit="$RB_UNIT" --on-active="${ROLLBACK_SEC}s" "$ufw_bin" --force disable >/dev/null 2>&1; then
    RB_MODE=systemd
  else
    setsid bash -c "sleep $ROLLBACK_SEC; '$ufw_bin' --force disable" </dev/null >/dev/null 2>&1 &
    RB_PID=$!; RB_MODE=pid
  fi
}

disarm_rollback() {
  case $RB_MODE in
    systemd) systemctl stop "$RB_UNIT.timer" >/dev/null 2>&1 ;;
    pid)     kill "$RB_PID" 2>/dev/null ;;
  esac
  RB_MODE=""
}

confirm_access() {
  local deadline=$((SECONDS + ROLLBACK_SEC - 5)) left a
  say ""
  warn "Страховка: если не подтвердить доступ за $ROLLBACK_SEC с, UFW отключится сам."
  say "    Не закрывая эту сессию, откройте ${BD}НОВОЕ${N} SSH-подключение и проверьте вход."
  while :; do
    left=$((deadline - SECONDS))
    (( left > 0 )) || break
    printf '%s?%s Вход в новой сессии работает? Введите %sok%s (осталось %s с): ' "$C" "$N" "$BD" "$N" "$left" >/dev/tty
    if IFS= read -r -t "$left" a </dev/tty; then
      case ${a,,} in
        ok|ок|ОК|Ок|y|yes|да|Да|ДА) disarm_rollback; ok "Доступ подтверждён, откат отменён"; return 0 ;;
      esac
    else
      printf '\n' >/dev/tty; break
    fi
  done
  disarm_rollback
  ufw --force disable >/dev/null 2>&1
  err "Подтверждения нет — UFW отключён, сервер снова открыт."
  die "Проверьте SSH-порт (флаг --ssh-port) и запустите скрипт ещё раз."
}

apply_ufw() {
  local has_rules=0 added p ip it guard=0
  step "UFW"
  install_pkgs ufw || die "Без ufw продолжать нельзя"
  [[ -f /etc/default/ufw ]] && sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw

  ufw status 2>/dev/null | grep -q '^Status: active' && has_rules=1
  added=$(ufw show added 2>/dev/null | grep -c '^ufw ')
  (( added > 0 )) && has_rules=1

  if (( has_rules )) && [[ -z $RESET_UFW ]]; then
    say "  Текущие правила UFW:"
    ufw show added 2>/dev/null | grep '^ufw ' | sed 's/^/    /'
    if confirm "Сбросить их и настроить UFW с нуля? (ufw сам сохранит бэкап в /etc/ufw)" Y
    then RESET_UFW=yes; else RESET_UFW=no; fi
  fi
  if (( has_rules )) && [[ $RESET_UFW == yes ]]; then
    ufwq --force reset || die "Не удалось сбросить UFW"
    ok "Старые правила сброшены (бэкап: /etc/ufw/*.rules.<дата>)"
  elif (( has_rules )); then
    for it in "$NODE_PORT" "$NODE_PORT/tcp" "$NODE_PORT/udp"; do
      ufw --force delete allow "$it" >/dev/null 2>&1
    done
    info "Старые правила оставлены; правила «allow $NODE_PORT для всех» (если были) удалены"
  fi

  for p in "${SSH_ARR[@]}"; do
    ufwq allow "$p/tcp" comment 'SSH' || die "Не удалось разрешить SSH $p — UFW НЕ включён"
  done
  ok "SSH: $(join ', ' "${SSH_ARR[@]}") — для всех"
  for ip in "${PANEL_ARR[@]}"; do
    ufwq allow from "$ip" to any port "$NODE_PORT" proto tcp comment 'Remnawave panel' ||
      die "Не удалось добавить правило для панели $ip — UFW НЕ включён"
  done
  ok "Порт ноды $NODE_PORT — только с $(join ', ' "${PANEL_ARR[@]}")"
  for it in "${VPN_ARR[@]}"; do
    if ufwq allow "$it" comment 'VPN'; then ok "$it — для всех"; else warn "Не удалось открыть $it"; fi
  done
  ufwq default deny incoming  || die "Не удалось задать политику входящих"
  ufwq default allow outgoing || die "Не удалось задать политику исходящих"

  if ! noninteractive && (( !NO_ROLLBACK )); then arm_rollback; guard=1; fi
  if ! ufwq --force enable; then
    (( guard )) && disarm_rollback
    die "Не удалось включить UFW (VPS на OpenVZ/LXC без iptables?)"
  fi
  ok "UFW включён: входящее запрещено, кроме перечисленного"
  (( guard )) && confirm_access
  return 0
}

# ── Telegram: установка ──────────────────────────────────────────────────────
write_tg_conf() {
  mkdir -p "${TG_CONF%/*}" && chmod 700 "${TG_CONF%/*}"
  ( umask 077
    {
      say "# node-guard: уведомления в Telegram. Можно править вручную — применяется сразу."
      say "TG_TOKEN=$(sq "$TG_TOKEN")"
      say "TG_CHAT_ID=$(sq "$TG_CHAT_ID")"
      say "TG_NODE_NAME=$(sq "$TG_NODE_NAME")"
      say "TG_NOTIFY_BANS=$TG_NOTIFY_BANS     # 1 — присылать баны fail2ban, 0 — нет"
      say "TG_NOTIFY_LOGINS=$TG_NOTIFY_LOGINS   # 1 — присылать входы по SSH, 0 — нет"
      say "# Свой адрес Bot API, если api.telegram.org с сервера недоступен"
      say "TG_API=$(sq "$TG_API")"
    } >"$TG_CONF"
  )
  chmod 600 "$TG_CONF"
}

write_notifier() {
  cat >"$NOTIFY_BIN" <<'NOTIFY'
#!/usr/bin/env bash
# node-guard-notify — уведомления node-guard в Telegram (создано node-guard.sh)
#   node-guard-notify test
#   node-guard-notify ban <jail> <ip> <failures>     ← fail2ban
#   node-guard-notify login                          ← pam_exec (sshd)
#   node-guard-notify report < текст.html
# Настройки: /etc/node-guard/telegram.conf
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
shopt -u patsub_replacement 2>/dev/null || true
CONF=/etc/node-guard/telegram.conf
[[ -r $CONF ]] || exit 0
# shellcheck source=/dev/null
. "$CONF"
[[ -n ${TG_TOKEN:-} && -n ${TG_CHAT_ID:-} ]] || exit 0
API=${TG_API:-https://api.telegram.org}
NODE=${TG_NODE_NAME:-$(hostname)}
NL=$'\n'

h() { local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; printf '%s' "$s"; }

send() {
  local resp
  resp=$(curl -sS -m 15 -K - \
           --data-urlencode "chat_id=$TG_CHAT_ID" --data-urlencode "text=$1" \
           -d parse_mode=HTML -d disable_web_page_preview=true \
           2>&1 <<<"url = \"${API%/}/bot$TG_TOKEN/sendMessage\"")
  [[ $resp == *'"ok":true'* ]] && return 0
  printf '%s\n' "$resp" >&2
  return 1
}

# Отправка в фоне: не задерживаем ни fail2ban, ни вход по SSH
send_bg() { ( send "$1" >/dev/null 2>&1 & ); }

case ${1:-} in
  test)
    send "✅ <b>$(h "$NODE")</b> · node-guard${NL}Тестовое сообщение."
    exit $? ;;
  ban)
    [[ ${TG_NOTIFY_BANS:-1} == 1 ]] || exit 0
    ip=${3:-?}
    send_bg "🚫 <b>$(h "$NODE")</b> · fail2ban <code>$(h "${2:-?}")</code>${NL}Забанен <a href=\"https://ipinfo.io/$(h "$ip")\">$(h "$ip")</a>, ошибок: $(h "${4:-?}")" ;;
  login)
    [[ ${TG_NOTIFY_LOGINS:-1} == 1 && ${PAM_TYPE:-} == open_session ]] || exit 0
    ip=${PAM_RHOST:-?}
    send_bg "🔑 <b>$(h "$NODE")</b> · вход по SSH${NL}Пользователь: <code>$(h "${PAM_USER:-?}")</code>${NL}С адреса: <a href=\"https://ipinfo.io/$(h "$ip")\">$(h "$ip")</a>${NL}$(date '+%F %T %Z')" ;;
  report)
    send "$(cat)"
    exit $? ;;
  *)
    echo "Использование: node-guard-notify test | ban <jail> <ip> <failures> | login | report < text" >&2
    exit 2 ;;
esac
exit 0
NOTIFY
  chmod 755 "$NOTIFY_BIN"
}

write_f2b_tg_action() {
  mkdir -p "${F2B_TG_ACTION%/*}"
  cat >"$F2B_TG_ACTION" <<EOF
# Создано node-guard.sh — уведомления о банах в Telegram через $NOTIFY_BIN
[Definition]
# не слать повторно баны, восстановленные после перезапуска fail2ban
norestored  = 1
actionstart =
actionstop  =
actioncheck =
actionban   = $NOTIFY_BIN ban <name> <ip> <failures>
actionunban =
EOF
}

apply_telegram() {
  if (( TG_REMOVE )); then
    step "Telegram"
    rm -f "$TG_CONF"
    [[ -f $PAM_SSHD ]] && sed -i '/node-guard-notify/d' "$PAM_SSHD"
    ok "Уведомления в Telegram отключены"
    return 0
  fi
  (( TG_ENABLED )) || return 0
  step "Telegram"
  install_pkgs curl || { warn "Без curl уведомления работать не будут"; TG_ENABLED=0; return 1; }
  write_tg_conf
  write_notifier
  if (( !SKIP_F2B )) || [[ -d /etc/fail2ban ]]; then write_f2b_tg_action; fi
  # Строка в PAM ставится всегда: включать и выключать входы можно в $TG_CONF.
  # optional — если отправка не удастся, вход по SSH это не заблокирует.
  if [[ -f $PAM_SSHD ]]; then
    sed -i '/node-guard-notify/d' "$PAM_SSHD"
    printf '%s\n' "# node-guard-notify: уведомление о входе по SSH в Telegram" \
      "session optional pam_exec.so quiet $NOTIFY_BIN login" >>"$PAM_SSHD"
  else
    warn "Нет $PAM_SSHD — уведомления о входе по SSH не подключены"
  fi
  if (( TG_NOTIFY_LOGINS )) && [[ $(sshd -T 2>/dev/null | awk '$1=="usepam"{print $2}') == no ]]; then
    warn "В sshd выключен UsePAM — уведомления о входе приходить не будут"
  fi
  ok "Настройки: $TG_CONF (только root)"
  ok "Отчёт: да · баны fail2ban: $(yn "$TG_NOTIFY_BANS") · входы по SSH: $(yn "$TG_NOTIFY_LOGINS")"
}

server_ip() {
  ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

tg_report() {
  (( TG_ENABLED )) || return 0
  local t e name hport cport n=0 p ufw_s f2b_s sip
  local -a open=()
  for p in "${SSH_ARR[@]}"; do open+=("$p/tcp"); done
  open+=("${VPN_ARR[@]}")
  if ufw status 2>/dev/null | grep -q '^Status: active'; then ufw_s="включён"; else ufw_s="⚠️ выключен"; fi
  if (( F2B_OK )); then f2b_s="работает"; else f2b_s="не настроен"; fi

  t="🛡 <b>$(html "$TG_NODE_NAME")</b> · node-guard${NL}"
  sip=$(server_ip)
  t+="Сервер: <code>$(html "$(hostname)")${sip:+ · $sip}</code>${NL}${NL}"
  t+="<b>UFW</b>: $ufw_s${NL}"
  t+="Для всех: $(html "$(join ', ' "${open[@]}")")${NL}"
  t+="Порт ноды $NODE_PORT ← $(html "$(join ', ' "${PANEL_ARR[@]}")")${NL}"
  ((${#CLOSED[@]})) && t+="Закрыто: $(html "$(join ', ' "${CLOSED[@]}")")${NL}"
  t+="<b>fail2ban</b>: $f2b_s${NL}"
  if ((${#D_EXP[@]})); then
    t+="${NL}⚠️ <b>Docker мимо UFW</b>:${NL}"
    for e in "${D_EXP[@]}"; do
      if (( ++n > 10 )); then t+="… и ещё $(( ${#D_EXP[@]} - 10 ))${NL}"; break; fi
      IFS='|' read -r name _ hport cport _ <<<"$e"
      t+="• $(html "$name") — $hport → $(html "$cport")${NL}"
    done
  fi
  if tg_send "$t"; then ok "Отчёт отправлен в Telegram"; else warn "Отчёт в Telegram не отправился: $TG_ERR"; fi
}

# ── 5. fail2ban ──────────────────────────────────────────────────────────────
write_jail() {   # write_jail <backend> <recidive 0|1> <telegram 0|1>
  local backend=$1 rec=$2 tg=${3:-0} ignore="127.0.0.1/8 ::1" ip
  for ip in "${PANEL_ARR[@]}"; do ignore+=" $ip"; done
  {
    printf '# Создано node-guard.sh %s. Повторный запуск скрипта перезапишет файл.\n\n' "$(date '+%F %T')"
    cat <<EOF
[DEFAULT]
ignoreip           = $ignore
bantime            = 1h
bantime.increment  = true
bantime.maxtime    = 1w
findtime           = 10m
maxretry           = 5
banaction          = iptables-multiport
banaction_allports = iptables-allports
EOF
    if (( tg )); then
      cat <<'EOF'
action             = %(action_)s
                     node-guard-telegram
EOF
    fi
    cat <<EOF

[sshd]
enabled  = true
port     = $(join ',' "${SSH_ARR[@]}")
mode     = aggressive
backend  = $backend
EOF
    if (( rec )); then
      cat <<'EOF'

[recidive]
enabled  = true
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
    fi
  } >"$F2B_JAIL"
}

apply_fail2ban() {
  local backend=auto i
  local -a pkgs=(fail2ban)
  step "fail2ban"
  if (( SKIP_F2B )); then info "Пропущено (--no-fail2ban)"; return 0; fi
  if [[ ! -s /var/log/auth.log ]]; then backend=systemd; pkgs+=(python3-systemd); fi
  install_pkgs "${pkgs[@]}" || return 1
  mkdir -p /etc/fail2ban/jail.d
  [[ -e /var/log/fail2ban.log ]] || touch /var/log/fail2ban.log

  # пробуем полный конфиг, при ошибке — без recidive, затем без Telegram
  local tg=$TG_ENABLED rec=1 tg_on=0 t good=0
  local -a tries=("1 $tg" "0 $tg")
  (( tg )) && tries+=("0 0")
  for t in "${tries[@]}"; do
    read -r rec tg_on <<<"$t"
    write_jail "$backend" "$rec" "$tg_on"
    if fail2ban-client -t >/dev/null 2>&1; then good=1; break; fi
  done
  if (( !good )); then
    err "Конфиг fail2ban не прошёл проверку:"
    fail2ban-client -t 2>&1 | tail -n 15 | sed 's/^/    /' >&2
    return 1
  fi
  (( rec )) || warn "recidive выключен (fail2ban не пишет лог в файл)"
  (( tg && !tg_on )) && warn "Уведомления о банах не подключились к fail2ban"
  systemctl enable fail2ban >/dev/null 2>&1
  if ! systemctl restart fail2ban; then
    err "fail2ban не перезапустился — смотрите: journalctl -u fail2ban -n 30"; return 1
  fi
  for i in {1..15}; do fail2ban-client ping >/dev/null 2>&1 && break; sleep 1; done
  if fail2ban-client status sshd >/dev/null 2>&1; then
    F2B_OK=1
    ok "fail2ban работает: SSH ($(join ',' "${SSH_ARR[@]}")), лог: $backend, конфиг: $F2B_JAIL"
  else
    err "Jail sshd не поднялся — смотрите: journalctl -u fail2ban -n 30"; return 1
  fi
}

# ── 6. Docker ────────────────────────────────────────────────────────────────
report_docker() {
  local e name hip hport cport cfg wd svc cp pr sfx dc ext_if c first_port="" ccfg cwd csvc
  local -a names=()
  step "Docker: порты в обход UFW"
  if (( !DOCKER_OK )); then info "Docker не найден или не запущен — проверять нечего."; return 0; fi

  for e in "${D_HOST[@]}"; do ok "${e%%|*} — network_mode: host, его порты закрывает UFW"; done
  for e in "${D_LOCAL[@]}"; do
    IFS='|' read -r name hip hport cport <<<"$e"
    ok "$name — $hip:$hport → $cport, только локально"
  done
  if ((${#D_EXP[@]} == 0)); then ok "Контейнеров с портами, открытыми в интернет, нет."; return 0; fi

  say ""
  warn "Docker сам пишет правила iptables и пропускает трафик к контейнерам РАНЬШЕ UFW."
  warn "Эти порты доступны из интернета, даже если UFW их «закрывает»:"
  for e in "${D_EXP[@]}"; do
    IFS='|' read -r name hip hport cport _ <<<"$e"
    say "    ${R}•${N} $name   $hip:$hport → $cport"
    [[ -z $first_port ]] && first_port=$hport
    in_list "$name" "${names[@]}" || names+=("$name")
  done

  dc="docker compose"; docker compose version >/dev/null 2>&1 || dc="docker-compose"
  ext_if=$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  ext_if=${ext_if:-eth0}

  say ""
  say "${BD}Как закрыть${N} (если порт снаружи не нужен — например, к сервису ходит nginx на этом же сервере)"
  for c in "${names[@]}"; do
    ccfg="" cwd="" csvc=""
    say ""
    say "  ${BD}▸ $c${N}"
    for e in "${D_EXP[@]}"; do
      IFS='|' read -r name hip hport cport cfg wd svc <<<"$e"
      [[ $name == "$c" ]] || continue
      ccfg=$cfg cwd=$wd csvc=$svc
      cp=${cport%/*} pr=${cport#*/} sfx=""
      [[ $pr == udp ]] && sfx="/udp"
      if [[ -n $cfg ]]; then
        say "    в ports: \"$hport:$cp$sfx\"  →  ${G}\"127.0.0.1:$hport:$cp$sfx\"${N}"
      else
        say "    пересоздайте контейнер с  ${G}-p 127.0.0.1:$hport:$cp$sfx${N}  вместо  -p $hport:$cp$sfx"
      fi
    done
    if [[ -n $ccfg ]]; then
      say "    файл:   ${ccfg//,/, }${csvc:+   (сервис: $csvc)}"
      say "    затем:  ${BD}cd ${cwd:-<папка проекта>} && $dc up -d${N}"
      say "    ${DIM}не нужен вообще — удалите у сервиса блок ports:${N}"
    fi
  done

  say ""
  say "${BD}Другие способы${N}"
  say "  • Пустить к порту только свой IP, не трогая compose (правило живёт до перезагрузки):"
  say "      iptables -I DOCKER-USER -i $ext_if -p tcp -m conntrack --ctorigdstport $first_port --ctdir ORIGINAL ! -s <ВАШ_IP> -j DROP"
  say "    Постоянно и через UFW — утилита ufw-docker: github.com/chaifeng/ufw-docker"
  say "  • Для всех контейнеров сразу: в /etc/docker/daemon.json добавить  ${G}\"ip\": \"127.0.0.1\"${N}"
  say "    затем  systemctl restart docker  и  $dc up -d --force-recreate  в каждом проекте —"
  say "    порты без явного IP станут слушать только localhost."
  say "  • Если порт должен быть публичным (сайт, страница подписки) — оставьте, но UFW его не защищает."
}

# ── итог ─────────────────────────────────────────────────────────────────────
summary() {
  hdr "Итог"
  ufw status verbose 2>/dev/null | sed 's/^/  /'
  if (( F2B_OK )); then
    say ""
    fail2ban-client status sshd 2>/dev/null | sed 's/^/  /'
  fi
  ((${#CLOSED[@]})) && { say ""; ok "Закрыто для интернета: $(join ', ' "${CLOSED[@]}")"; }
  ((${#D_EXP[@]})) && warn "Осталось Docker-портов в обход UFW: ${#D_EXP[@]} — как закрыть, написано выше"
  (( TG_ENABLED )) && ok "Telegram: настройки в $TG_CONF, проверка: $NOTIFY_BIN test"
  say ""
  say "${BD}Полезное${N}"
  say "  ufw status numbered                      правила UFW"
  say "  ufw allow 8443/tcp                       открыть порт для всех"
  say "  ufw delete <номер>                       удалить правило"
  say "  fail2ban-client status sshd              кто забанен"
  say "  fail2ban-client set sshd unbanip <IP>    разбанить"
  (( TG_ENABLED )) && say "  node-guard-notify test                   тестовое сообщение в Telegram"
  say "  Сменился IP панели или порты — просто запустите скрипт ещё раз."
}

# ── аргументы ────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
node-guard.sh v$VERSION — защита ноды Remnawave (аудит портов, UFW, fail2ban, Docker)

Использование: sudo bash node-guard.sh [опции]

  --panel-ip IP[,IP]   IP сервера панели — только ему доступен порт ноды
  --node-port PORT     порт ноды, к которому подключается панель (обычно 2222)
  --ports LIST         порты для всех: 443,8443,80/tcp,2053/udp,10000:10100/tcp
  --ssh-port LIST      SSH-порт(ы), если автоопределение ошиблось
  --reset              сбросить существующие правила UFW (по умолчанию — спросить)
  --no-reset           оставить существующие правила UFW и дописать свои
  --no-fail2ban        не настраивать fail2ban
  --no-rollback        без страховочного автоотката UFW
  --tg-token TOKEN     токен Telegram-бота (вместе с --tg-id включает уведомления)
  --tg-id ID           ваш USER_ID в Telegram (или ID группы)
  --tg-name NAME       подпись ноды в уведомлениях (по умолчанию hostname)
  --no-telegram        без уведомлений (если были — отключить)
  --audit              только проверка портов и Docker, ничего не менять
  -y, --yes            без вопросов (значения по умолчанию / из флагов)
  -h, --help           эта справка

Примеры:
  sudo bash node-guard.sh
  sudo bash node-guard.sh --audit
  sudo bash node-guard.sh --panel-ip 203.0.113.10 --node-port 2222 --ports 443/tcp,8443/tcp -y
EOF
}

parse_args() {
  need() { [[ $# -ge 2 && -n $2 && ( $2 != -* || $2 == - || $2 =~ ^-[0-9]+$ ) ]] || die "Опции $1 нужно значение (см. --help)"; }
  while (($#)); do
    case $1 in
      --panel-ip)   need "$@"; PANEL_IPS=$2; shift 2 ;;
      --panel-ip=*) PANEL_IPS=${1#*=}; shift ;;
      --node-port)  need "$@"; NODE_PORT=$2; shift 2 ;;
      --node-port=*) NODE_PORT=${1#*=}; shift ;;
      --ports)      need "$@"; VPN_PORTS=$2; shift 2 ;;
      --ports=*)    VPN_PORTS=${1#*=}; shift ;;
      --ssh-port)   need "$@"; SSH_PORTS=$2; shift 2 ;;
      --ssh-port=*) SSH_PORTS=${1#*=}; shift ;;
      --reset)      RESET_UFW=yes; shift ;;
      --no-reset)   RESET_UFW=no; shift ;;
      --no-fail2ban) SKIP_F2B=1; shift ;;
      --no-rollback) NO_ROLLBACK=1; shift ;;
      --tg-token)   need "$@"; TG_TOKEN=$2; shift 2 ;;
      --tg-token=*) TG_TOKEN=${1#*=}; shift ;;
      --tg-id)      need "$@"; TG_CHAT_ID=$2; shift 2 ;;
      --tg-id=*)    TG_CHAT_ID=${1#*=}; shift ;;
      --tg-name)    need "$@"; TG_NODE_NAME=$2; shift 2 ;;
      --tg-name=*)  TG_NODE_NAME=${1#*=}; shift ;;
      --no-telegram) TG_DISABLE=1; shift ;;
      --audit)      AUDIT_ONLY=1; shift ;;
      -y|--yes)     ASSUME_YES=1; shift ;;
      -h|--help)    usage; exit 0 ;;
      -V|--version) echo "$VERSION"; exit 0 ;;
      *) die "Неизвестная опция: $1 (см. --help)" ;;
    esac
  done
}

# ── main ─────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  say "${BD}node-guard.sh v$VERSION${N} — защита ноды Remnawave"
  (( EUID == 0 )) || die "Запустите от root: sudo bash node-guard.sh"
  command -v ss >/dev/null 2>&1 || die "Нет утилиты ss (пакет iproute2)"

  collect_listeners
  collect_docker
  print_audit

  if (( AUDIT_ONLY )); then
    report_docker
    exit 0
  fi

  command -v apt-get >/dev/null 2>&1 || die "Нужен Debian/Ubuntu (apt)"
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    die "Активен firewalld — он конфликтует с UFW. Отключите: systemctl disable --now firewalld"
  fi
  if (( !HAVE_TTY && !ASSUME_YES )); then
    die "Нет терминала для вопросов. Запустите с -y и --panel-ip (см. --help)"
  fi

  step "Параметры"
  ask_ssh_ports
  ask_node_port
  ask_panel_ips
  ask_vpn_ports
  ask_telegram
  compute_closed
  print_plan

  if ! confirm "Применить?" Y; then info "Отменено, ничего не изменено."; exit 0; fi

  apply_ufw
  apply_telegram
  apply_fail2ban || warn "fail2ban не настроен — UFW при этом работает"
  report_docker
  summary
  tg_report
}

main "$@"
