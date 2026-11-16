#!/system/bin/sh
MODDIR=${0%/*}
BASE=/data/adb/sshprotocol
PID="$BASE/sshprotocol.pid"
HEVPID="$BASE/hev.pid"
CFG="$BASE/config.json"
HEVCFG="$BASE/hev.yml"
LOG="$BASE/logs/module.log"
MARK=438
TABLE=2022
DNS_IP=198.18.0.2

mkdir -p "$BASE/logs"; touch "$LOG"
log(){ echo "[$(date '+%F %T')] $*" >> "$LOG"; }
alive(){ [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
iptables_cmd(){ command -v iptables >/dev/null 2>&1 && iptables -w "$@" 2>/dev/null; }
dns_redirect_off(){
  iptables_cmd -t nat -D OUTPUT -p udp --dport 53 -m mark ! --mark "$MARK" ! -d 127.0.0.0/8 -j DNAT --to-destination "$DNS_IP":53
  iptables_cmd -t nat -D OUTPUT -p udp --dport 53 -m mark ! --mark "$MARK" ! -d 127.0.0.0/8 -j REDIRECT --to-ports 53
}
dns_redirect_on(){
  command -v iptables >/dev/null 2>&1 || { log "WARN: iptables unavailable; DNS redirect skipped"; return 0; }
  if ! iptables_cmd -t nat -C OUTPUT -p udp --dport 53 -m mark ! --mark "$MARK" ! -d 127.0.0.0/8 -j DNAT --to-destination "$DNS_IP":53; then
    iptables_cmd -t nat -A OUTPUT -p udp --dport 53 -m mark ! --mark "$MARK" ! -d 127.0.0.0/8 -j DNAT --to-destination "$DNS_IP":53
  fi
  log "DNS UDP redirect enabled -> $DNS_IP:53 (HEV mapdns)"
}
stop_one(){
  f="$1"; [ -f "$f" ] || return 0
  p="$(cat "$f" 2>/dev/null)"
  if alive "$p"; then kill "$p" 2>/dev/null; i=0; while alive "$p" && [ "$i" -lt 5 ]; do sleep 1; i=$((i+1)); done; alive "$p" && kill -9 "$p" 2>/dev/null; fi
  rm -f "$f"
}
route_down(){
  dns_redirect_off
  ip rule del pref 100 2>/dev/null
  ip -6 rule del pref 100 2>/dev/null
  ip rule del to 10.0.0.0/8 pref 1000 2>/dev/null
  ip rule del to 172.16.0.0/12 pref 1000 2>/dev/null
  ip rule del to 192.168.0.0/16 pref 1000 2>/dev/null
  ip rule del to 169.254.0.0/16 pref 1000 2>/dev/null
  ip -6 rule del to fc00::/7 pref 1000 2>/dev/null
  ip -6 rule del to fe80::/10 pref 1000 2>/dev/null
  ip rule del pref 11000 2>/dev/null
  ip -6 rule del pref 11000 2>/dev/null
  ip route flush table "$TABLE" 2>/dev/null
  ip -6 route flush table "$TABLE" 2>/dev/null
}
route_up(){
  command -v ip >/dev/null 2>&1 || { log "WARN: ip command unavailable; global routing skipped"; return 0; }
  route_down
  ip rule add fwmark "$MARK" lookup main pref 100 2>>"$LOG"
  ip -6 rule add fwmark "$MARK" lookup main pref 100 2>>"$LOG"
  ip rule add to 10.0.0.0/8 lookup main pref 1000 2>>"$LOG"
  ip rule add to 172.16.0.0/12 lookup main pref 1000 2>>"$LOG"
  ip rule add to 192.168.0.0/16 lookup main pref 1000 2>>"$LOG"
  ip rule add to 169.254.0.0/16 lookup main pref 1000 2>>"$LOG"
  ip -6 rule add to fc00::/7 lookup main pref 1000 2>>"$LOG"
  ip -6 rule add to fe80::/10 lookup main pref 1000 2>>"$LOG"
  ip route add default dev tun0 table "$TABLE" 2>>"$LOG"
  ip -6 route add default dev tun0 table "$TABLE" 2>>"$LOG"
  ip rule add lookup "$TABLE" pref 11000 2>>"$LOG"
  ip -6 rule add lookup "$TABLE" pref 11000 2>>"$LOG"
  [ -f "$BASE/dns.enabled" ] && dns_redirect_on
  log "Global routing policy enabled (table=$TABLE mark=$MARK)"
}
start(){
  [ -x "$MODDIR/bin/sshprotocol" ] || { log "ERROR: sshprotocol binary missing"; exit 1; }
  [ -x "$MODDIR/bin/hev-socks5-tunnel" ] || { log "ERROR: hev binary missing"; exit 1; }
  [ -f "$CFG" ] || { log "ERROR: config missing: $CFG"; exit 1; }
  p="$(cat "$PID" 2>/dev/null)"; h="$(cat "$HEVPID" 2>/dev/null)"
  if alive "$p" && alive "$h"; then log "Tunnel already running"; exit 0; fi
  "$MODDIR/bin/sshprotocol" check "$CFG" >> "$LOG" 2>&1 || { log "ERROR: configuration check failed"; exit 1; }
  if ! alive "$p"; then
    "$MODDIR/bin/sshprotocol" run "$CFG" >> "$LOG" 2>&1 &
    echo $! > "$PID"
    i=0; while [ "$i" -lt 20 ]; do p="$(cat "$PID")"; alive "$p" && break; sleep 1; i=$((i+1)); done
    alive "$(cat "$PID")" || { log "ERROR: SSH engine failed to start"; rm -f "$PID"; exit 1; }
  fi
  if ! alive "$h"; then
    "$MODDIR/bin/hev-socks5-tunnel" "$HEVCFG" >> "$BASE/logs/hev-console.log" 2>&1 &
    echo $! > "$HEVPID"
  fi
  sleep 2
  alive "$(cat "$HEVPID")" || { log "ERROR: HEV failed; stopping SSH"; stop_one "$PID"; exit 1; }
  if [ -f "$BASE/routing.enabled" ]; then route_up; fi
  log "Tunnel start command completed"
}
case "$1" in
 start) start ;;
 stop) route_down; stop_one "$HEVPID"; stop_one "$PID"; log "Tunnel stopped" ;;
 restart) "$0" stop; sleep 1; start ;;
 route-on) touch "$BASE/routing.enabled"; route_up ;;
 route-off) rm -f "$BASE/routing.enabled"; route_down; log "Global routing disabled" ;;
 dns-on) touch "$BASE/dns.enabled"; [ -f "$BASE/routing.enabled" ] && dns_redirect_on; log "DNS mapping enabled" ;;
 dns-off) rm -f "$BASE/dns.enabled"; dns_redirect_off; log "DNS mapping disabled" ;;
 dns-status) if [ -f "$BASE/dns.enabled" ]; then if [ -f "$BASE/routing.enabled" ]; then echo "DNS mapping: ACTIVE (HEV mapdns $DNS_IP:53)"; else echo "DNS mapping: ENABLED, waiting for global routing"; fi; else echo "DNS mapping: DISABLED"; fi; iptables -t nat -S OUTPUT 2>/dev/null | grep -F "$DNS_IP" || true ;;
 clear-logs) : > "$LOG"; : > "$BASE/logs/sshprotocol.log"; : > "$BASE/logs/hev.log"; : > "$BASE/logs/hev-console.log"; log "Logs cleared" ;;
 diagnose)
   echo "=== STATUS ==="; p="$(cat "$PID" 2>/dev/null)"; h="$(cat "$HEVPID" 2>/dev/null)"; alive "$p" && echo "SSH engine: running pid=$p" || echo "SSH engine: stopped"; alive "$h" && echo "HEV: running pid=$h" || echo "HEV: stopped"
   echo "=== TUN ==="; ip addr show tun0 2>&1
   echo "=== ROUTES ==="; ip rule show 2>&1; ip route show table "$TABLE" 2>&1
   echo "=== DNS ==="; "$0" dns-status
   echo "=== ANDROID DNS PROPERTIES ==="; getprop | grep -i 'net.dns' | head -n 12
   ;;
 status)
   s=STOPPED; p="$(cat "$PID" 2>/dev/null)"; h="$(cat "$HEVPID" 2>/dev/null)"
   if alive "$p" && alive "$h"; then s=RUNNING; elif alive "$p"; then s=SSH_ONLY; elif alive "$h"; then s=HEV_ONLY; fi
   [ -f "$BASE/routing.enabled" ] && s="$s + ROUTING"
   [ -f "$BASE/dns.enabled" ] && s="$s + DNS"
   echo "$s" ;;
 stats)
   rx="$(cat /sys/class/net/tun0/statistics/rx_bytes 2>/dev/null || echo 0)"; tx="$(cat /sys/class/net/tun0/statistics/tx_bytes 2>/dev/null || echo 0)"
   echo "RX_BYTES=$rx"; echo "TX_BYTES=$tx" ;;
 logs)
   for f in "$LOG" "$BASE/logs/sshprotocol.log" "$BASE/logs/hev.log" "$BASE/logs/hev-console.log"; do
     [ -f "$f" ] || continue
     echo "===== $(basename "$f") ====="; tail -n 100 "$f"
   done ;;
 *) echo "Usage: $0 {start|stop|restart|status|stats|logs|clear-logs|diagnose|route-on|route-off|dns-on|dns-off|dns-status}"; exit 2 ;;
esac
