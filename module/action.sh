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
mkdir -p "$BASE/logs"; touch "$LOG"
log(){ echo "[$(date '+%F %T')] $*" >> "$LOG"; }
alive(){ [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
stop_one(){
  f="$1"; [ -f "$f" ] || return 0
  p="$(cat "$f" 2>/dev/null)"
  if alive "$p"; then kill "$p" 2>/dev/null; i=0; while alive "$p" && [ "$i" -lt 5 ]; do sleep 1; i=$((i+1)); done; alive "$p" && kill -9 "$p" 2>/dev/null; fi
  rm -f "$f"
}
route_down(){
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
  # Preserve local/LAN routes and bypass the tunnel for sockets marked by SSH/HEV.
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
  log "Global routing policy enabled (table=$TABLE mark=$MARK)"
}
start(){
  [ -x "$MODDIR/bin/sshprotocol" ] || { log "ERROR: sshprotocol binary missing"; exit 1; }
  [ -x "$MODDIR/bin/hev-socks5-tunnel" ] || { log "ERROR: hev binary missing"; exit 1; }
  [ -f "$CFG" ] || { log "ERROR: config missing: $CFG"; exit 1; }
  p="$(cat "$PID" 2>/dev/null)"; h="$(cat "$HEVPID" 2>/dev/null)"
  if alive "$p" && alive "$h"; then log "Tunnel already running"; exit 0; fi
  "$MODDIR/bin/sshprotocol" check "$CFG" >> "$LOG" 2>&1 || exit 1
  if ! alive "$p"; then
    "$MODDIR/bin/sshprotocol" run "$CFG" >> "$LOG" 2>&1 &
    echo $! > "$PID"
    i=0; while [ "$i" -lt 20 ]; do
      p="$(cat "$PID")"; alive "$p" && break
      sleep 1; i=$((i+1))
    done
    alive "$(cat "$PID")" || { log "ERROR: SSH engine failed to start"; rm -f "$PID"; exit 1; }
  fi
  if ! alive "$h"; then
    "$MODDIR/bin/hev-socks5-tunnel" "$HEVCFG" >> "$BASE/logs/hev-console.log" 2>&1 &
    echo $! > "$HEVPID"
  fi
  sleep 2
  alive "$(cat "$HEVPID")" || { log "ERROR: HEV failed; stopping SSH"; stop_one "$PID"; exit 1; }
  if [ -f "$BASE/routing.enabled" ]; then route_up; fi
  log "Tunnel started"
}
case "$1" in
 start) start ;;
 stop) route_down; stop_one "$HEVPID"; stop_one "$PID"; log "Tunnel stopped" ;;
 restart) "$0" stop; sleep 1; start ;;
 route-on) touch "$BASE/routing.enabled"; route_up ;;
 route-off) rm -f "$BASE/routing.enabled"; route_down ;;
 status)
   s=STOPPED; p="$(cat "$PID" 2>/dev/null)"; h="$(cat "$HEVPID" 2>/dev/null)"
   if alive "$p" && alive "$h"; then s=RUNNING; elif alive "$p"; then s=SSH_ONLY; fi
   [ -f "$BASE/routing.enabled" ] && s="$s + ROUTING"
   echo "$s";;
 stats)
   rx="$(cat /sys/class/net/tun0/statistics/rx_bytes 2>/dev/null || echo 0)"
   tx="$(cat /sys/class/net/tun0/statistics/tx_bytes 2>/dev/null || echo 0)"
   echo "RX_BYTES=$rx"; echo "TX_BYTES=$tx";;
 logs)
   tail -n 100 "$LOG"
   tail -n 100 "$BASE/logs/sshprotocol.log" 2>/dev/null
   tail -n 100 "$BASE/logs/hev.log" 2>/dev/null
   tail -n 50 "$BASE/logs/hev-console.log" 2>/dev/null;;
 *) echo "Usage: $0 {start|stop|restart|status|stats|logs|route-on|route-off}"; exit 2 ;;
esac
