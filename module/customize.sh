#!/system/bin/sh
ui_print " "
ui_print " SSH Protocol KSU"
ui_print " Installing standalone tunnel..."
BASE=/data/adb/sshprotocol
mkdir -p "$BASE/logs"
[ -f "$BASE/config.json" ] || cp "$MODPATH/config/config.json" "$BASE/config.json"
[ -f "$BASE/hev.yml" ] || cp "$MODPATH/config/hev.yml" "$BASE/hev.yml"
[ -f "$BASE/dns.enabled" ] || touch "$BASE/dns.enabled"
chmod 600 "$BASE/config.json"
chmod 700 "$BASE" "$BASE/logs"
chmod 0755 "$MODPATH/action.sh" "$MODPATH/service.sh" "$MODPATH/uninstall.sh"
chmod 0755 "$MODPATH/bin/sshprotocol" "$MODPATH/bin/hev-socks5-tunnel" 2>/dev/null
