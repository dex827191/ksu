#!/system/bin/sh
MODDIR=${0%/*}
BASE=/data/adb/sshprotocol
[ -f "$BASE/auto_start" ] || exit 0
"$MODDIR/action.sh" start
