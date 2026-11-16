#!/system/bin/sh
MODDIR=${0%/*}
"$MODDIR/action.sh" stop >/dev/null 2>&1
