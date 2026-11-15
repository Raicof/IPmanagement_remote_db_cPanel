#!/bin/bash
# Install / uninstall cpanel-remotedb-fw on a cPanel server (run as root).
#   ./install.sh              install (cron is NOT enabled until you confirm the dry run)
#   ./install.sh --enable     install and enable the 2-minute cron job
#   ./install.sh --uninstall  remove firewall rules, cron, logrotate and program files
set -euo pipefail

PREFIX=/opt/cpanel-remotedb-fw
CONF_DIR=/etc/cpanel-remotedb-fw
CRON=/etc/cron.d/cpanel-remotedb-fw
LOGROTATE=/etc/logrotate.d/cpanel-remotedb-fw
PY=/usr/bin/python3
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -x "$PY" ] || die "$PY not found"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "Python >= 3.9 required (found $("$PY" -V 2>&1)); older distros are not supported yet"

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$CRON"
  if [ -x "$PREFIX/cpanel-remotedb-fw" ]; then
    "$PY" -I "$PREFIX/cpanel-remotedb-fw" purge || echo "warning: purge failed, check the firewall" >&2
  fi
  rm -f "$LOGROTATE"
  rm -rf "$PREFIX"
  echo "uninstalled (kept $CONF_DIR, /var/lib/cpanel-remotedb-fw and /var/log/cpanel-remotedb-fw)"
  exit 0
fi

[ -d /usr/local/cpanel ] || echo "warning: /usr/local/cpanel not found - is this a cPanel server?" >&2

# Program files: root-owned and not writable by anyone else (root runs them from cron).
install -d -m 0755 -o root -g root "$PREFIX" "$PREFIX/remotedb_fw" "$PREFIX/remotedb_fw/firewalls"
install -m 0755 -o root -g root "$SRC/cpanel-remotedb-fw" "$PREFIX/cpanel-remotedb-fw"
install -m 0644 -o root -g root "$SRC"/remotedb_fw/*.py "$PREFIX/remotedb_fw/"
install -m 0644 -o root -g root "$SRC"/remotedb_fw/firewalls/*.py "$PREFIX/remotedb_fw/firewalls/"

install -d -m 0700 -o root -g root "$CONF_DIR" /var/lib/cpanel-remotedb-fw /var/log/cpanel-remotedb-fw
if [ ! -e "$CONF_DIR/config.json" ]; then
  echo '{}' > "$CONF_DIR/config.json"
  chmod 0600 "$CONF_DIR/config.json"
fi
install -m 0644 -o root -g root "$SRC/deploy/config.example.json" "$CONF_DIR/config.example.json"
install -m 0644 -o root -g root "$SRC/deploy/cpanel-remotedb-fw.logrotate" "$LOGROTATE"

echo "== detected firewall"
"$PY" -I "$PREFIX/cpanel-remotedb-fw" detect
echo "== dry run (nothing is changed)"
"$PY" -I "$PREFIX/cpanel-remotedb-fw" sync --dry-run

if [ "${1:-}" = "--enable" ]; then
  install -m 0644 -o root -g root "$SRC/deploy/cpanel-remotedb-fw.cron" "$CRON"
  echo "cron enabled: $CRON (every 2 minutes)"
else
  echo
  echo "Review the dry run above, then enable the cron job with: $0 --enable"
fi
