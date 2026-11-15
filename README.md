# cpanel-remotedb-fw

Lets cPanel users open database access for their own IPs. An IP added under
**cPanel » Databases » Remote Database Access** is validated and, if it passes,
allowed through the server firewall to the MySQL port (3306). The tool runs from
root's cron every 2 minutes and works with **CSF, firewalld, nftables and
iptables**.

```
cron (every 2 min, root)
  └─ collect   hosts of every cPanel account (MySQL grants or cPanel API)
  └─ validate  security gates per host, duplicates, max 5 per user
  └─ detect    CSF > firewalld > nftables > iptables
  └─ apply     diff against the LIVE firewall, change only what differs,
               restart/reload only when something changed
  └─ log       sync.log, validation-errors.log (JSON lines), status.json
```

## Supported platforms

| Distro | Python | Typical firewall | Status |
|---|---|---|---|
| Ubuntu 24.04 | 3.12 | CSF / ufw(iptables) / nftables | v1 target |
| CloudLinux 10 | 3.12 | CSF / firewalld / nftables | v1 target |
| AlmaLinux 9, CloudLinux 9 | 3.9 | CSF / firewalld | v1 target |
| Ubuntu 22.04 | 3.10 | CSF / ufw(iptables) | should work, not the focus |
| AlmaLinux 8 | 3.6 | CSF / firewalld | **not yet** (needs the "older distros" release) |

It needs only the Python standard library. The installer refuses to run on Python older than 3.9.

## Install

```bash
./install.sh            # copies to /opt/cpanel-remotedb-fw, shows detection + a dry run
./install.sh --enable   # same, then installs /etc/cron.d/cpanel-remotedb-fw
./install.sh --uninstall
```

Before enabling cron on a server, read the dry-run output. In particular, check
the `WARNING:` lines, such as *"port 3306 is listed in TCP_IN … open to everyone"*.
If the port is already open to the whole world, per-IP rules change nothing.

## Commands

```bash
cpanel-remotedb-fw sync                  # what cron runs
cpanel-remotedb-fw sync --dry-run        # report + the exact firewall commands, nothing applied
cpanel-remotedb-fw sync --intake f.json --dry-run --firewall nftables
cpanel-remotedb-fw validate [--intake f.json]   # gates only; exit 3 if anything rejected/inactive
cpanel-remotedb-fw detect                # which firewall would be used
cpanel-remotedb-fw status                # last run (status.json)
cpanel-remotedb-fw purge [--dry-run]     # remove everything this tool added
```

Exit codes: `0` ok, `1` runtime/firewall error, `2` config error, `3` (validate) problems found.
For `sync`, stdout is empty and stderr only carries fatal errors, so cron mails root
only when something is actually broken.

## Where the IPs come from

cPanel stores a Remote Database Access host as a MySQL grant `'<cpuser>'@'<host>'`.

* `"source": "mysql"` (default). One `SELECT User, Host FROM mysql.user` per run, using
  `/root/.my.cnf`. This is the same data MySQL itself enforces, and a single query stays
  cheap on servers with hundreds of accounts.
* `"source": "cpanel_api"` runs `cpapi2 --user=<u> MysqlFE listhosts` once per account.
  This uses the official API but starts one process per account. If one account fails,
  that account keeps its last known-good IPs instead of losing access.

Accounts come from `/var/cpanel/users/`. Suspended accounts
(`/var/cpanel/suspended/<user>`) are skipped, so their access is closed.
Deleted accounts lose their rules on the next run.

## Validation gates

Every host is checked by these gates in order; the first failure rejects it:

| # | gate | rejects |
|---|---|---|
| 1 | `type` | non-string values |
| 2 | `empty` | blank entries |
| 3 | `length` | > 64 characters |
| 4 | `wildcard` | `*`, `%`, `_`, `?` (`%` and `_` are MySQL host wildcards) |
| 5 | `localhost` | `localhost`, `localhost.localdomain`, `ip6-localhost`, … |
| 6 | `all_access` | `any`, `all`, `0/0`, … |
| 7 | `charset` | hostnames and anything that is not a literal IP (spaces, `;`, `$()`, …) |
| 8 | `syntax` | invalid IPs; IPv4 with leading zeros (`010.1.1.1`, ambiguous octal) |
| 9 | `all_access` | `0.0.0.0`, `::`, any `/0` |
| 10 | `single_host` | ranges (`10.0.0.0/8`, `…/255.255.255.0`); `/32` and `/128` are accepted and normalised |
| 11 | `ip_version` | IPv6, only if `allow_ipv6` is false |
| 12 | `localhost` | loopback `127.0.0.0/8`, `::1`, `::ffff:127.x.x.x` |
| 13 | `special` | multicast, link-local, reserved/broadcast, `0.0.0.0/8` |
| 14 | `private` | RFC1918 / CGNAT / ULA, only if `allow_private_ips` is false |
| 15 | `blocked` | the server's own IPs (`/var/cpanel/mainip`, `/etc/ips`) and `blocked_ips` |

After that, each user's list goes through two more gates:

* **`duplicate`**: IPs are compared after normalisation (`::ffff:1.2.3.4` = `1.2.3.4/32` = `1.2.3.4`).
  The first copy is kept and each extra copy is logged.
* **`limit`**: at most `max_ips_per_user` (5) IPs are active. The **most recently added win**,
  and the oldest become *inactive*: they stay in cPanel but are not opened in the firewall.
  Neither MySQL nor the cPanel API records when a host was added, so the tool keeps a
  first-seen timestamp for each IP in `/var/lib/cpanel-remotedb-fw/state.json`. On the very first run
  there is no history yet, so the order the source returns is used.

The same IP listed by two accounts becomes one firewall rule, tagged with both users.

## Firewall behaviour

Each backend owns clearly named objects and never edits anything else.

| Backend | What it manages | Applies with | Service restart |
|---|---|---|---|
| **CSF** | `/etc/csf/cpanel-remotedb.allow` (+ one `Include` line in `csf.allow`), rules like `tcp\|in\|d=3306\|s=IP` | file write | `csf -r` **only when the file changed** |
| **firewalld** | ipsets `cpremotedb4` / `cpremotedb6`, one rich rule per family and port that references the set | `firewall-cmd --permanent` + runtime | `--reload` only when the ipsets/rich rules themselves change. Adding or removing IPs is applied live without a reload, so other tools' runtime rules (fail2ban etc.) are not wiped |
| **nftables** | chain `cpremotedb` inside **every** table that has an input filter chain, plus a `jump` at the top of that chain | one atomic `nft -f` transaction | never: restarting nftables would reload nftables.conf and wipe the rules |
| **iptables** | chain `CPREMOTEDB`, plus a jump at the top of `INPUT` (v4 and v6) | atomic `iptables-restore --noflush` | never (same reason) |

Notes:

* **Port-restricted rules.** In CSF a bare IP in `csf.allow` would open *every* port to that IP,
  so the port-restricted advanced syntax is used instead.
* **nftables needs a chain per table.** A drop in any input base chain is final, so a separate
  table of our own would do nothing. The rules therefore go into each table that filters input.
* **Reboots (nftables/iptables).** Their rules live only in the running firewall. After a reboot
  they are re-created by the next cron run, within 2 minutes. Until then the port stays
  **closed** (fail-closed).
* **Self-repair.** Each run compares against the live firewall. If someone tampers with our
  chain (extra rules, widened ranges) or removes it, the chain is rebuilt on the next run.
* **Failure handling.** If collecting IPs fails completely (for example MySQL is down), the run
  aborts **before** touching the firewall. Overlapping runs are prevented with a lock file.

## Logs

`/var/log/cpanel-remotedb-fw/`:

* **`validation-errors.log`** (JSON lines). One line per rejected or inactive entry:
  `{"time", "user", "host", "gate", "reason"}`. Each problem is logged **once**, not every
  2 minutes. If the user fixes it and later reintroduces it, it is logged again.
* **`sync.log`**: every firewall action, warning and run summary.
* **`status.json`**: the current state per user (active / inactive / rejected) and the rules.

A logrotate file is installed.

## Tests

```bash
python3 -m unittest discover -s tests -t .      # 160 tests, stdlib only
```

* `test_validation_gates.py`: one test class per gate.
* `test_user_gates.py`: duplicates and the 5-IP stack, including ordering across runs.
* `test_firewall_{csf,firewalld,nftables,iptables}.py`: the same scenarios run against every
  backend, fed by the intake JSON files in `tests/fixtures/`. They cover the initial sync,
  a second run that must change nothing and restart nothing, reconciliation after users
  change their lists, dry run, purge, and log contents. Backend-specific cases are covered
  as well.
* `test_sync.py`, `test_detect.py`, `test_sources.py`, `test_config.py`, `test_cli.py`:
  orchestration, distro/firewall detection profiles, sources, config, CLI, and a
  Python 3.9 compatibility check.

The firewall tests use **simulators** (`tests/fakes.py`) of `firewall-cmd`, `nft`,
`iptables(-restore)` and `csf`. They copy those tools' output formats and error
behaviour, and each one evaluates packets, so a test can assert "198.51.100.10 reaches
3306, 192.0.2.1 does not".

## Verify on a staging server before rollout

The code has not yet been run against real firewalls or a real cPanel. Check these:

1. `cpanel-remotedb-fw sync --dry-run` on one server per distro/firewall combination, then
   `sync -v`, and confirm access from an allowed IP and from a non-allowed IP.
2. **CSF:** that `Include` in `csf.allow` and the advanced rules (incl. IPv6) load after `csf -r`
   (`csf -l | grep 3306`).
3. **firewalld:** the default zone is the zone of the public interface (otherwise set `firewalld.zone`).
4. **cPanel's own grants:** cPanel may hold grants such as `localhost` or the server
   hostname for every account. These are rejected and logged once per account on the
   first run, with no access impact.
5. **Imunify360** (common on CloudLinux) runs its own firewall layer. Check that it does
   not block 3306 independently.
