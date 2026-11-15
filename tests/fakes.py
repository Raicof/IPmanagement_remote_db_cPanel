"""Test doubles: a fake command runner plus small simulators of the firewall
CLIs (firewall-cmd, nft, iptables/iptables-restore, csf).

The simulators implement the subset of each tool this project uses, with the
same output formats and the error behaviour that matters (atomic batches,
unknown chains/ipsets, family mismatches...).  Each one can also answer
"would a TCP packet from <ip> to <port> be accepted?", so tests assert the
*effect* of the rules, not just the commands that were issued.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import shlex
from typing import Callable, Dict, List, Optional

from remotedb_fw.runner import CommandError, Result

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def ok(stdout: str = "") -> Result:
    return Result(0, stdout, "")


def fail(stderr: str, code: int = 1) -> Result:
    return Result(code, "", stderr)


class FakeRunner:
    """Drop-in for remotedb_fw.runner.Runner."""

    def __init__(self, binaries=(), services=()):
        self.binaries = set(binaries)
        self.services = set(services)
        self.calls: List[List[str]] = []
        self.inputs: List[Optional[str]] = []
        self.handlers: Dict[str, Callable[[List[str], Optional[str]], Result]] = {
            "systemctl": self._systemctl
        }

    def add(self, binary: str, handler: Callable[[List[str], Optional[str]], Result]) -> None:
        self.binaries.add(binary)
        self.handlers[binary] = handler

    def which(self, binary: str) -> Optional[str]:
        name = os.path.basename(binary)
        return binary if (binary in self.binaries or name in self.binaries) else None

    def _systemctl(self, argv, _input):
        if argv[1:3] == ["is-active", "--quiet"]:
            return ok() if argv[3] in self.services else fail("inactive", 3)
        return fail("unsupported systemctl call")

    def run(self, argv, input_text=None, check=True, timeout=None) -> Result:
        self.calls.append(list(argv))
        self.inputs.append(input_text)
        name = os.path.basename(argv[0])
        handler = self.handlers.get(name) or self.handlers.get(argv[0])
        result = handler(list(argv), input_text) if handler else fail(f"{name}: not found", 127)
        if check and not result.ok:
            raise CommandError(argv, result.returncode, result.stdout, result.stderr)
        return result

    def commands(self, binary: str) -> List[List[str]]:
        name = os.path.basename(binary)
        return [c for c in self.calls if os.path.basename(c[0]) == name]


# ---------------------------------------------------------------------------
# firewalld
# ---------------------------------------------------------------------------


class FirewalldSim:
    def __init__(self, zone: str = "public", open_ports=(), services=("ssh",)):
        self.default_zone = zone
        config = {
            "ipsets": {},  # name -> {"family": "inet", "entries": set()}
            "rich": {zone: []},  # zone -> [rule strings]
            "ports": {zone: set(open_ports)},
            "services": {zone: set(services)},
        }
        self.permanent = config
        self.runtime = copy.deepcopy(config)
        self.reloads = 0

    def install(self, runner: FakeRunner) -> "FirewalldSim":
        runner.add("firewall-cmd", self.handle)
        return self

    def handle(self, argv, _input):
        args = argv[1:]
        permanent = "--permanent" in args
        args = [a for a in args if a != "--permanent"]
        cfg = self.permanent if permanent else self.runtime
        opts = {}
        flags = []
        for arg in args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                opts[key] = value
            else:
                flags.append(arg)
        zone = opts.get("--zone", self.default_zone)

        if flags == ["--state"]:
            return ok("running\n")
        if flags == ["--get-default-zone"]:
            return ok(self.default_zone + "\n")
        if flags == ["--reload"]:
            self.runtime = copy.deepcopy(self.permanent)
            self.reloads += 1
            return ok("success\n")
        if flags == ["--get-ipsets"]:
            return ok(" ".join(sorted(cfg["ipsets"])) + "\n")
        if "--new-ipset" in opts:
            if not permanent:
                return fail("Error: NOT_SUPPORTED_IN_RUNTIME", 2)
            name = opts["--new-ipset"]
            if name in cfg["ipsets"]:
                return fail(f"Error: NAME_CONFLICT: {name}", 26)
            family = opts.get("--option", "family=inet").split("=", 1)[1]
            cfg["ipsets"][name] = {"family": family, "entries": set()}
            return ok("success\n")
        if "--delete-ipset" in opts:
            name = opts["--delete-ipset"]
            if name not in cfg["ipsets"]:
                return fail(f"Error: INVALID_IPSET: {name}", 116)
            del cfg["ipsets"][name]
            return ok("success\n")
        if "--ipset" in opts:
            name = opts["--ipset"]
            if name not in cfg["ipsets"]:
                return fail(f"Error: INVALID_IPSET: {name}", 116)
            ipset = cfg["ipsets"][name]
            if flags == ["--get-entries"]:
                return ok("".join(e + "\n" for e in sorted(ipset["entries"])))
            for op in ("add", "remove"):
                path = opts.get(f"--{op}-entries-from-file")
                if path is None:
                    continue
                with open(path, "r", encoding="utf-8") as handle:
                    entries = [line.strip() for line in handle if line.strip()]
                want = 4 if ipset["family"] == "inet" else 6
                for entry in entries:
                    if ipaddress.ip_address(entry).version != want:
                        return fail(f"Error: INVALID_ENTRY: {entry}", 136)
                for entry in entries:
                    (ipset["entries"].add if op == "add" else ipset["entries"].discard)(entry)
                return ok("success\n")
        if flags == ["--list-rich-rules"]:
            return ok("".join(r + "\n" for r in cfg["rich"].get(zone, [])))
        if flags == ["--list-ports"]:
            return ok(" ".join(sorted(cfg["ports"].get(zone, ()))) + "\n")
        if flags == ["--list-services"]:
            return ok(" ".join(sorted(cfg["services"].get(zone, ()))) + "\n")
        if "--add-rich-rule" in opts:
            rule = opts["--add-rich-rule"]
            ref = rule.split('ipset="', 1)[1].split('"', 1)[0] if 'ipset="' in rule else None
            if ref and ref not in cfg["ipsets"]:
                return fail(f"Error: INVALID_IPSET: {ref}", 116)
            rules = cfg["rich"].setdefault(zone, [])
            if rule not in rules:
                rules.append(rule)
            return ok("success\n")
        if "--remove-rich-rule" in opts:
            rules = cfg["rich"].setdefault(zone, [])
            if opts["--remove-rich-rule"] in rules:
                rules.remove(opts["--remove-rich-rule"])
            return ok("success\n")
        return fail(f"firewall-cmd sim: unsupported {argv}")

    def allows(self, ip: str, port: int, runtime: bool = True) -> bool:
        """Effective verdict in the default zone (runtime config)."""
        cfg = self.runtime if runtime else self.permanent
        zone = self.default_zone
        if f"{port}/tcp" in cfg["ports"].get(zone, set()):
            return True
        addr = ipaddress.ip_address(ip)
        for rule in cfg["rich"].get(zone, []):
            attrs = dict(part.split("=", 1) for part in shlex.split(rule) if "=" in part)
            if attrs.get("port") != str(port) or attrs.get("protocol") != "tcp":
                continue
            ipset = cfg["ipsets"].get(attrs.get("ipset"))
            if ipset and str(addr) in ipset["entries"]:
                return True
        return False


# ---------------------------------------------------------------------------
# nftables
# ---------------------------------------------------------------------------


class NftError(Exception):
    pass


class NftSim:
    """Holds a tiny ruleset in nft's JSON model."""

    def __init__(self):
        self.tables: Dict[tuple, dict] = {}  # (family, name) -> {"chains": {name: chain}}
        self.next_handle = 1
        self.batches: List[str] = []

    # --- building the "admin" ruleset ------------------------------------
    def add_table(self, family: str, name: str) -> None:
        self.tables.setdefault((family, name), {"chains": {}})

    def add_chain(self, family, table, name, hook=None, policy="accept", prio=0, type_="filter"):
        chains = self.tables[(family, table)]["chains"]
        chain = {"name": name, "rules": []}
        if hook:
            chain.update({"hook": hook, "policy": policy, "prio": prio, "type": type_})
        chains[name] = chain
        return chain

    def add_rule(self, family, table, chain, expr, comment=None, insert=False):
        rule = {"handle": self.next_handle, "expr": expr}
        self.next_handle += 1
        if comment:
            rule["comment"] = comment
        rules = self.tables[(family, table)]["chains"][chain]["rules"]
        rules.insert(0, rule) if insert else rules.append(rule)
        return rule

    def install(self, runner: FakeRunner) -> "NftSim":
        runner.add("nft", self.handle)
        return self

    # --- CLI ----------------------------------------------------------------
    def handle(self, argv, input_text):
        if argv[1:] == ["-j", "list", "ruleset"]:
            return ok(json.dumps(self.to_json()))
        if argv[1:] == ["-f", "-"]:
            self.batches.append(input_text)
            snapshot = copy.deepcopy((self.tables, self.next_handle))
            try:
                for line in input_text.splitlines():
                    if line.strip():
                        self._exec(line)
            except NftError as exc:
                self.tables, self.next_handle = snapshot  # atomic: all or nothing
                return fail(f"Error: {exc}")
            return ok()
        return fail(f"nft sim: unsupported {argv}")

    def to_json(self) -> dict:
        out = [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]
        for (family, name), table in self.tables.items():
            out.append({"table": {"family": family, "name": name, "handle": 1}})
            for chain in table["chains"].values():
                obj = {"family": family, "table": name, "name": chain["name"], "handle": 1}
                for key in ("type", "hook", "prio", "policy"):
                    if key in chain:
                        obj[key] = chain[key]
                out.append({"chain": obj})
            for chain in table["chains"].values():
                for rule in chain["rules"]:
                    obj = {"family": family, "table": name, "chain": chain["name"],
                           "handle": rule["handle"], "expr": rule["expr"]}
                    if "comment" in rule:
                        obj["comment"] = rule["comment"]
                    out.append({"rule": obj})
        return {"nftables": out}

    def _chain(self, family, table, name):
        try:
            return self.tables[(family, table)]["chains"][name]
        except KeyError:
            raise NftError(f"No such file or directory: chain {family} {table} {name}") from None

    def _exec(self, line: str) -> None:
        tokens = shlex.split(line)
        verb, kind = tokens[0], tokens[1]
        if kind == "chain":
            family, table, name = tokens[2:5]
            if (family, table) not in self.tables:
                raise NftError(f"No such table {family} {table}")
            chains = self.tables[(family, table)]["chains"]
            if verb == "add":
                chains.setdefault(name, {"name": name, "rules": []})
            elif verb == "flush":
                self._chain(family, table, name)["rules"] = []
            elif verb == "delete":
                chain = self._chain(family, table, name)
                if chain["rules"]:
                    raise NftError("Device or resource busy: chain not empty")
                for other in chains.values():
                    for rule in other["rules"]:
                        if any(e.get("jump", {}).get("target") == name for e in rule["expr"]):
                            raise NftError("Device or resource busy: chain in use")
                del chains[name]
            return
        if kind == "rule":
            family, table, chain_name = tokens[2:5]
            chain = self._chain(family, table, chain_name)
            rest = tokens[5:]
            if verb == "delete":
                handle = int(rest[1])
                before = len(chain["rules"])
                chain["rules"] = [r for r in chain["rules"] if r["handle"] != handle]
                if len(chain["rules"]) == before:
                    raise NftError(f"Could not process rule: handle {handle}")
                return
            expr, comment = self._parse_rule(family, table, rest)
            self.add_rule(family, table, chain_name, expr, comment, insert=(verb == "insert"))
            return
        raise NftError(f"syntax error: {line}")

    def _parse_rule(self, family, table, toks):
        expr, comment, i = [], None, 0
        while i < len(toks):
            tok = toks[i]
            if tok in ("ip", "ip6") and toks[i + 1] == "saddr":
                if family == "ip" and tok == "ip6" or family == "ip6" and tok == "ip":
                    raise NftError(f"conflicting protocols specified: {tok} in {family} table")
                addr = ipaddress.ip_address(toks[i + 2])
                if (tok == "ip") != (addr.version == 4):
                    raise NftError(f"{tok} saddr with wrong address family")
                expr.append({"match": {"op": "==", "left": {"payload": {
                    "protocol": tok, "field": "saddr"}}, "right": str(addr)}})
                i += 3
            elif tok == "tcp" and toks[i + 1] == "dport":
                expr.append({"match": {"op": "==", "left": {"payload": {
                    "protocol": "tcp", "field": "dport"}}, "right": int(toks[i + 2])}})
                i += 3
            elif tok in ("accept", "drop"):
                expr.append({tok: None})
                i += 1
            elif tok == "jump":
                if toks[i + 1] not in self.tables[(family, table)]["chains"]:
                    raise NftError(f"Could not process rule: chain {toks[i + 1]} not found")
                expr.append({"jump": {"target": toks[i + 1]}})
                i += 2
            elif tok == "comment":
                comment = toks[i + 1]
                if len(comment.encode()) > 128:
                    raise NftError("comment too long")
                i += 2
            else:
                raise NftError(f"syntax error near {tok}")
        return expr, comment

    # --- packet evaluation ----------------------------------------------------
    def _eval_chain(self, family, table, chain, ip, port) -> Optional[str]:
        addr = ipaddress.ip_address(ip)
        for rule in chain["rules"]:
            matched = True
            verdict = None
            for e in rule["expr"]:
                if "match" in e:
                    p = e["match"]["left"]["payload"]
                    if p["field"] == "saddr":
                        want_v = 4 if p["protocol"] == "ip" else 6
                        if addr.version != want_v or str(addr) != e["match"]["right"]:
                            matched = False
                    elif p["field"] == "dport" and port != e["match"]["right"]:
                        matched = False
                elif "accept" in e:
                    verdict = "accept"
                elif "drop" in e:
                    verdict = "drop"
                elif "jump" in e:
                    verdict = ("jump", e["jump"]["target"])
                if not matched:
                    break
            if not matched:
                continue
            if isinstance(verdict, tuple):
                target = self.tables[(family, table)]["chains"][verdict[1]]
                sub = self._eval_chain(family, table, target, ip, port)
                if sub:
                    return sub
                continue
            if verdict:
                return verdict
        return None

    def allows(self, ip: str, port: int) -> bool:
        """Every input base chain (any table) must accept the packet."""
        version = ipaddress.ip_address(ip).version
        for (family, table), tdata in self.tables.items():
            if family == "ip" and version != 4 or family == "ip6" and version != 6:
                continue
            for chain in tdata["chains"].values():
                if chain.get("hook") != "input":
                    continue
                verdict = self._eval_chain(family, table, chain, ip, port) or chain["policy"]
                if verdict == "drop":
                    return False
        return True


# ---------------------------------------------------------------------------
# iptables / ip6tables
# ---------------------------------------------------------------------------


class IptablesSim:
    """filter table for one family; handles iptables -S and iptables-restore."""

    BUILTIN = ("INPUT", "FORWARD", "OUTPUT")

    def __init__(self, version: int = 4, input_policy: str = "ACCEPT"):
        self.version = version
        self.chains: Dict[str, List[str]] = {c: [] for c in self.BUILTIN}
        self.policies = {c: "ACCEPT" for c in self.BUILTIN}
        self.policies["INPUT"] = input_policy
        self.restores: List[str] = []

    @property
    def names(self):
        if self.version == 4:
            return "iptables", "iptables-restore"
        return "ip6tables", "ip6tables-restore"

    def install(self, runner: FakeRunner) -> "IptablesSim":
        runner.add(self.names[0], self.handle_cli)
        runner.add(self.names[1], self.handle_restore)
        return self

    def _canon(self, chain: str, spec: List[str]) -> str:
        spec = list(spec)
        if "-s" in spec:
            i = spec.index("-s") + 1
            iface = ipaddress.ip_interface(spec[i])
            if iface.version != self.version:
                raise ValueError(f"host/network `{spec[i]}' not found")
            spec[i] = f"{iface.ip}/{iface.network.prefixlen}"
        if "--comment" in spec:
            i = spec.index("--comment") + 1
            if len(spec[i]) > 256:
                raise ValueError("comment too long")
            spec[i] = f'"{spec[i]}"'
        return " ".join([f"-A {chain}"] + spec)

    def add_rule(self, chain: str, spec: str, insert: bool = False) -> None:
        line = self._canon(chain, shlex.split(spec))
        self.chains[chain].insert(0, line) if insert else self.chains[chain].append(line)

    def handle_cli(self, argv, _input):
        args = [a for a in argv[1:] if a != "-w"]
        if len(args) == 2 and args[0] == "-S":
            chain = args[1]
            if chain not in self.chains:
                return fail(f"{self.names[0]}: No chain/target/match by that name.")
            head = f"-P {chain} {self.policies[chain]}" if chain in self.BUILTIN else f"-N {chain}"
            return ok("\n".join([head] + self.chains[chain]) + "\n")
        return fail(f"iptables sim: unsupported {argv}")

    def handle_restore(self, argv, input_text):
        if "--noflush" not in argv:
            return fail("sim expects --noflush (never flush the whole table)")
        self.restores.append(input_text)
        chains = copy.deepcopy(self.chains)
        try:
            self._restore(input_text)
        except (ValueError, KeyError, IndexError) as exc:
            self.chains = chains
            return fail(f"{self.names[1]}: line failed: {exc}")
        return ok()

    def _restore(self, text: str) -> None:
        lines = [l for l in text.splitlines() if l.strip()]
        if lines[0] != "*filter" or lines[-1] != "COMMIT":
            raise ValueError("bad table framing")
        for line in lines[1:-1]:
            if line.startswith(":"):
                name = line[1:].split()[0]
                self.chains[name] = []  # create, or flush if it exists
                continue
            tokens = shlex.split(line)
            op, chain = tokens[0], tokens[1]
            if chain not in self.chains:
                raise KeyError(f"chain {chain} does not exist")
            if op == "-F":
                self.chains[chain] = []
            elif op == "-X":
                if self.chains[chain]:
                    raise ValueError("chain not empty")
                if any(f"-j {chain}" in r for rules in self.chains.values() for r in rules):
                    raise ValueError("chain still referenced")
                del self.chains[chain]
            elif op == "-A":
                self._check_target(tokens)
                self.chains[chain].append(self._canon(chain, tokens[2:]))
            elif op == "-I":
                pos = int(tokens[2]) - 1
                self._check_target(tokens)
                self.chains[chain].insert(pos, self._canon(chain, tokens[3:]))
            elif op == "-D":
                target = self._canon(chain, tokens[2:])
                self.chains[chain].remove(target)
            else:
                raise ValueError(f"unknown op {op}")

    def _check_target(self, tokens):
        target = tokens[tokens.index("-j") + 1]
        if target not in ("ACCEPT", "DROP", "REJECT", "RETURN") and target not in self.chains:
            raise KeyError(f"target {target} does not exist")

    def _eval(self, chain: str, ip: str, port: int) -> Optional[str]:
        addr = ipaddress.ip_address(ip)
        for line in self.chains[chain]:
            tokens = shlex.split(line)
            opts = dict(zip(tokens[::2], tokens[1::2]))
            if "-s" in opts and addr not in ipaddress.ip_network(opts["-s"], strict=False):
                continue
            if "--dport" in opts and int(opts["--dport"]) != port:
                continue
            target = opts["-j"]
            if target in ("ACCEPT", "DROP", "REJECT"):
                return target
            if target == "RETURN":
                return None
            sub = self._eval(target, ip, port)
            if sub:
                return sub
        return None

    def allows(self, ip: str, port: int) -> bool:
        return (self._eval("INPUT", ip, port) or self.policies["INPUT"]) == "ACCEPT"


# ---------------------------------------------------------------------------
# CSF
# ---------------------------------------------------------------------------


class CsfSim:
    """Files in a temp dir + a fake `csf` binary.  `allows` models CSF rules:
    ports in TCP_IN are open to all; csf.allow (with Include) advanced rules
    ``tcp|in|d=PORT|s=IP`` open PORT to IP; everything else is dropped."""

    def __init__(self, root: str, tcp_in: str = "20,21,22,25,53,80,110,143,443,465,587,993,995",
                 ipv6: bool = True, allow_text: str = "# csf.allow\n1.2.3.4 # admin office\n"):
        self.root = root
        self.allow_file = os.path.join(root, "csf.allow")
        self.conf_file = os.path.join(root, "csf.conf")
        self.include_file = os.path.join(root, "cpanel-remotedb.allow")
        self.bin = os.path.join(root, "csf")
        with open(self.allow_file, "w") as handle:
            handle.write(allow_text)
        with open(self.conf_file, "w") as handle:
            handle.write(f'TESTING = "0"\nTCP_IN = "{tcp_in}"\nTCP6_IN = "{tcp_in}"\n'
                         f'IPV6 = "{1 if ipv6 else 0}"\n')
        self.restarts = 0
        self.loaded: Optional[List[str]] = None  # rules active after last restart

    def config(self) -> dict:
        return {"csf": {"bin": self.bin, "allow_file": self.allow_file,
                        "include_file": self.include_file, "conf_file": self.conf_file,
                        "disable_file": os.path.join(self.root, "csf.disable")}}

    def install(self, runner: FakeRunner) -> "CsfSim":
        runner.add(self.bin, self.handle)
        return self

    def handle(self, argv, _input):
        if argv[1:] == ["-r"]:
            self.restarts += 1
            self.loaded = self._read_allow(self.allow_file)
            return ok("csf restarted\n")
        return fail("csf sim: unsupported")

    def _read_allow(self, path: str, depth: int = 0) -> List[str]:
        lines = []
        with open(path) as handle:
            for raw in handle:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("Include "):
                    if depth < 3:
                        lines.extend(self._read_allow(line.split(None, 1)[1], depth + 1))
                    continue
                lines.append(line)
        return lines

    def allows(self, ip: str, port: int) -> bool:
        if self.loaded is None:
            raise AssertionError("csf was never restarted - rules not loaded")
        with open(self.conf_file) as handle:
            conf = handle.read()
        tcp_in = conf.split('TCP_IN = "', 1)[1].split('"', 1)[0].split(",")
        if str(port) in tcp_in:
            return True
        for rule in self.loaded:
            if "|" not in rule:
                if rule == ip:
                    return True  # bare IP = all ports
                continue
            fields = dict(part.split("=", 1) for part in rule.split("|") if "=" in part)
            if rule.startswith("tcp|in|") and fields.get("d") == str(port) \
                    and fields.get("s") == ip:
                return True
        return False
