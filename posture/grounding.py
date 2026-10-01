"""CPE-to-service-port grounding — maps device software (CPE) to the network
ports those services typically listen on.

This is the posture-side half of *finer port-to-CVE mapping*: the forebode
attack-graph classifier uses this mapping to suppress a CVE's network role
when the affected service's port is not truly exposed (not both
firewall-allowed AND listening).  For example, a CVE targeting OpenSSH
(``cpe:2.3:a:openssh:openssh``) is suppressed when port 22 is not in the
device's truly-exposed set.

The mapping is a **static knowledge table**, not a live probe.  It covers
common server software whose default ports are well-known.  Software not in
the table returns an empty list — the caller treats an empty list as "no
port-specific grounding available; do not suppress on this axis" (degrade
gracefully, same as the firewall/interface grounding observers).

CPE 2.3 format::

    cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>

The mapping key is `<part>:<vendor>:<product>` (case-insensitive).
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from .sources.live_cpe import enrich_device_matchers


# ---------------------------------------------------------------------------
# Static CPE-to-port mapping
# ---------------------------------------------------------------------------
#
# Keys are "part:vendor:product" in lower case.  Values are the TCP ports the
# service listens on by default.  A service that can run on arbitrary ports
# (e.g. a web framework) is omitted — only software with a strong default
# convention is included, so the mapping is high-precision (low false-suppress).
#
# Rationale for each entry is the IANA well-known-port registry or the
# project's documented default configuration.

_CPE_PORTS: dict[str, list[int]] = {
    # --- SSH ---
    "a:openssh:openssh": [22],
    "a:openbsd:openssh": [22],

    # --- Web servers ---
    "a:apache:http_server": [80, 443],
    "a:apache:httpd": [80, 443],
    "a:nginx:nginx": [80, 443],
    "a:lighttpd:lighttpd": [80, 443],
    "a:caddy:caddy": [80, 443],
    "a:traefik:traefik": [80, 443],
    "a:cherokee:cherokee": [80, 443],

    # --- Database servers ---
    "a:postgresql:postgresql": [5432],
    "a:mysql:mysql": [3306],
    "a:mariadb:mariadb": [3306],
    "a:percona:percona_server": [3306],
    "a:redis:redis": [6379],
    "a:mongodb:mongodb": [27017],
    "a:elastic:elasticsearch": [9200, 9300],
    "a:influxdb:influxdb": [8086],
    "a:couchdb:couchdb": [5984],

    # --- Mail servers ---
    "a:postfix:postfix": [25, 587],
    "a:openbsd:opensmtpd": [25, 587],
    "a:dovecot:dovecot": [143, 993],
    "a:courier:courier_imap": [143, 993],
    "a:proftpd:proftpd": [21],
    "a:vsftpd:vsftpd": [21],
    "a:pureftpd:pure-ftpd": [21],

    # --- DNS / DHCP ---
    "a:isc:bind": [53],
    "a:isc:bind9": [53],
    "a:unbound:unbound": [53],
    "a:powerdns:powerdns": [53],
    "a:isc:dhcpd": [67, 68],
    "a:kea:kea": [67, 68],

    # --- File sharing ---
    "a:samba:samba": [139, 445],

    # --- Monitoring / DevOps ---
    "a:grafana:grafana": [3000],
    "a:prometheus:prometheus": [9090],
    "a:zabbix:zabbix": [10050, 10051],
    "a:nagios:nagios": [5666],
    "a:jenkins:jenkins": [8080],
    "a:gitlab:gitlab": [80, 443],
    "a:hashicorp:consul": [8500],
    "a:hashicorp:vault": [8200],
    "a:hashicorp:nomad": [4646],
    "a:rabbitmq:rabbitmq": [5672, 15672],

    # --- Other servers ---
    "a:squid:squid": [3128],
    "a:varnish:varnish": [6081],
    "a:nginx:nginx_unit": [8000],
    "a:apache:tengine": [80, 443],
    "a:php:php": [9000],
    "a:tomcat:tomcat": [8080],
    "a:eclipse:jetty": [8080],
    "a:wildfly:wildfly": [8080, 9990],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def cpe_port_key(cpe: str) -> str:
    """Extract the `part:vendor:product` key from a CPE 2.3 string.

    >>> cpe_port_key("cpe:2.3:a:openssh:openssh:9.6p1")
    'a:openssh:openssh'

    Returns `""` for a malformed CPE (fewer than 5 colon-separated parts).
    The caller treats an empty key as "no mapping available".
    """
    parts = cpe.split(":")
    # cpe:2.3:<part>:<vendor>:<product> = at least 5 parts
    if len(parts) < 5:
        return ""
    return f"{parts[2]}:{parts[3]}:{parts[4]}".lower()


def ports_for_cpe(cpe: str) -> list[int]:
    """Default service ports for the given CPE 2.3 string.

    Returns an empty list when the CPE is not in the mapping or is malformed.
    An empty list means "no port-specific grounding; do not suppress on this
    axis" — the caller degrades gracefully.
    """
    key = cpe_port_key(cpe)
    if not key:
        return []
    return list(_CPE_PORTS.get(key, []))


def grounding_for_matchers(matchers: list[dict]) -> dict[str, list[int]]:
    """Map a device's CPE matchers to a `{cpe: [ports]}` grounding dict.

    Only matchers with `type == "nvd_cpe"` and a non-empty `cpe` value are
    considered.  CPEs not in the static mapping are omitted from the result
    (not included with an empty list), so the caller can distinguish "this CPE
    maps to no known ports" from "this CPE was not in the matchers at all".

    >>> grounding_for_matchers([
    ...     {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1"},
    ...     {"type": "nvd_cpe", "cpe": "cpe:2.3:o:linux:linux_kernel:6.18"},
    ... ])
    {'cpe:2.3:a:openssh:openssh:9.6p1': [22]}
    """
    result: dict[str, list[int]] = {}
    for m in matchers:
        if m.get("type") != "nvd_cpe":
            continue
        cpe = m.get("cpe", "")
        if not cpe:
            continue
        ports = ports_for_cpe(cpe)
        if ports:
            result[cpe] = ports
    return result


def known_cpe_keys() -> list[str]:
    """All CPE keys in the static mapping (for introspection / testing)."""
    return sorted(_CPE_PORTS.keys())



# ---------------------------------------------------------------------------
# Composite device grounding — all axes in one call
# ---------------------------------------------------------------------------

def _is_loopback_bind(bind) -> bool:
    """True when a socket bind address is loopback (host-only reachability)."""
    if not bind:
        return False
    b = str(bind).strip().lower()
    if b in ("localhost", "::1"):
        return True
    if b.startswith("127."):
        return True
    return False


def _is_loopback_ip(ip: str) -> bool:
    """True when the IP is in the 127/8 IPv4 loopback range or is ::1."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback


def _is_loopback_iface(name: str) -> bool:
    """Heuristic: the loopback interface is conventionally named ``lo``."""
    return str(name).strip().lower() == "lo"


def _parse_firewall(device: dict) -> tuple[set[str], set[str], str]:
    """Extract (allowed_ports, denied_ports, default_policy) from a device's
    firewall snapshot.

    Returns sets of ``"proto/port"`` strings and the lower-cased default
    policy (``""`` when absent).  When no firewall data is supplied, all sets
    are empty and the default policy is ``""``.
    """
    fw = device.get("firewall")
    if not isinstance(fw, dict):
        path = device.get("firewall_path")
        if path:
            fw = _load_json(path)
    if not isinstance(fw, dict):
        return set(), set(), ""

    rules = fw.get("rules")
    if not isinstance(rules, list):
        rules = []
    default_policy = str(fw.get("default_policy") or "").strip().lower()

    allowed: set[str] = set()
    denied: set[str] = set()
    for r in rules:
        if not isinstance(r, dict):
            continue
        action = str(r.get("action") or "").strip().lower()
        proto = str(r.get("proto") or "").strip().lower()
        port = r.get("port")
        direction = str(r.get("direction") or "inbound").strip().lower()
        if direction != "inbound" or not proto or port is None:
            continue
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        key = f"{proto}/{port_i}"
        if action == "allow":
            allowed.add(key)
        elif action == "deny":
            denied.add(key)
    return allowed, denied, default_policy


def _parse_local_exposure(device: dict) -> tuple[set[str], set[str]]:
    """Extract (exposed_ports, loopback_ports) from a device's socket capture.

    Returns sets of ``"proto/port"`` strings.  ``exposed_ports`` are sockets
    with a non-loopback (or missing) bind; ``loopback_ports`` are sockets
    bound to 127/8, ::1, or localhost.  When no exposure data is supplied,
    both sets are empty.
    """
    surface = device.get("exposure")
    if not isinstance(surface, list):
        path = device.get("exposure_path")
        if path:
            surface = _load_json(path)
    if not isinstance(surface, list):
        return set(), set()

    exposed: set[str] = set()
    loopback: set[str] = set()
    for s in surface:
        if not isinstance(s, dict):
            continue
        proto = str(s.get("proto") or "").strip().lower()
        port = s.get("port")
        if not proto or port is None:
            continue
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        key = f"{proto}/{port_i}"
        if _is_loopback_bind(s.get("bind")):
            loopback.add(key)
        else:
            exposed.add(key)
    return exposed, loopback


def _parse_interfaces(device: dict) -> tuple[bool, list[str]]:
    """Extract (has_network_access, reachable_subnets) from a device's
    interface snapshot.

    ``has_network_access`` is True when at least one UP interface has a
    non-loopback address.  ``reachable_subnets`` is the list of subnet CIDR
    strings from those interfaces.  When no interface data is supplied,
    returns ``(False, [])``.
    """
    interfaces = device.get("interfaces")
    if not isinstance(interfaces, list):
        path = device.get("interfaces_path")
        if path:
            interfaces = _load_json(path)
    if not isinstance(interfaces, list):
        return False, []

    has_net = False
    subnets: list[str] = []
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        state = str(iface.get("state") or "").strip().lower()
        if state != "up":
            continue
        name = str(iface.get("name") or "").strip()
        is_lo = _is_loopback_iface(name)
        addresses = iface.get("addresses")
        if not isinstance(addresses, list):
            continue
        for addr in addresses:
            if not isinstance(addr, dict):
                continue
            ip = str(addr.get("ip") or "").strip()
            prefix = addr.get("prefix")
            if not ip or prefix is None:
                continue
            try:
                prefix_i = int(prefix)
            except (TypeError, ValueError):
                continue
            loopback = is_lo or _is_loopback_ip(ip)
            try:
                net = ipaddress.ip_network(f"{ip}/{prefix_i}", strict=False)
            except ValueError:
                continue
            if not loopback:
                has_net = True
                subnets.append(str(net))
    return has_net, subnets


def _load_json(path: str | Path) -> dict | list | None:
    """Read a JSON file from the given path.  Returns the parsed content on
    success, or ``None`` when the file is not found or unparseable."""
    p = Path(path)
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    return data


def device_grounding(device: dict, *, use_live_cpe: bool = False) -> dict:
    """Compose all grounding axes into a single device grounding assessment.

    This is the posture-side API that a consumer (forebode's attack graph, a
    fleet dashboard, or any downstream tool) calls to get the complete
    grounding picture for a device in one call, rather than running each
    observer separately and composing the results.

    The function reads the device's supplied snapshots — firewall rules,
    listening sockets, network interfaces, and CPE matchers — and produces a
    grounding dict with these keys:

    - ``truly_exposed_ports``: ``set[str]`` of ``"proto/port"`` strings that
      are *both* firewall-allowed AND listening on a non-loopback bind.  A
      port in this set is genuinely reachable from the network.  When the
      firewall default policy is ``"allow"``, ports that are listening
      (non-loopback) and not explicitly denied are also included.
    - ``firewall_allowed``: ``set[str]`` of ports the firewall explicitly
      allows (inbound).
    - ``firewall_denied``: ``set[str]`` of ports the firewall explicitly
      denies (inbound).
    - ``listening_exposed``: ``set[str]`` of ports with a non-loopback
      (or missing) bind — sockets that are listening and potentially
      network-reachable.
    - ``listening_loopback``: ``set[str]`` of ports bound to loopback.
    - ``has_network_access``: ``bool`` — whether the device has at least one
      UP non-loopback interface address.
    - ``reachable_subnets``: ``list[str]`` of subnet CIDR strings from
      non-loopback UP interfaces.
    - ``cpe_ports``: ``dict[str, list[int]]`` mapping the device's CPE
      matchers to their default service ports.  When ``use_live_cpe`` is
      ``True``, live-discovered CPE matchers (from the host's package manager)
      are merged into the device's matchers before computing this dict.
    - ``firewall_default_policy``: ``str`` — ``"deny"``, ``"allow"``, or
      ``""`` (absent).

    All axes degrade gracefully: a missing snapshot yields an empty set or
    ``False``, never an error.  The caller treats an empty
    ``truly_exposed_ports`` as "no port is provably reachable" and an empty
    ``cpe_ports`` as "no CPE-specific grounding available".

    Example::

        grounding = device_grounding({
            "firewall": {"default_policy": "deny", "rules": [
                {"action": "allow", "proto": "tcp", "port": 22, "direction": "inbound"},
            ]},
            "exposure": [
                {"proto": "tcp", "port": 22, "bind": "0.0.0.0"},
            ],
            "interfaces": [
                {"name": "eth0", "state": "up", "addresses": [
                    {"ip": "192.168.1.42", "prefix": 24},
                ]},
            ],
            "matchers": [
                {"type": "nvd_cpe", "cpe": "cpe:2.3:a:openssh:openssh:9.6p1"},
            ],
        })
        # grounding["truly_exposed_ports"] == {"tcp/22"}
        # grounding["has_network_access"] == True
        # grounding["cpe_ports"] == {"cpe:2.3:a:openssh:openssh:9.6p1": [22]}
    """
    fw_allowed, fw_denied, fw_default = _parse_firewall(device)
    listening_exposed, listening_loopback = _parse_local_exposure(device)
    has_net, subnets = _parse_interfaces(device)
    matchers = device.get("matchers") or []
    if use_live_cpe:
        matchers = enrich_device_matchers(device)
    cpe_ports = grounding_for_matchers(matchers)

    # Truly exposed = port is listening (non-loopback) AND firewall allows it.
    # When the firewall default policy is "allow", a listening port that is
    # not explicitly denied is also truly exposed (the firewall permits by
    # default).  When the default policy is "deny" or absent, only ports with
    # an explicit allow rule are truly exposed.
    truly_exposed: set[str] = set()
    for key in listening_exposed:
        if key in fw_allowed:
            truly_exposed.add(key)
        elif key not in fw_denied and fw_default == "allow":
            truly_exposed.add(key)

    return {
        "truly_exposed_ports": truly_exposed,
        "firewall_allowed": fw_allowed,
        "firewall_denied": fw_denied,
        "firewall_default_policy": fw_default,
        "listening_exposed": listening_exposed,
        "listening_loopback": listening_loopback,
        "has_network_access": has_net,
        "reachable_subnets": subnets,
        "cpe_ports": cpe_ports,
    }
