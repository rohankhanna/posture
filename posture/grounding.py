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
