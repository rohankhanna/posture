"""Live CPE discovery — measure installed software and map it to CPE entries.

This is the live counterpart to device-config-supplied CPE matchers: instead
of trusting a device's declared ``matchers`` list, it shells out to the host's
package manager (``dpkg-query`` on Debian/Ubuntu, ``rpm`` on Fedora/RHEL/SUSE)
and builds CPE 2.3 entries from the measured package inventory.  The resulting
matchers can be fed into :func:`posture.grounding.grounding_for_matchers` to
get port-to-CVE grounding based on what is *actually installed*, not what the
device *claims* is installed.

Why live?  The device-config matchers are honest about what the device reports,
but the report can be stale, hand-edited, or incomplete.  ``dpkg-query`` or
``rpm`` reads the package database's actual state — the measured ground truth
for "what software is on this machine right now".  When live data is available
it supplements (or replaces) the snapshot matchers; when it is not (no
``dpkg``/``rpm`` binary, non-Linux), the function is an honest no-op and the
snapshot matchers stand.

The pure functions ``parse_dpkg_query`` and ``parse_rpm_query`` are exported
for deterministic testing without subprocess calls.

Probe priority: ``dpkg-query`` first (Debian/Ubuntu — the most common Linux
desktop distribution), then ``rpm`` (Fedora/RHEL/SUSE).  Both produce the same
package-entry shape: ``{"name": str, "version": str}``.
"""

from __future__ import annotations

import subprocess

# ---------------------------------------------------------------------------
# Static dpkg/rpm package-name → CPE mapping
# ---------------------------------------------------------------------------
#
# Keys are package-manager package names (lower-case).  Values are
# ``(part, vendor, product)`` tuples that form the CPE 2.3 key
# ``<part>:<vendor>:<product>``.
#
# Only packages whose CPE vendor:product is *well-known* and *stable* are
# mapped.  A package not in the table is skipped — the caller degrades
# gracefully (no CPE matcher emitted, same as the firewall/interface grounding
# observers' empty-set semantics).
#
# The mapping is curated from the NVD CPE dictionary's canonical vendor:product
# entries and cross-referenced with the dpkg/rpm package names used by the
# upstream projects.

_DPKG_TO_CPE: dict[str, tuple[str, str, str]] = {
    # --- SSH ---
    "openssh-server": ("a", "openssh", "openssh"),
    "openssh-client": ("a", "openbsd", "openssh"),
    "openssh": ("a", "openssh", "openssh"),

    # --- Web servers ---
    "apache2": ("a", "apache", "http_server"),
    "httpd": ("a", "apache", "httpd"),
    "nginx": ("a", "nginx", "nginx"),
    "nginx-common": ("a", "nginx", "nginx"),
    "lighttpd": ("a", "lighttpd", "lighttpd"),
    "caddy": ("a", "caddy", "caddy"),
    "traefik": ("a", "traefik", "traefik"),

    # --- Database servers ---
    "postgresql": ("a", "postgresql", "postgresql"),
    "postgresql-16": ("a", "postgresql", "postgresql"),
    "postgresql-15": ("a", "postgresql", "postgresql"),
    "postgresql-14": ("a", "postgresql", "postgresql"),
    "mysql-server": ("a", "mysql", "mysql"),
    "mysql-client": ("a", "mysql", "mysql"),
    "mariadb-server": ("a", "mariadb", "mariadb"),
    "redis": ("a", "redis", "redis"),
    "redis-server": ("a", "redis", "redis"),
    "mongodb-server": ("a", "mongodb", "mongodb"),
    "mongodb-org": ("a", "mongodb", "mongodb"),
    "elasticsearch": ("a", "elastic", "elasticsearch"),
    "influxdb": ("a", "influxdb", "influxdb"),
    "couchdb": ("a", "couchdb", "couchdb"),

    # --- Mail servers ---
    "postfix": ("a", "postfix", "postfix"),
    "opensmtpd": ("a", "openbsd", "opensmtpd"),
    "dovecot-core": ("a", "dovecot", "dovecot"),
    "dovecot-imapd": ("a", "dovecot", "dovecot"),
    "dovecot": ("a", "dovecot", "dovecot"),
    "proftpd-basic": ("a", "proftpd", "proftpd"),
    "proftpd": ("a", "proftpd", "proftpd"),
    "vsftpd": ("a", "vsftpd", "vsftpd"),
    "pure-ftpd": ("a", "pureftpd", "pure-ftpd"),

    # --- DNS / DHCP ---
    "bind9": ("a", "isc", "bind9"),
    "bind9utils": ("a", "isc", "bind9"),
    "bind": ("a", "isc", "bind"),
    "unbound": ("a", "unbound", "unbound"),
    "pdns-server": ("a", "powerdns", "powerdns"),
    "isc-dhcp-server": ("a", "isc", "dhcpd"),
    "kea-dhcp4-server": ("a", "kea", "kea"),

    # --- File sharing ---
    "samba": ("a", "samba", "samba"),
    "smbd": ("a", "samba", "samba"),

    # --- Monitoring / DevOps ---
    "grafana": ("a", "grafana", "grafana"),
    "prometheus": ("a", "prometheus", "prometheus"),
    "zabbix-server-mysql": ("a", "zabbix", "zabbix"),
    "zabbix-agent": ("a", "zabbix", "zabbix"),
    "nagios4": ("a", "nagios", "nagios"),
    "nagios-nrpe-server": ("a", "nagios", "nagios"),
    "jenkins": ("a", "jenkins", "jenkins"),
    "gitlab-ce": ("a", "gitlab", "gitlab"),
    "gitlab-ee": ("a", "gitlab", "gitlab"),
    "consul": ("a", "hashicorp", "consul"),
    "vault": ("a", "hashicorp", "vault"),
    "nomad": ("a", "hashicorp", "nomad"),
    "rabbitmq-server": ("a", "rabbitmq", "rabbitmq"),

    # --- Other servers ---
    "squid": ("a", "squid", "squid"),
    "varnish": ("a", "varnish", "varnish"),
    "php-fpm": ("a", "php", "php"),
    "php8.3-fpm": ("a", "php", "php"),
    "tomcat10": ("a", "tomcat", "tomcat"),
    "tomcat9": ("a", "tomcat", "tomcat"),
    "jetty9": ("a", "eclipse", "jetty"),
    "wildfly": ("a", "wildfly", "wildfly"),
}

# RPM uses different package names in some cases.  This table maps rpm-specific
# names; entries not here fall through to the dpkg table (many names overlap).
_RPM_TO_CPE: dict[str, tuple[str, str, str]] = {
    "openssh-server": ("a", "openssh", "openssh"),
    "openssh-clients": ("a", "openbsd", "openssh"),
    "httpd": ("a", "apache", "httpd"),
    "nginx": ("a", "nginx", "nginx"),
    "postgresql-server": ("a", "postgresql", "postgresql"),
    "postgresql16-server": ("a", "postgresql", "postgresql"),
    "mariadb-server": ("a", "mariadb", "mariadb"),
    "redis": ("a", "redis", "redis"),
    "bind": ("a", "isc", "bind"),
    "bind-utils": ("a", "isc", "bind"),
    "dhcp-server": ("a", "isc", "dhcpd"),
    "samba": ("a", "samba", "samba"),
    "grafana": ("a", "grafana", "grafana"),
    "prometheus": ("a", "prometheus", "prometheus"),
    "zabbix-server-pgsql": ("a", "zabbix", "zabbix"),
    "zabbix-agent": ("a", "zabbix", "zabbix"),
    "nagios": ("a", "nagios", "nagios"),
    "jenkins": ("a", "jenkins", "jenkins"),
    "gitlab-ce": ("a", "gitlab", "gitlab"),
    "consul": ("a", "hashicorp", "consul"),
    "vault": ("a", "hashicorp", "vault"),
    "nomad": ("a", "hashicorp", "nomad"),
    "rabbitmq-server": ("a", "rabbitmq", "rabbitmq"),
    "squid": ("a", "squid", "squid"),
    "varnish": ("a", "varnish", "varnish"),
    "php-fpm": ("a", "php", "php"),
    "tomcat": ("a", "tomcat", "tomcat"),
    "jetty": ("a", "eclipse", "jetty"),
    "wildfly": ("a", "wildfly", "wildfly"),
}


# ---------------------------------------------------------------------------
# Pure parsers — exported for deterministic testing (no subprocess, no I/O)
# ---------------------------------------------------------------------------

def parse_dpkg_query(text: str) -> list[dict]:
    """Convert ``dpkg-query -W -f='${Package}\\t${Version}\\n'`` output to a
    list of ``{"name": str, "version": str}`` dicts.

    dpkg-query emits one package per line with a tab separating the package
    name from the version.  Empty lines and lines without a tab are skipped.

    >>> parse_dpkg_query("openssh-server\\t1:9.6p1-3ubuntu13.4\\nnginx\\t1.24.0")
    [{'name': 'openssh-server', 'version': '1:9.6p1-3ubuntu13.4'}, {'name': 'nginx', 'version': '1.24.0'}]

    Pure: no subprocess, no I/O.  Deterministic and testable.
    """
    if not text or not isinstance(text, str):
        return []
    packages: list[dict] = []
    for line in text.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            # Some dpkg-query formats use spaces instead of tabs.
            parts = line.split(maxsplit=1)
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        version = parts[1].strip()
        if name and version:
            packages.append({"name": name, "version": version})
    return packages


def parse_rpm_query(text: str) -> list[dict]:
    """Convert ``rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'`` output to
    a list of ``{"name": str, "version": str}`` dicts.

    rpm emits one package per line with a tab separator.  The version field
    includes the release suffix (e.g. ``1.24.0-1.el9``).

    >>> parse_rpm_query("openssh-server\\t9.6p1-1.el9\\nnginx\\t1.24.0-1.el9")
    [{'name': 'openssh-server', 'version': '9.6p1-1.el9'}, {'name': 'nginx', 'version': '1.24.0-1.el9'}]

    Pure: no subprocess, no I/O.  Deterministic and testable.
    """
    # The parsing logic is identical to dpkg — both use tab-separated
    # name/version lines.
    return parse_dpkg_query(text)


# ---------------------------------------------------------------------------
# Package → CPE conversion
# ---------------------------------------------------------------------------

def _normalize_version(version: str) -> str:
    """Strip dpkg/rpm epoch and release suffixes to get a clean upstream
    version suitable for CPE.

    dpkg versions: ``1:9.6p1-3ubuntu13.4`` -> ``9.6p1``
    rpm versions: ``1.24.0-1.el9`` -> ``1.24.0``

    The CPE 2.3 ``version`` field is the upstream version, not the distro
    packaging version.  We strip:
      - leading ``epoch:`` (dpkg)
      - trailing ``-<release>`` (both dpkg and rpm)
    """
    v = version
    # Strip dpkg epoch: "1:9.6p1" -> "9.6p1"
    if ":" in v:
        # Only strip if the prefix before ':' is all digits (epoch)
        colon = v.index(":")
        if v[:colon].isdigit():
            v = v[colon + 1:]
    # Strip release suffix: "9.6p1-3ubuntu13.4" -> "9.6p1"
    if "-" in v:
        v = v.split("-")[0]
    return v


def package_to_cpe(name: str, version: str, table: dict[str, tuple[str, str, str]] | None = None) -> str | None:
    """Construct a CPE 2.3 string from a package name and version.

    Returns the full CPE 2.3 URI (``cpe:2.3:<part>:<vendor>:<product>:<version>:``
    with trailing colons for the remaining fields) or ``None`` when the package
    name is not in the mapping table.

    >>> package_to_cpe("openssh-server", "1:9.6p1-3ubuntu13.4")
    'cpe:2.3:a:openssh:openssh:9.6p1:*:*:*:*:*:*'
    >>> package_to_cpe("unknown-package", "1.0") is None
    True

    The ``table`` parameter allows callers to pass a custom mapping (e.g.
    the rpm table instead of dpkg).  Defaults to the dpkg table.
    """
    if table is None:
        table = _DPKG_TO_CPE
    key = name.lower().strip()
    if key not in table:
        return None
    part, vendor, product = table[key]
    clean_version = _normalize_version(version)
    return f"cpe:2.3:{part}:{vendor}:{product}:{clean_version}:*:*:*:*:*:*"


def packages_to_cpe_matchers(
    packages: list[dict],
    table: dict[str, tuple[str, str, str]] | None = None,
) -> list[dict]:
    """Convert a list of package entries to CPE matcher dicts.

    Each matcher has ``{"type": "nvd_cpe", "cpe": <cpe_string>}`` — the same
    shape that :func:`posture.grounding.grounding_for_matchers` consumes.

    Packages not in the mapping table are silently skipped (the caller treats
    a smaller list as "fewer CPE matchers available", not an error).
    """
    matchers: list[dict] = []
    for pkg in packages:
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        cpe = package_to_cpe(name, version, table=table)
        if cpe is not None:
            matchers.append({"type": "nvd_cpe", "cpe": cpe})
    return matchers


# ---------------------------------------------------------------------------
# Live probing
# ---------------------------------------------------------------------------

def probe_dpkg() -> list[dict] | None:
    """Run ``dpkg-query`` and return the parsed package list, or ``None``
    when the command is unavailable or fails.

    ``None`` means "no live data, try fallback" — never raises.
    """
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return parse_dpkg_query(proc.stdout)


def probe_rpm() -> list[dict] | None:
    """Run ``rpm -qa`` and return the parsed package list, or ``None``
    when the command is unavailable or fails.

    ``None`` means "no live data, try fallback" — never raises.
    """
    try:
        proc = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return parse_rpm_query(proc.stdout)


def discover_live_cpe() -> list[dict]:
    """Discover CPE matchers from the host's live package database.

    Probes ``dpkg-query`` first (Debian/Ubuntu), then ``rpm`` (Fedora/RHEL).
    Returns a list of ``{"type": "nvd_cpe", "cpe": <cpe>}`` matcher dicts.
    When neither package manager is available, returns an empty list (the
    caller treats an empty list as "no live CPE data; use snapshot matchers").
    """
    # Try dpkg first
    packages = probe_dpkg()
    if packages is not None:
        return packages_to_cpe_matchers(packages, table=_DPKG_TO_CPE)

    # Fall back to rpm
    packages = probe_rpm()
    if packages is not None:
        return packages_to_cpe_matchers(packages, table=_RPM_TO_CPE)

    # Neither available — honest empty
    return []


def enrich_device_matchers(device: dict) -> list[dict]:
    """Merge live-discovered CPE matchers into the device's existing matchers.

    When the device already supplies CPE matchers (via ``device["matchers"]``),
    the live matchers are *merged in* — CPEs already present are not
    duplicated.  When the device supplies no matchers, the live matchers
    become the full set.  When no live data is available, the device's
    original matchers are returned unchanged.
    """
    existing = list(device.get("matchers") or [])
    live = discover_live_cpe()

    if not live:
        return existing

    existing_cpes = {
        m.get("cpe") for m in existing
        if isinstance(m, dict) and m.get("type") == "nvd_cpe"
    }
    for m in live:
        if m.get("cpe") not in existing_cpes:
            existing.append(m)
            existing_cpes.add(m.get("cpe", ""))

    return existing


def known_dpkg_packages() -> list[str]:
    """All dpkg package names in the mapping (for introspection / testing)."""
    return sorted(_DPKG_TO_CPE.keys())


def known_rpm_packages() -> list[str]:
    """All rpm package names in the mapping (for introspection / testing)."""
    return sorted(_RPM_TO_CPE.keys())
