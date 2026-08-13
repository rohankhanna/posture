"""The glossary — the vocabulary as data, not code.

The single design fact this module encodes: **the words are not hardcoded.**
CVE, CWE, KEV, EPSS, GHSA, USN, the six axes — every one of them is a row in a
table the system reads, not a string baked into the code. New terms grow the
system instead of breaking it.

Two layers of indirection make that possible:

  - **ROLES** are functional jobs (severity_coordinate, exploitability_signal,
    weakness_category, advisory_scheme, ...). The engine resolves ROLES, not
    literal term ids, so "what fills this job" can change without touching code.
    (The spine itself is NOT a role anymore: the alias↔alias graph has no
    single rebindable join key — cve is one peer among many. See spine.py.)
  - **KINDS** are what a term *is* (identifier_scheme, coordinate_system, axis,
    ...). A observer declares the kind of the keys it emits; a kind not in the
    glossary is an emergent signal — the vocab monitor surfaces it as a
    candidate (auto), the human decides to trust it (never auto).

The autonomy contract (user decision): **auto the MAP, human the TRUST.**
Discovering terms, writing candidates, measuring health, graceful-unknown,
no-wipe, fallback are AUTO. Promoting a candidate to known, deprecating a term
with a successor, rebinding a role are HUMAN — each versioned, dated, cited,
recorded in `term_changes`. A security tool that silently rewrote its own trust
would itself be an attack surface.

The **deterministic term-profile / neighborhood** (`neighborhood`,
`suggest_for_signal`) is the model-free Phase-1 classifier: it relates terms by
shared kind/role and substring matches on labels. It is deliberately NOT a
learned embedding — that is a clearly-separated, versioned, opt-in Phase 2
extension point: an embedding is another map (a
map-of-a-map, geometry inferred not measured), so if it is ever added it must
be grown in dated, reproducible batches and must never sit in the trust path.
"""

from __future__ import annotations
import datetime as _dt
import sqlite3
from dataclasses import dataclass, field

from .axis import Axis, AXES, AXIS_META


# ---------------------------------------------------------------------------
# ROLES — the indirection layer (the job, not the word)
# ---------------------------------------------------------------------------

ROLES: set[str] = {
    "severity_coordinate",      # cvss
    "exploitability_signal",    # kev, epss, ssvc
    "weakness_category",        # cwe, capec, attack, d3fend
    "advisory_scheme",          # ghsa, usn, dsa, rhsa, apsb, osv_id
    "advisory_format",         # csaf, stix, oval
    "inventory_format",         # cyclonedx, spdx
    "posture_axis",             # the six axes themselves are terms
}

# What a term IS (not the job it fills). A observer declares the kind of its keys;
# a kind outside the glossary's known set is an emergent new-term signal.
KINDS: set[str] = {
    "identifier_scheme",   # a naming scheme for a real thing (cve, ghsa, usn, ...)
    "coordinate_system",   # a scoring rubric (cvss)
    "axis",                # a posture dimension (the six, and any future ones)
    "weakness_category",   # cwe / capec / att&ck / d3fend
    "signal_source",       # exploitability intel (kev, epss, ssvc)
    "advisory_format",     # a wire format for advisories (csaf, stix, oval)
    "inventory_format",    # a SBOM format (cyclonedx, spdx)
    "other",
}


@dataclass
class Term:
    """One entry in the glossary.

    `roles` is the set of functional jobs this term can fill (see ROLES). The
    engine resolves roles (e.g. severity_coordinate -> cvss), so "what fills a
    job" can change without code. The spine itself is not a role — it is the
    alias↔alias graph (see spine.py); cve is one peer among many.

    `status`:
      - `known`      — trusted; the system reasons over it.
      - `candidate`  — surfaced (auto) but not yet trusted; awaiting human review.
      - `deprecated` — retired; `successor` points at the term that replaces it
                       (the CVE-replacement course-correction).
    """
    id: str
    label: str = ""
    kind: str = "other"
    roles: list[str] = field(default_factory=list)
    status: str = "candidate"   # a new term is NOT trusted until promoted
    successor: str | None = None
    citation: str = ""
    discovered_at: str = ""
    promoted_at: str | None = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "label": self.label, "kind": self.kind,
            "roles": list(self.roles), "status": self.status,
            "successor": self.successor, "citation": self.citation,
            "discovered_at": self.discovered_at, "promoted_at": self.promoted_at,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# The seed — the vocabulary we start with (cited; the map is foreign-authored)
# ---------------------------------------------------------------------------

# Identifier + scoring + signal schemes, each cited to its authority. These are
# AXIOM-1/2/3 in the axiom stack (naming + coordinate + CPE authorities) —
# recorded as cited terms, not as unquestioned facts.
_SEED_TERMS: list[dict] = [
    {"id": "cve", "label": "Common Vulnerabilities and Exposures",
     "kind": "identifier_scheme", "roles": [],
     "citation": "MITRE / NVD — https://nvd.nist.gov/ (cve is one peer of the alias graph)"},
    {"id": "ghsa", "label": "GitHub Security Advisory",
     "kind": "identifier_scheme", "roles": ["advisory_scheme"],
     "citation": "GitHub Advisory Database — https://github.com/advisories"},
    {"id": "usn", "label": "Ubuntu Security Notice",
     "kind": "identifier_scheme", "roles": ["advisory_scheme"],
     "citation": "Ubuntu security tracker — https://ubuntu.com/security/notices"},
    {"id": "dsa", "label": "Debian Security Advisory",
     "kind": "identifier_scheme", "roles": ["advisory_scheme"],
     "citation": "Debian security tracker — https://security-tracker.debian.org"},
    {"id": "rhsa", "label": "Red Hat Security Advisory",
     "kind": "identifier_scheme", "roles": ["advisory_scheme"],
     "citation": "Red Hat CVE database — https://access.redhat.com/security"},
    {"id": "apsb", "label": "Apple Security Advisory",
     "kind": "identifier_scheme", "roles": ["advisory_scheme"],
     "citation": "Apple security releases — https://support.apple.com/security"},
    {"id": "osv_id", "label": "OSV advisory id",
     "kind": "identifier_scheme", "roles": ["advisory_scheme"],
     "citation": "OSV — https://osv.dev/ (open-source vulnerability schema)"},
    {"id": "cwe", "label": "Common Weakness Enumeration",
     "kind": "weakness_category", "roles": ["weakness_category"],
     "citation": "MITRE CWE — https://cwe.mitre.org/"},
    {"id": "capec", "label": "Common Attack Pattern Enum",
     "kind": "weakness_category", "roles": ["weakness_category"],
     "citation": "MITRE CAPEC — https://capec.mitre.org/"},
    {"id": "attack", "label": "MITRE ATT&CK",
     "kind": "weakness_category", "roles": ["weakness_category"],
     "citation": "MITRE ATT&CK — https://attack.mitre.org/"},
    {"id": "d3fend", "label": "MITRE D3FEND",
     "kind": "weakness_category", "roles": ["weakness_category"],
     "citation": "MITRE D3FEND — https://d3fend.mitre.org/"},
    {"id": "cvss", "label": "Common Vulnerability Scoring System",
     "kind": "coordinate_system", "roles": ["severity_coordinate"],
     "citation": "FIRST.org CVSS — https://www.first.org/cvss/ (a rubric, not a measurement)"},
    {"id": "epss", "label": "Exploit Prediction Scoring System",
     "kind": "signal_source", "roles": ["exploitability_signal"],
     "citation": "FIRST.org EPSS — https://www.first.org/epss/ (a predictive model)"},
    {"id": "kev", "label": "CISA Known Exploited Vulnerabilities",
     "kind": "signal_source", "roles": ["exploitability_signal"],
     "citation": "CISA KEV — https://www.cisa.gov/kev (US-gov exploitability signal)"},
    {"id": "ssvc", "label": "Stakeholder-Specific Vulnerability Categorization",
     "kind": "signal_source", "roles": ["exploitability_signal"],
     "citation": "CERT/CC SSVC — https://www.certscc.github.io/ssvc/"},
    {"id": "csaf", "label": "Common Security Advisory Framework",
     "kind": "advisory_format", "roles": ["advisory_format"],
     "citation": "OASIS CSAF — https://oasis-open.github.io/csaf-documentation/"},
    {"id": "stix", "label": "Structured Threat Information eXpression",
     "kind": "advisory_format", "roles": ["advisory_format"],
     "citation": "OASIS STIX 2.x — https://oasis-open.github.io/cti-documentation/"},
    {"id": "oval", "label": "Open Vulnerability and Assessment Language",
     "kind": "advisory_format", "roles": ["advisory_format"],
     "citation": "OVAL — https://oval.mitre.org/"},
    {"id": "cyclonedx", "label": "CycloneDX SBOM",
     "kind": "inventory_format", "roles": ["inventory_format"],
     "citation": "CycloneDX — https://cyclonedx.org/"},
    {"id": "spdx", "label": "SPDX SBOM",
     "kind": "inventory_format", "roles": ["inventory_format"],
     "citation": "SPDX — https://spdx.dev/"},
]


def _axis_seed_terms() -> list[dict]:
    """The six axes as glossary terms. The Axis enum is the SEED for these; new
    axes are discovered -> candidate -> promoted (human) and appear in
    known_axes(). The set grows; the enum does not have to."""
    out = []
    for ax in AXES():
        meta = AXIS_META.get(ax, {})
        out.append({
            "id": ax.value,
            "label": meta.get("desc", ax.value),
            "kind": "axis",
            "roles": ["posture_axis"],
            "citation": "posture seed axis (the body of the posture map)",
            "notes": f"key_kind={meta.get('key_kind', '')}; "
                     f"statuses={meta.get('status_set', '')}",
        })
    return out


def SEED() -> list[dict]:
    """The full seed glossary (schemes + axes)."""
    return _SEED_TERMS + _axis_seed_terms()


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Seeding + reads
# ---------------------------------------------------------------------------

def ensure_seeded(conn: sqlite3.Connection, now: str | None = None) -> int:
    """Idempotently seed the glossary on first use. Returns the count of terms
    present after seeding. The six axes are seeded too. (The spine role binding
    `vulnerability_join_key -> cve` is no longer seeded: the spine is the
    alias↔alias graph now, not a rebindable word — see spine.py.)"""
    from . import store as _store
    ts = now or _now()
    for t in SEED():
        row = _store.get_term(conn, t["id"])
        if row is None:
            t = dict(t, discovered_at=ts)
            _store.upsert_term(conn, t)
    return len(_store.all_terms(conn))


def get(conn: sqlite3.Connection, term_id: str) -> Term | None:
    from . import store as _store
    d = _store.get_term(conn, term_id)
    return Term(**d) if d else None


def all(conn: sqlite3.Connection, status: str | None = None) -> list[Term]:
    from . import store as _store
    return [Term(**d) for d in _store.all_terms(conn, status=status)]


def known_kinds(conn: sqlite3.Connection) -> set[str]:
    """The identifier/format kinds the system currently understands. A observer
    key of a kind outside this set is an emergent new-term signal. Axes (kind
    'axis') are excluded — they are dimensions, not identifiers."""
    return {t.kind for t in all(conn, status="known") if t.kind != "axis"}


def known_axes(conn: sqlite3.Connection) -> list:
    """The known posture axes (dimensions of the event space), in canonical
    order. Seed axes return as `Axis` enum values (so the registry, which keys
    on Axis, matches them); a future promoted non-seed axis returns as a plain
    string. n is variable by construction — the six are the seed, not the law."""
    from . import store as _store
    out: list = []
    for d in _store.all_terms(conn, status="known"):
        if d["kind"] != "axis":
            continue
        try:
            out.append(Axis(d["id"]))
        except ValueError:
            out.append(d["id"])  # a promoted, non-seed axis
    return out


def resolve_role(conn: sqlite3.Connection, role: str) -> Term | None:
    """The term currently filling `role`. Resolution order:

      1. the explicit spine binding for the role (the human-gated rebind), if
         it points at a known term;
      2. otherwise the first known term carrying `role` in seed order;
      3. a deprecated term resolves to its known successor (course-correction).

    Returns None if nothing fills the role (the engine then degrades loudly).
    """
    from . import store as _store
    binding = _store.get_spine_binding(conn, role)
    if binding:
        t = get(conn, binding["term_id"])
        if t and t.status == "known":
            return t
        if t and t.status == "deprecated" and t.successor:
            succ = get(conn, t.successor)
            if succ and succ.status == "known":
                return succ
    # fall back to the first known term with the role
    for t in all(conn, status="known"):
        if role in t.roles:
            return t
    return None


# ---------------------------------------------------------------------------
# Trust changes — HUMAN-gated, versioned, dated, cited
# ---------------------------------------------------------------------------

def add_term(conn: sqlite3.Connection, term: Term, actor: str = "human",
             version: str = "", now: str | None = None) -> Term:
    """Add a term (candidate or known). Adding is not trusting — a candidate is
    surfaced, not authoritative. Recording the change is mandatory."""
    from . import store as _store
    ts = now or _now()
    if not term.discovered_at:
        term.discovered_at = ts
    _store.upsert_term(conn, term.to_dict())
    _store.record_term_change(conn, "add", term.id,
                              f"kind={term.kind} status={term.status}",
                              actor, version, ts)
    return term


def promote_term(conn: sqlite3.Connection, term_id: str, actor: str = "human",
                 version: str = "", now: str | None = None) -> Term:
    """THE trust gate: candidate -> known. Promoting is the one act that makes
    a term authoritative, so it is human, versioned, dated. Returns the term."""
    from . import store as _store
    ts = now or _now()
    t = get(conn, term_id)
    if t is None:
        raise KeyError(f"unknown term: {term_id}")
    if t.status == "deprecated":
        raise ValueError(f"{term_id} is deprecated; promote its successor "
                         f"{t.successor!r} instead")
    _store.set_term_status(conn, term_id, "known", promoted_at=ts)
    _store.record_term_change(conn, "promote", term_id, "candidate -> known",
                              actor, version, ts)
    return get(conn, term_id)  # type: ignore[return-value]


def deprecate_term(conn: sqlite3.Connection, term_id: str, successor: str,
                   actor: str = "human", version: str = "",
                   now: str | None = None) -> Term:
    """Retire a term and point at its replacement — the CVE-replacement
    course-correction. The crosswalk (old id <-> new id) is maintained
    separately so historical joins still resolve."""
    from . import store as _store
    ts = now or _now()
    t = get(conn, term_id)
    if t is None:
        raise KeyError(f"unknown term: {term_id}")
    if get(conn, successor) is None:
        raise KeyError(f"successor term not found: {successor}")
    _store.set_term_status(conn, term_id, "deprecated", successor=successor)
    _store.record_term_change(conn, "deprecate", term_id,
                              f"successor={successor}", actor, version, ts)
    return get(conn, term_id)  # type: ignore[return-value]


def rebind_role(conn: sqlite3.Connection, role: str, term_id: str,
                actor: str = "human", version: str = "",
                now: str | None = None) -> None:
    """Point a spine role at a different term (human-gated). The course-
    correction when the old term dies: the role stays, the word filling it
    swaps, old joins resolve via crosswalk. Recorded."""
    from . import store as _store
    ts = now or _now()
    t = get(conn, term_id)
    if t is None:
        raise KeyError(f"unknown term: {term_id}")
    if t.status != "known":
        raise ValueError(f"{term_id} is {t.status}; promote it before rebinding")
    _store.set_spine_binding(conn, role, term_id, ts)
    _store.record_term_change(conn, "rebind", term_id,
                              f"role={role}", actor, version, ts)


# ---------------------------------------------------------------------------
# Deterministic term-profile / neighborhood (model-free Phase-1 classifier)
# ---------------------------------------------------------------------------

def neighborhood(conn: sqlite3.Connection, term_id: str) -> list[Term]:
    """The deterministic 'nearby' terms: those sharing a role or kind with
    `term_id` (excluding itself). This is the model-free stand-in for a learned
    embedding — it relates terms by structure, not by inferred geometry, so it
    stays in the measured/deterministic stratum. A real embedding (Phase 2,
    opt-in) would replace or augment this with a dated, reproducible vector
    space that is NEVER in the trust path."""
    t = get(conn, term_id)
    if t is None:
        return []
    out: list[Term] = []
    seen = {term_id}
    for other in all(conn, status="known"):
        if other.id in seen:
            continue
        if (set(t.roles) & set(other.roles)) or t.kind == other.kind:
            out.append(other)
            seen.add(other.id)
    return out


def suggest_for_signal(conn: sqlite3.Connection, label: str,
                      context: str = "") -> list[Term]:
    """A deterministic first guess for a new-term signal: known terms whose
    label/id the signal's label or context substring-matches. Returns ranked
    candidates (most-overlapping first). This only SUGGESTS — promotion is
    human. The LLM classifier (off by default) can draft a richer guess; it too
    never judges trust."""
    label_l = (label or "").lower()
    ctx_l = (context or "").lower()
    hay = label_l + " " + ctx_l
    scored: list[tuple[int, Term]] = []
    for t in all(conn, status="known"):
        score = 0
        for tok in (t.id, t.label):
            tok_l = tok.lower()
            if tok_l and tok_l in hay:
                score += len(tok_l)
        if score:
            scored.append((score, t))
    scored.sort(key=lambda x: -x[0])
    return [t for _, t in scored]