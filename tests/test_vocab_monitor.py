"""Vocab-monitor tests — new terms grow the system; nothing breaks."""
from posture import store, glossary as G, vocab_monitor as V


def _conn():
    conn = store.connect(":memory:")
    G.ensure_seeded(conn)
    return conn


def test_emergent_unknown_kind_auto_writes_candidate():
    conn = _conn()
    # a observer emits keys of a kind the glossary does not know ("X")
    sigs = V.scan_emergent(conn, "future_observer", "X",
                           ["X-2026-1", "X-2026-2"])
    assert len(sigs) == 1
    assert sigs[0].kind == "X"
    t = G.get(conn, "X")
    assert t is not None and t.status == "candidate"  # NOT trusted
    assert "X" not in G.known_kinds(conn)  # candidate is not known


def test_emergent_known_kind_raises_nothing():
    conn = _conn()
    sigs = V.scan_emergent(conn, "nvd", "cve", ["CVE-2026-1"])
    assert sigs == []
    # no candidate term 'cve' duplicate created
    assert G.get(conn, "cve").status == "known"


def test_structured_scan_surfaces_standard_formats_as_candidates(monkeypatch):
    conn = _conn()
    # a NOVEL standard format the seed doesn't know surfaces as a candidate.
    from posture import discovery as _discovery
    novel = dict(_discovery.STANDARD_FORMATS)
    novel["sbomdx"] = "SBOM-DX (a hypothetical future SBOM standard)"
    monkeypatch.setattr(_discovery, "STANDARD_FORMATS", novel)
    sigs = V.scan_structured(conn)
    assert any(s.label.startswith("SBOM-DX") for s in sigs)
    # the surfaced term is a CANDIDATE — the machine notices, never auto-trusts
    assert G.get(conn, "sbomdx").status == "candidate"
    # running it again does not crash and sbomdx stays candidate (not promoted)
    V.scan_structured(conn)
    assert G.get(conn, "sbomdx").status == "candidate"


def test_queue_lists_candidates_only():
    conn = _conn()
    V.scan_emergent(conn, "w", "Y", ["Y-1"])
    q = V.queue(conn)
    assert any(c["id"] == "Y" for c in q)
    # known terms are not in the queue
    assert "cve" not in {c["id"] for c in q}


def test_promote_clears_from_queue():
    conn = _conn()
    V.scan_emergent(conn, "w", "Z", ["Z-1"])
    assert any(c["id"] == "Z" for c in V.queue(conn))
    G.promote_term(conn, "Z")
    assert "Z" not in {c["id"] for c in V.queue(conn)}
    assert "Z" in {t.id for t in G.all(conn, status="known")}


def test_real_observers_expose_declared_key_kind():
    """Regression: `Observer` is a dataclass, so its auto-generated `__init__`
    defaults `key_kind=None` and SHADOWS a subclass's class-level `key_kind`
    unless the subclass passes `key_kind=self.key_kind` through. Before the
    fix, nvd/ubuntu/debian/apple/cis all silently had `key_kind=None`, so the
    vocab monitor never fired for them (cyclonedx_sbom already passed it).
    The instance attribute must equal the declared class attribute.
    """
    from posture.sources.nvd_cve import NvdCveObserver
    from posture.sources.ubuntu_tracker import UbuntuTrackerObserver
    from posture.sources.debian_tracker import DebianTrackerObserver
    from posture.sources.apple_advisory import AppleAdvisoryObserver
    from posture.sources.cis_checker import CisCheckerObserver
    from posture.sources.cyclonedx_sbom import CyclonedxSbomObserver

    cases = [
        (NvdCveObserver(), "cve"),
        (UbuntuTrackerObserver(), "cve"),
        (DebianTrackerObserver(), "cve"),
        (AppleAdvisoryObserver(), "cve"),
        (CisCheckerObserver(), "cis_check"),
        (CyclonedxSbomObserver(), "package"),
    ]
    for w, expected in cases:
        assert type(w).key_kind == expected  # class attr is intact
        assert w.key_kind == expected  # instance attr is NOT shadowed to None


def test_engine_emergent_scan_runs_on_unknown_kind_observer():
    """A observer with an unknown key_kind does NOT crash the engine and the
    kind lands as a candidate term."""
    from posture.axis import Axis
    from posture.observer import Observer, ObserverResult, Verdict, Provenance
    from posture import engine

    class W(Observer):
        def __init__(self):
            super().__init__(id="future", axes=(Axis.VULNERABILITY,),
                             bias="neutral", key_kind="newx")
        def assess(self, device, policy):
            return ObserverResult(verdicts=[Verdict(
                axis="vulnerability", key="NEWX-1", status="unpatched",
                provenance=Provenance(observer="future", policy_version="",
                                      fetched_at="", complete=True))],
                complete=True)

    class FakePolicy:
        version = "2026-08-01.1"
        def has_observer(self, wid): return wid == "future"
        def observer_order(self, wid): return 10
        def observer_bias(self, wid, default="neutral"): return default
        def observer_weight(self, wid): return "medium"
        def degradation_for(self, wid): return None

    conn = store.connect(":memory:")
    reg = engine.__dict__["ObserverRegistry"]()  # noqa
    from posture.observer import ObserverRegistry
    reg = ObserverRegistry()
    reg.register(W())
    dp = engine.assess({"id": "dev", "os": "linux"}, reg, FakePolicy(), conn=conn)
    vuln = next(a for a in dp.axes if a.axis == "vulnerability")
    assert vuln.status == "unpatched"  # the verdict still emitted + committed
    # and the unknown kind became a candidate
    assert G.get(conn, "newx").status == "candidate"