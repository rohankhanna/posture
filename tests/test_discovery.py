"""Tests for the discovery horizon-scan — the delta + idempotent upsert + the
POSTURE_LLM-gated live seam.

These pin five things:
  1. ``horizon_scan(conn)`` is an offline DELTA — it surfaces only aggregators
     whose url is not already in the candidates table; a human's
     adopted/rejected decision stops an aggregator resurfacing; conn=None
     returns the raw registry.
  2. ``store.add_candidate`` is idempotent on url (v3 unique index): re-adding
     the same url does NOT duplicate and does NOT wipe a human's status — it
     refreshes fmt/axis/note only. This is the fix for CI running `posture
     discover` daily without spamming the exported spine.
  3. the v3 migration dedups a pre-v3 candidates table that accumulated
     duplicate urls and raises a unique index, then bumps user_version to 3.
  4. the LLM horizon seam is OFF by default (``is_enabled()`` False without
     POSTURE_LLM; ``parse_horizon`` returns None) — sovereignty-safe: no
     provider is chosen, the system is complete model-free.
  5. the opt-in live ``--fetch`` path surfaces the aggregator itself when no
     LLM is wired, and surfaces LLM-drafted candidates when one is (mocked — no
     real network, no real LLM).

SELF-CONTAINED: tmp-path sqlite DBs, monkeypatched fetch (never real network),
monkeypatched env/parse for the seam. Mirrors the repo's hermetic-test norm.
"""
from __future__ import annotations
import sqlite3
from types import SimpleNamespace

import pytest

from posture import store, discovery
from posture.discovery import Candidate, horizon_scan, horizon_scan_live
from posture import llm_horizon


# ---------------------------------------------------------------------------
# offline delta: horizon_scan(conn) vs conn=None
# ---------------------------------------------------------------------------

def test_horizon_scan_no_conn_returns_full_registry():
    cands = horizon_scan(None)
    assert len(cands) == len(discovery.AGGREGATORS)
    assert all(isinstance(c, Candidate) for c in cands)


def test_horizon_scan_on_empty_db_surfaces_every_aggregator():
    conn = store.connect(":memory:")
    cands = horizon_scan(conn)
    assert {c.url for c in cands} == {a["url"] for a in discovery.AGGREGATORS}
    assert len(cands) == len(discovery.AGGREGATORS)


def test_horizon_scan_after_register_yields_empty_delta():
    conn = store.connect(":memory:")
    for c in horizon_scan(conn):
        discovery.register_candidate(conn, c)
    conn.commit()
    assert horizon_scan(conn) == []          # everything already recorded


def test_rejected_candidate_does_not_resurface():
    conn = store.connect(":memory:")
    cands = horizon_scan(conn)
    discovery.register_candidate(conn, cands[0])
    conn.commit()
    discovery.set_candidate_status(conn, cands[0].url, "rejected")
    conn.commit()
    remaining = {c.url for c in horizon_scan(conn)}
    assert cands[0].url not in remaining     # rejected -> not a new candidate


def test_adopted_candidate_does_not_resurface():
    conn = store.connect(":memory:")
    cands = horizon_scan(conn)
    discovery.register_candidate(conn, cands[0])
    conn.commit()
    discovery.set_candidate_status(conn, cands[0].url, "adopted")
    conn.commit()
    remaining = {c.url for c in horizon_scan(conn)}
    assert cands[0].url not in remaining


# ---------------------------------------------------------------------------
# idempotent upsert (v3): no dup, status preserved, fmt/axis/note refreshed
# ---------------------------------------------------------------------------

def test_add_candidate_is_idempotent_on_url():
    conn = store.connect(":memory:")
    store.add_candidate(conn, "https://x", "json", "threat", "first")
    store.add_candidate(conn, "https://x", "json", "threat", "second")
    conn.commit()
    rows = store.candidates(conn)
    assert len(rows) == 1                     # no duplicate
    assert rows[0]["note"] == "second"        # note refreshed


def test_add_candidate_preserves_human_status_across_re_scan():
    """A re-scan refreshes metadata but never wipes an adopted/rejected
    decision — CI can run discover daily without resetting prior reviews."""
    conn = store.connect(":memory:")
    store.add_candidate(conn, "https://x", "json", "threat", "first")
    conn.commit()
    discovery.set_candidate_status(conn, "https://x", "adopted")
    conn.commit()
    # a later re-scan re-registers the same url
    store.add_candidate(conn, "https://x", "csv", "vulnerability", "refreshed")
    conn.commit()
    rows = store.candidates(conn)
    assert len(rows) == 1
    assert rows[0]["status"] == "adopted"     # human decision preserved
    assert rows[0]["fmt"] == "csv"             # metadata refreshed
    assert rows[0]["axis"] == "vulnerability"
    assert rows[0]["note"] == "refreshed"


# ---------------------------------------------------------------------------
# v3 migration: dedup a pre-v3 candidates table + raise the unique index
# ---------------------------------------------------------------------------

def test_v3_migration_dedups_duplicate_candidate_urls_and_raises_unique_index(tmp_path):
    db = tmp_path / "pre_v3.db"
    raw = sqlite3.connect(str(db))
    raw.execute(
        "CREATE TABLE candidates (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, "
        "fmt TEXT, axis TEXT, status TEXT DEFAULT 'review', note TEXT, added_at TEXT)"
    )
    # a pre-v3 db that accumulated 3 dup rows for one url (the bug)
    for note in ("a", "b", "c"):
        raw.execute("INSERT INTO candidates (url, fmt, axis, note) VALUES (?,?,?,?)",
                    ("https://x", "json", "threat", note))
    raw.execute("INSERT INTO candidates (url, fmt, axis, note) VALUES (?,?,?,?)",
                ("https://y", "csv", "vulnerability", "keep"))
    raw.execute("PRAGMA user_version = 2")
    raw.commit(); raw.close()

    conn = store.connect(str(db))             # runs _migrate -> v3
    rows = store.candidates(conn)
    assert len(rows) == 2                     # one row per url (dup collapsed)
    assert {r["url"] for r in rows} == {"https://x", "https://y"}
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    idx = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='candidates_url_uq'"
    ).fetchone()
    assert idx is not None                    # unique index enforced -> upsert legal


# ---------------------------------------------------------------------------
# LLM seam: off by default, sovereignty-safe
# ---------------------------------------------------------------------------

def test_llm_horizon_disabled_by_default(monkeypatch):
    monkeypatch.delenv("POSTURE_LLM", raising=False)
    assert llm_horizon.is_enabled() is False
    assert llm_horizon.parse_horizon("any html", Candidate("n", "u", "json", "threat", "")) is None


def test_llm_horizon_enabled_when_posture_llm_set_but_still_stub(monkeypatch):
    monkeypatch.setenv("POSTURE_LLM", "test")
    assert llm_horizon.is_enabled() is True
    # the seam is wired-on but the default impl is still a no-op stub (no
    # provider chosen) -> returns None until an operator plugs a real parser
    assert llm_horizon.parse_horizon("any html", Candidate("n", "u", "json", "threat", "")) is None


# ---------------------------------------------------------------------------
# live --fetch path: aggregator surfaced when no LLM; LLM drafts when wired
# ---------------------------------------------------------------------------

def test_horizon_scan_live_without_llm_surfaces_aggregator_itself(monkeypatch):
    """No POSTURE_LLM -> each new aggregator is fetched and surfaced as a
    single review candidate (no LLM parsing). fetch is monkeypatched -> no
    network."""
    monkeypatch.delenv("POSTURE_LLM", raising=False)
    monkeypatch.setattr(discovery, "fetch_aggregator", lambda url: "<html>fake</html>")
    conn = store.connect(":memory:")
    cands = horizon_scan_live(conn)
    assert {c.url for c in cands} == {a["url"] for a in discovery.AGGREGATORS}
    assert all(c.status == "review" for c in cands)


def test_horizon_scan_live_with_wired_llm_surfaces_drafts(monkeypatch):
    """When an LLM is wired, its drafted candidates surface instead of the raw
    aggregator (still status='review' — the LLM drafts, a human decides)."""
    monkeypatch.setenv("POSTURE_LLM", "test")
    monkeypatch.setattr(discovery, "fetch_aggregator", lambda url: "<html>fake</html>")

    drafted = [Candidate("NEW-FEED", "https://new", "osv", "vulnerability",
                        "LLM drafted this from the page")]

    def fake_parse(body, agg):
        return drafted if agg.url == discovery.AGGREGATORS[0]["url"] else None

    monkeypatch.setattr(llm_horizon, "parse_horizon", fake_parse)
    conn = store.connect(":memory:")
    cands = horizon_scan_live(conn)
    by_url = {c.url for c in cands}
    assert "https://new" in by_url                       # the LLM draft surfaced
    # the first aggregator is NOT surfaced as itself (the LLM replaced it),
    # but the rest still surface as themselves (parse returned None for them)
    first_url = discovery.AGGREGATORS[0]["url"]
    assert first_url not in by_url
    assert all(c.status == "review" for c in cands)


def test_horizon_scan_live_starts_from_the_offline_delta(monkeypatch):
    """A live scan does not re-fetch already-recorded aggregators — it starts
    from the offline delta, so fetch_aggregator is called only for new urls."""
    monkeypatch.delenv("POSTURE_LLM", raising=False)
    fetched: list[str] = []
    monkeypatch.setattr(discovery, "fetch_aggregator",
                        lambda url: fetched.append(url) or "<html/>")
    conn = store.connect(":memory:")
    # record the first 3 aggregators as already-known
    for a in discovery.AGGREGATORS[:3]:
        store.add_candidate(conn, a["url"], a["fmt"], a["axis"], a["note"])
    conn.commit()
    cands = horizon_scan_live(conn)
    fetched_urls = set(fetched)
    assert len(fetched) == len(discovery.AGGREGATORS) - 3   # only the delta
    for a in discovery.AGGREGATORS[:3]:
        assert a["url"] not in fetched_urls


# ---------------------------------------------------------------------------
# CLI: posture discover surfaces the delta (idempotent across runs)
# ---------------------------------------------------------------------------

def test_cli_discover_offline_surfaces_delta_then_empty_on_rerun(capsys, tmp_path):
    from posture import cli
    db = str(tmp_path / "d.db")
    args = SimpleNamespace(db=db, fetch=False)
    assert cli._cmd_discover(args) == 0
    out1 = capsys.readouterr().out
    assert f"{len(discovery.AGGREGATORS)} candidate source(s) surfaced" in out1
    # second run: the delta is empty (all already recorded, idempotent)
    assert cli._cmd_discover(args) == 0
    out2 = capsys.readouterr().out
    assert "0 candidate source(s) surfaced" in out2
    assert "no new aggregators" in out2
    # the table did not bloat: exactly one row per aggregator
    conn = store.connect(db)
    assert len(store.candidates(conn)) == len(discovery.AGGREGATORS)


def test_cli_discover_fetch_flag_is_off_by_default():
    """The discover subparser defaults to the offline delta (the CI mode); the
    live --fetch path is opt-in and never the default."""
    from posture.cli import build_parser  # noqa: F401  (assert import works)
    import posture.cli as _cli
    # the subparser is built inside build_parser; reach the default via a parsed argv
    p = _cli.build_parser()
    ns = p.parse_args(["discover"])
    assert ns.fetch is False
    assert ns.func is _cli._cmd_discover