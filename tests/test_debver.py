"""dpkg version-comparison tests for posture.debver.

These assert the dpkg `--compare-versions` ordering for the cases that
motivated the port: real Ubuntu fixed versions like ``6.17.9-6.17.0+signed``
and tilde pre-releases like ``1.0~rc1`` that ``packaging.version`` cannot
compare correctly. A few canonical dpkg ordering cases are pinned too.
"""
from posture import debver


# --- canonical dpkg ordering (validated against dpkg) -----------------------

def test_tilde_sorts_before_everything_including_end_of_string():
    # 1.0~rc1 < 1.0  (tilde sorts before end-of-string)
    assert debver.lt("1.0~rc1", "1.0")
    assert debver.compare("1.0~rc1", "1.0") == -1
    # and 1.0~rc1 < 1.0~rc2
    assert debver.lt("1.0~rc1", "1.0~rc2")
    # ge is the inverse
    assert debver.ge("1.0", "1.0~rc1")


def test_epoch_dominates():
    assert debver.lt("1.0", "1:1.0")
    assert debver.lt("0:1.0", "1:1.0")
    assert debver.compare("1:1.0", "1:1.0") == 0


def test_revision_after_upstream():
    assert debver.lt("1.0-1", "1.0-2")
    # a revision makes a version GREATER than the bare upstream (empty revision)
    assert debver.ge("1.0-1", "1.0")
    assert not debver.lt("1.0-1", "1.0")
    assert debver.ge("1.0-2", "1.0-1")


def test_numeric_digit_runs_compare_numerically_not_lexically():
    # 2 vs 10: lexicographically "10" < "2", but numerically 10 > 2
    assert debver.lt("2.0", "10.0")
    assert debver.ge("10.0", "2.0")
    # leading zeros don't change numeric value
    assert debver.compare("1.02", "1.2") == 0


def test_letters_and_punctuation_order():
    # letters before non-letters (punctuation): 1.0a < 1.0.a
    assert debver.lt("1.0a", "1.0.a")
    # a '+' suffix makes a version greater than the bare base (no tilde)
    assert debver.ge("1.0+signed", "1.0")
    assert debver.lt("1.0", "1.0+signed")


def test_equal_versions_compare_zero():
    assert debver.compare("1.2.3-4", "1.2.3-4") == 0
    assert debver.ge("1.2.3-4", "1.2.3-4")
    assert not debver.lt("1.2.3-4", "1.2.3-4")


# --- the motivating real-world dpkg versions --------------------------------

def test_real_dpkg_kernel_version_compares_against_simple_fix():
    # the fixture version: packaging.version rejects this whole
    # string; dpkg compares it cleanly.
    installed = "6.17.9-6.17.0+signed"
    assert debver.ge(installed, "6.17.9")          # installed has the fix
    assert not debver.lt(installed, "6.17.9")
    # an older kernel is still unpatched against the same fix
    assert debver.lt("6.17.8", "6.17.9")


def test_ubuntu_tracker_kge_uses_dpkg_semantics_not_lex():
    """Regression: ubuntu_tracker._kge must use dpkg semantics, not the old
    packaging+lex fallback. The tilde case is the false-safe violation the
    fallback caused: ``1.0~rc1`` lex-compares ``>= 1.0`` (wrong) but dpkg
    orders ``1.0~rc1 < 1.0`` (a tilde pre-release is NOT patched)."""
    from posture.sources.ubuntu_tracker import _kge

    # simple versions still work (packaging agreed on these)
    assert _kge("6.18", "6.17.9") is True
    assert _kge("6.17", "6.17.9") is False

    # the dpkg versions packaging cannot compare:
    assert _kge("6.17.9-6.17.0+signed", "6.17.9") is True
    # tilde pre-release is NOT >= the release (the old lex fallback said True)
    assert _kge("1.0~rc1", "1.0") is False