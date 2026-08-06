"""Shared git-backfill primitives for ingestion peers.

Both the cvelistV5 CVE back-fill and the GHSA git-clone ingestion read historical
records out of a blobless git clone. The mechanics are identical: enumerate the
record paths under a tree prefix, slice `cap` past a path cursor, and fetch the
slice's blobs in ONE round trip via ``git archive`` streamed through ``tarfile``
(no per-blob ``git show``, no working-tree extraction). This module is the one
shared implementation; each peer supplies its own ``parse_fn`` and path prefix.

``git_backfill_slice`` is only-adds and fetch-only — it never writes to a DB or
touches verdicts. The caller (``backfill_tick`` / ``ghsa_ingest_tick``) owns the
upsert + cursor advance, so a tick killed mid-sweep retries the same slice
idempotently next time.
"""
from __future__ import annotations

import subprocess
import tarfile
from pathlib import Path


def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({r.returncode}): {r.stderr.strip()}")
    return r.stdout


def ls_tree_paths(repo: Path, tip: str, path_prefix: str,
                  suffix: str = ".json") -> list[str]:
    """Sorted repo-relative paths under ``path_prefix`` at commit ``tip`` whose
    name ends in ``suffix`` (default ``.json``). Enumerates trees present on the
    blobless clone via ``git ls-tree -r --name-only`` (no blob fetch here — only
    the slice below is fetched)."""
    raw = _git(repo, "ls-tree", "-r", "--name-only", tip, "--", path_prefix)
    return sorted(p.strip() for p in raw.splitlines()
                  if p.strip() and p.endswith(suffix))


def git_backfill_slice(
    repo: Path,
    tip: str,
    path_prefix: str,
    cursor: str | None,
    cap: int,
    parse_fn,
    suffix: str = ".json",
):
    """Fetch + parse the next ``cap`` records under ``path_prefix`` after the
    path ``cursor`` (None = start from the top).

    Returns ``(records, new_cursor, done)`` where:

      - ``records``  — list of ``parse_fn(blob_text)`` results (parse_fn returns
        None to skip a malformed record; those are dropped, not counted);
      - ``new_cursor`` — the last path processed (the next slice starts after
        it); None if nothing was processed;
      - ``done``      — True when no more paths remain beyond this slice (the
        back-fill is exhausted).

    The slice's blobs are fetched in ONE ``git archive <tip> -- <paths>`` round
    trip (a single promisor negotiation for the whole slice, not per-blob
    ``git show``) and streamed through ``tarfile`` so no working tree is
    materialized. Idempotent: re-running with the same cursor re-processes the
    same slice (the caller's upsert is idempotent, so no double-count).
    """
    paths = ls_tree_paths(repo, tip, path_prefix, suffix=suffix)
    if cursor:
        paths = [p for p in paths if p > cursor]
    if not cap or cap <= 0:
        # cap<=0 means "no limit" — take the whole remaining range in one slice
        slice_ = paths
    else:
        slice_ = paths[:cap]

    if not slice_:
        # nothing to do: either exhausted, or the prefix is empty
        return [], cursor, True

    remaining = paths[len(slice_):]
    done = len(remaining) == 0

    # one round trip: `git archive <tip> -- <paths...>` streams a tar of exactly
    # the requested blobs (missing blobs are fetched from the promisor on demand).
    proc = subprocess.Popen(
        ["git", "-C", str(repo), "archive", tip, "--", *slice_],
        stdout=subprocess.PIPE,
    )
    records: list = []
    try:
        tar = tarfile.open(fileobj=proc.stdout, mode="r|")
        for member in tar:
            if not member.isfile():
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            text = f.read().decode("utf-8", "replace")
            try:
                rec = parse_fn(text)
            except Exception:
                rec = None
            if rec is not None:
                records.append(rec)
        tar.close()
    finally:
        proc.stdout.close()
        proc.wait()

    new_cursor = slice_[-1]
    return records, new_cursor, done