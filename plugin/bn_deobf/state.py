"""Per-BV state: per-function activity toggle (via WorkflowMachine.override_set)
and FDE range cache.

Toggle storage: BN's own `WorkflowMachine.override_set(activity, enable)` —
session-only (lost on BN restart), but no custom callback / eligibility logic
needed; BN handles dispatch.

FDE ranges are decoded on first use (by `eh_frame.parse_eh_frame`) and cached
keyed by `id(bv)` for cheap lookup. If a function isn't covered by any FDE
(no .eh_frame, unsupported encoding, or out-of-range address), we fall back
to BN's own function bounds — never crash the analysis pipeline.
"""

from __future__ import annotations

from binaryninja.workflow import WorkflowMachine

from . import eh_frame

ACTIVITY_NAME = "analysis.plugins.bn_deobf"

_fde_cache: dict[int, list[tuple[int, int]]] = {}


def _machine(fn) -> WorkflowMachine:
    return WorkflowMachine(fn.handle)


def is_enabled(fn) -> bool:
    """Return True if the activity is currently eligible to run on this function.

    `override_query(ACT)` returns a status dict whose `response.activity.eligible`
    is the resolved state (after default + override). When the user has set an
    explicit override, `response.activity.override` is also present and reflects
    the override value alone.
    """
    try:
        q = _machine(fn).override_query(ACTIVITY_NAME)
    except Exception:
        return False
    if not isinstance(q, dict):
        return False
    info = q.get("response", {}).get("activity", {})
    return bool(info.get("eligible", False))


def toggle_and_reanalyze(bv, fn) -> None:
    """Right-click handler: flip the per-function activity override and reanalyze."""
    machine = _machine(fn)
    currently_on = is_enabled(fn)
    if currently_on:
        machine.override_set(ACTIVITY_NAME, False)
        verb = "DISABLED"
    else:
        machine.override_set(ACTIVITY_NAME, True)
        verb = "ENABLED"
    print(f"[bn_deobf] {verb} {fn.name} @ {hex(fn.start)}")
    fn.reanalyze()


def fde_for(bv, addr: int) -> tuple[int, int]:
    """Return the (start, end) FDE range that contains addr.

    Falls back to (fn.start, fn.start + fn.total_bytes) when:
      - .eh_frame is missing or empty
      - the FDE parser hit an unsupported encoding
      - addr is not inside any FDE
    """
    key = id(bv)
    ranges = _fde_cache.get(key)
    if ranges is None:
        ranges = eh_frame.parse_eh_frame(bv)
        _fde_cache[key] = ranges

    lo, hi = 0, len(ranges)
    while lo < hi:
        mid = (lo + hi) // 2
        s, e = ranges[mid]
        if addr < s:
            hi = mid
        elif addr >= e:
            lo = mid + 1
        else:
            return (s, e)

    fn = bv.get_function_at(addr)
    if fn is None:
        return (addr, addr)
    return (fn.start, fn.start + fn.total_bytes)


def invalidate_cache(bv=None) -> None:
    """Drop cached FDE ranges. Call after editing the binary or to force re-parse."""
    if bv is None:
        _fde_cache.clear()
    else:
        _fde_cache.pop(id(bv), None)
