"""Indirect-branch deobfuscator for chained-jump obfuscation
(libtiny.so style: csel + .data dispatch tables + linked chunks).

Operates on LLIL SSA form. csel materializes as LLIL_REG_PHI nodes; the
evaluator unions phi sources and propagates value sets through the expression
tree, reading .data loads directly from the BV when needed.

The driver does ONE thing per indirect branch: union (current targets ∪
evaluator candidates), restrict to the function's FDE range, and commit.
That one rule subsumes "fix up BN auto's out-of-FDE picks" and "augment
BN auto's narrow set" without separate sweeps.

All write entry points (run, step, deobfuscate_all) accept an `undoable`
flag (default True) that wraps the work in `bv.undoable_transaction()`.
Successful runs commit a single undo entry — Cmd-Z / `bv.undo()` reverts
the whole pass. Exceptions inside the transaction auto-revert. Pass
`undoable=False` to skip the transaction (e.g. when the caller manages
its own).

Designed to run inside `bn py exec`. Public API:

    resolve_targets(func, pc)              -> set[int] | None
    step(func, fde_range, **kw)            -> dict       # one pass
    run(func, fde_range, **kw)             -> dict       # iterate to fixpoint
    audit(func, fde_range)                 -> dict       # diagnostic
    parse_fde_ranges(path)                 -> list[(start, end)]
    deobfuscate_all(bv, fde_ranges, **kw)  -> dict       # batch over a binary
"""

from __future__ import annotations

import contextlib
import re
from pathlib import Path
from typing import Iterable

from binaryninja import RegisterValueType


def _maybe_undoable(bv, undoable: bool):
    """Wrap mutations in `bv.undoable_transaction()` when undoable=True."""
    return bv.undoable_transaction() if undoable else contextlib.nullcontext()


# ---------------------------------------------------------------------------
# Bit math.

_U64 = (1 << 64) - 1


def _mask(sz: int) -> int:
    return (1 << (sz * 8)) - 1


def _trunc(v: int, sz: int) -> int:
    return v & _mask(sz)


def _sext(v: int, frm: int, to: int) -> int:
    bits = frm * 8
    if v & (1 << (bits - 1)):
        v -= 1 << bits
    return _trunc(v, to)


# ---------------------------------------------------------------------------
# Op handlers — pure transforms, dispatched by op name.

# Binary: (left, right, size) -> int.
_BIN = {
    "LLIL_ADD": lambda l, r, sz: _trunc(l + r, sz),
    "LLIL_SUB": lambda l, r, sz: _trunc(l - r, sz),
    "LLIL_AND": lambda l, r, sz: _trunc(l & r, sz),
    "LLIL_OR":  lambda l, r, sz: _trunc(l | r, sz),
    "LLIL_XOR": lambda l, r, sz: _trunc(l ^ r, sz),
    "LLIL_MUL": lambda l, r, sz: _trunc(l * r, sz),
    "LLIL_LSL": lambda l, r, sz: _trunc(l << (r & 63), sz),
    "LLIL_LSR": lambda l, r, sz: (l & _mask(sz)) >> (r & 63),
    "LLIL_ASR": lambda l, r, sz: _sext(l, sz, sz) >> (r & 63),
}

# Unary: (value, expr) -> int. Closure on `expr` reads .src.size when needed.
_UNARY = {
    "LLIL_SX":       lambda v, e: _trunc(_sext(v, e.src.size, e.size), e.size),
    "LLIL_ZX":       lambda v, e: _trunc(v, e.size),
    "LLIL_LOW_PART": lambda v, e: _trunc(v, e.size),
    "LLIL_NEG":      lambda v, e: _trunc(-v, e.size),
    "LLIL_NOT":      lambda v, e: _trunc(~v, e.size),
}


# ---------------------------------------------------------------------------
# Multi-value SSA evaluator.

class _Eval:
    """Bounded, cycle-safe, cached SSA expression evaluator.

    Returns set[int] of possible values, or None on failure. Multi-value lets
    us model csel — which surfaces as LLIL_REG_PHI in SSA — by enumerating
    and unioning every phi source.
    """

    __slots__ = ("ssa", "bv", "max_set", "max_depth", "_cache", "_active")

    def __init__(self, ssa_func, *, max_set: int = 32, max_depth: int = 32):
        self.ssa = ssa_func
        self.bv = ssa_func.source_function.view
        self.max_set = max_set
        self.max_depth = max_depth
        self._cache: dict = {}
        self._active: set = set()

    # -- expression -----------------------------------------------------

    def expr(self, e, depth: int = 0):
        if depth > self.max_depth:
            return None
        op = e.operation.name

        if op in ("LLIL_CONST", "LLIL_CONST_PTR"):
            return {e.constant & _U64}

        if op == "LLIL_REG_SSA":
            return self._reg(e.src, depth + 1, partial_size=None)
        if op == "LLIL_REG_SSA_PARTIAL":
            return self._reg(e.full_reg, depth + 1, partial_size=e.size)

        if op in ("LLIL_LOAD", "LLIL_LOAD_SSA"):
            addrs = self.expr(e.src, depth + 1)
            if addrs is None:
                return None
            out: set = set()
            for a in addrs:
                data = self.bv.read(a, e.size)
                if not data or len(data) < e.size:
                    return None
                out.add(int.from_bytes(data, "little"))
                if len(out) > self.max_set:
                    return None
            return out

        if op in _BIN:
            ls = self.expr(e.left, depth + 1)
            rs = self.expr(e.right, depth + 1)
            if ls is None or rs is None:
                return None
            fn = _BIN[op]
            out = set()
            for l in ls:
                for r in rs:
                    out.add(fn(l, r, e.size))
                    if len(out) > self.max_set:
                        return None
            return out

        if op in _UNARY:
            xs = self.expr(e.src, depth + 1)
            if xs is None:
                return None
            fn = _UNARY[op]
            return {fn(v, e) for v in xs}

        return None

    # -- register definition --------------------------------------------

    def _reg(self, ssa_reg, depth: int, *, partial_size: int | None):
        key = (ssa_reg.reg.name, ssa_reg.version, partial_size)
        cached = self._cache.get(key, _MISS)
        if cached is not _MISS:
            return cached
        if key in self._active:
            return None  # cycle
        self._active.add(key)
        try:
            result = self._reg_uncached(ssa_reg, depth, partial_size)
        finally:
            self._active.discard(key)
        self._cache[key] = result
        return result

    def _reg_uncached(self, ssa_reg, depth: int, partial_size: int | None):
        defn = self.ssa.get_ssa_reg_definition(ssa_reg)
        if defn is None:
            # Function-entry value or external. Last-ditch: BN's path-insensitive VSA.
            func = self.ssa.source_function
            try:
                rv = func.get_reg_value_at(func.start, ssa_reg.reg.name)
            except Exception:
                return None
            if rv.type in (RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue):
                v = rv.value & _U64
                return {_trunc(v, partial_size) if partial_size else v}
            return None

        op = defn.operation.name
        if op == "LLIL_REG_PHI":
            out: set = set()
            for src in defn.src:
                sub = self._reg(src, depth + 1, partial_size=partial_size)
                if sub is None:
                    return None
                out |= sub
                if len(out) > self.max_set:
                    return None
            return out
        if op == "LLIL_SET_REG_SSA":
            sub = self.expr(defn.src, depth + 1)
            if sub is None:
                return None
            return {_trunc(v, partial_size) for v in sub} if partial_size else sub
        if op == "LLIL_SET_REG_SSA_PARTIAL":
            sub = self.expr(defn.src, depth + 1)
            if sub is None:
                return None
            return {_trunc(v, defn.size) for v in sub}
        return None


_MISS = object()


# ---------------------------------------------------------------------------
# Public API.

def _auto_params(fde_size: int) -> dict:
    """Pick (max_set, max_depth, max_rounds) by FDE size.

    Calibrated on libtiny.so: small functions converge with the original
    defaults; 8k-32k functions need a larger set to keep multi-value
    enumeration alive (sample showed 8k coverage 41%→80% with max_set=64);
    >32k functions are dispatch-table-heavy and need both deeper traversal
    and many more rounds to drain the worklist.
    """
    if fde_size <= 1024:
        return {"max_set": 32,   "max_depth": 32,  "max_rounds": 30}
    if fde_size <= 8192:
        return {"max_set": 64,   "max_depth": 48,  "max_rounds": 60}
    if fde_size <= 32768:
        return {"max_set": 256,  "max_depth": 64,  "max_rounds": 90}
    if fde_size <= 131072:
        return {"max_set": 512,  "max_depth": 96,  "max_rounds": 120}
    return {"max_set": 1024, "max_depth": 128, "max_rounds": 150}


def resolve_targets(func, pc, *, max_set: int = 32, max_depth: int = 32):
    """Resolve the indirect branch at pc to a candidate set, or None."""
    il = func.get_low_level_il_at(pc)
    if il is None or il.operation.name not in ("LLIL_JUMP", "LLIL_JUMP_TO"):
        return None
    ssa_il = il.ssa_form
    if ssa_il is None or not hasattr(ssa_il, "dest"):
        return None
    return _Eval(func.low_level_il.ssa_form, max_set=max_set, max_depth=max_depth).expr(ssa_il.dest)


def step(func, fde_range, *, max_set: int | None = None, max_depth: int | None = None,
         undoable: bool = False, wait: bool = True) -> dict:
    """One pass: for every LLIL_JUMP[_TO] in func, set its user_indirect_branches
    to (current ∪ evaluator) ∩ fde_range. This single rule both adds missing
    targets and prunes BN-auto targets that escaped the FDE.

    `undoable=True` wraps the pass in `bv.undoable_transaction()`. Default is
    False because step() is normally called from run(), which handles the
    transaction at a coarser granularity.

    `wait=True` (default) calls `bv.update_analysis_and_wait()` at the end so
    the next step() sees the new BN-auto edges. Pass `wait=False` when calling
    from inside an Activity action — the analysis pipeline is already running
    and a recursive wait would deadlock.

    `max_set`/`max_depth` default to size-adaptive values from `_auto_params`
    when None.
    """
    fs, fe = fde_range
    bv = func.view
    arch = bv.arch
    auto = _auto_params(fe - fs)
    if max_set is None:
        max_set = auto["max_set"]
    if max_depth is None:
        max_depth = auto["max_depth"]

    with _maybe_undoable(bv, undoable):
        ev = _Eval(func.low_level_il.ssa_form, max_set=max_set, max_depth=max_depth)

        new_edges = 0
        pruned = 0
        touched = []

        for block in func.low_level_il:
            for il in block:
                if il.operation.name not in ("LLIL_JUMP", "LLIL_JUMP_TO"):
                    continue
                pc = il.address
                ssa_il = il.ssa_form
                if ssa_il is None or not hasattr(ssa_il, "dest"):
                    continue

                current = {ib.dest_addr for ib in func.get_indirect_branches_at(pc)}
                cands = ev.expr(ssa_il.dest) or set()
                merged = {t for t in (current | cands) if fs <= t < fe}

                if merged != current:
                    if merged:
                        func.set_user_indirect_branches(pc, [(arch, t) for t in sorted(merged)])
                    new_edges += len(merged - current)
                    pruned += len(current - merged)
                    touched.append((hex(pc), len(merged)))

        if wait:
            bv.update_analysis_and_wait()
        return {"new_edges": new_edges, "pruned": pruned, "touched": touched}


def run(func, fde_range, *, max_rounds: int | None = None,
        max_set: int | None = None, max_depth: int | None = None,
        undoable: bool = True) -> dict:
    """Iterate step() until fixpoint or max_rounds. Returns audit + history.

    `undoable=True` (default) wraps the entire run in one undoable_transaction:
    the whole convergence becomes a single GUI undo entry, and any exception
    auto-reverts. Pass False to manage the transaction yourself.

    `max_rounds`/`max_set`/`max_depth` default to size-adaptive values from
    `_auto_params` when None — small functions stay cheap, large dispatch-table
    monsters get the headroom they need.
    """
    fs, fe = fde_range
    auto = _auto_params(fe - fs)
    if max_rounds is None:
        max_rounds = auto["max_rounds"]
    if max_set is None:
        max_set = auto["max_set"]
    if max_depth is None:
        max_depth = auto["max_depth"]

    with _maybe_undoable(func.view, undoable):
        history = []
        for r in range(max_rounds):
            s = step(func, fde_range, max_set=max_set, max_depth=max_depth, undoable=False)
            history.append({"round": r, **s})
            if s["new_edges"] == 0 and s["pruned"] == 0:
                break
        return {"history": history, "audit": audit(func, fde_range)}


def audit(func, fde_range) -> dict:
    """Coverage %, gaps, reachability, edge sanity for a function.

    Coverage is clamped to fde_range: bytes a block contributes outside the
    FDE (e.g. when BN extended this function into adjacent code) are excluded.
    out_of_fde_blocks / out_of_fde_edges expose that side-effect.
    """
    fs, fe = fde_range
    bbs = sorted(func.basic_blocks, key=lambda b: b.start)
    covered = sum(max(0, min(b.end, fe) - max(b.start, fs)) for b in bbs)

    gaps = []
    prev = fs
    for b in bbs:
        if b.start > prev:
            gaps.append((prev, b.start))
        prev = max(prev, b.end)
    if prev < fe:
        gaps.append((prev, fe))

    # Reachability from entry block.
    seen: set = set()
    stack = [bbs[0]] if bbs else []
    while stack:
        bb = stack.pop()
        if bb.start in seen:
            continue
        seen.add(bb.start)
        for e in bb.outgoing_edges:
            if e.target and e.target.start not in seen:
                stack.append(e.target)

    out_of_fde_edges = sum(
        1 for b in bbs for pc in range(b.start, b.end, 4)
        for ib in func.get_indirect_branches_at(pc)
        if not (fs <= ib.dest_addr < fe)
    )

    return {
        "blocks": len(bbs),
        "covered_bytes": covered,
        "fde_size": fe - fs,
        "coverage_pct": round(covered / (fe - fs) * 100, 2) if fe > fs else 0.0,
        "gaps": [(hex(s), hex(e), e - s) for s, e in gaps],
        "unreachable_blocks": [hex(s) for s in sorted({b.start for b in bbs} - seen)],
        "out_of_fde_blocks": sum(1 for b in bbs if not (fs <= b.start < fe)),
        "out_of_fde_edges": out_of_fde_edges,
    }


_FDE_RE = re.compile(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)")


def parse_fde_ranges(path) -> list:
    """Parse `readelf -wf <so>` output (file path) into [(start, end), ...]."""
    text = Path(path).read_text()
    return [(int(m[1], 16), int(m[2], 16)) for m in _FDE_RE.finditer(text)]


def deobfuscate_all(bv, fde_ranges: Iterable, *,
                    max_rounds: int | None = None, max_set: int | None = None,
                    progress_every: int = 0,
                    undoable: bool = True) -> dict:
    """Register every FDE start as a function and run() each one. Skips empty FDEs.

    `undoable=True` (default) wraps the entire batch in a single
    undoable_transaction so a single `bv.undo()` reverts the whole sweep.
    Use False if you want per-function transactions instead — this function
    will then call run() with undoable=True internally.

    `max_rounds`/`max_set` default to size-adaptive values per function (via
    `_auto_params`); pass explicit ints to override uniformly.
    """
    ranges = [(s, e) for s, e in fde_ranges if e > s]

    with _maybe_undoable(bv, undoable):
        for s, _ in ranges:
            if not bv.get_function_at(s):
                bv.add_function(s)
        bv.update_analysis_and_wait()

        summaries = []
        for i, (s, e) in enumerate(ranges):
            f = bv.get_function_at(s)
            if f is None:
                continue
            # If we own the outer transaction, inner run() shouldn't open a nested one;
            # otherwise let each function get its own undo entry.
            inner_undoable = not undoable
            summaries.append({"func": hex(s),
                              **run(f, (s, e), max_rounds=max_rounds, max_set=max_set,
                                    undoable=inner_undoable)["audit"]})
            if progress_every and (i + 1) % progress_every == 0:
                avg = sum(x["coverage_pct"] for x in summaries) / len(summaries)
                print(f"[{i+1}/{len(ranges)}] avg coverage: {avg:.1f}%")
        return {"functions": summaries, "count": len(summaries)}
