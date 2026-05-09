"""Profile JNI_OnLoad's obfuscation pattern after the deobfuscator hits 100%.

Captures: CFG topology, every indirect jump (PC, branch register, candidate
targets, def chain), .data dispatch tables loaded from, csel/phi structure,
constants referenced by each jump's expression tree.

Writes JSON to .temp/jnionload_profile.json and a brief text summary to
/tmp/jnionload_profile.log so we can tail it.
"""

import json
import sys
import time

LOG = "/tmp/jnionload_profile.log"

def log(m):
    with open(LOG, "a") as f:
        f.write(m + "\n")

open(LOG, "w").close()

sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/.temp")
sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/plugin/bn_deobf")
import importlib, deobfuscator, eh_frame as ef
importlib.reload(deobfuscator); importlib.reload(ef)

from binaryninja import LowLevelILOperation

PC = 0x1a0b8c
fn = bv.get_function_at(PC)  # noqa: F821
log(f"start: blocks={len(list(fn.basic_blocks))} size={fn.total_bytes}")

# Re-run deobfuscator from scratch to ensure 100% coverage state.
ranges = ef.parse_eh_frame(bv)  # noqa: F821
fde = next((s, e) for s, e in ranges if s == PC)
log(f"FDE: {hex(fde[0])}..{hex(fde[1])} size={fde[1]-fde[0]}")

# Clear and re-resolve.
for blk in fn.low_level_il:
    for il in blk:
        if il.operation.name in ("LLIL_JUMP", "LLIL_JUMP_TO"):
            try: fn.set_user_indirect_branches(il.address, [])
            except: pass
bv.update_analysis_and_wait()  # noqa: F821
log(f"after clear: blocks={len(list(fn.basic_blocks))} size={fn.total_bytes}")

t0 = time.time()
report = deobfuscator.run(fn, fde)
log(f"deobf converged in {time.time()-t0:.1f}s, rounds={len(report['history'])}, audit={report['audit']['coverage_pct']}% covered={report['audit']['covered_bytes']}/{report['audit']['fde_size']}")

# ---- Now profile.

# 1. CFG topology
blocks = sorted(fn.basic_blocks, key=lambda b: b.start)
cfg = []
for b in blocks:
    cfg.append({
        "start": hex(b.start),
        "end": hex(b.end),
        "size": b.end - b.start,
        "preds": [hex(e.source.start) for e in b.incoming_edges],
        "succs": [(hex(e.target.start) if e.target else None, e.type.name) for e in b.outgoing_edges],
        "ends_indirect": False,  # filled below
    })
log(f"CFG: {len(blocks)} blocks; total bytes (in-FDE clamped): "
    f"{sum(min(b.end, fde[1]) - max(b.start, fde[0]) for b in blocks if b.start < fde[1] and b.end > fde[0])}")

# 2. Indirect jumps & their data-flow structure.
def expr_skeleton(e, depth=0, max_depth=6):
    """A compact JSON-ish skeleton of an LLIL expression — operation + key fields + recursive children."""
    if depth > max_depth:
        return {"op": "...", "trunc": True}
    op = e.operation.name
    out = {"op": op}
    if op in ("LLIL_CONST", "LLIL_CONST_PTR"):
        out["k"] = hex(e.constant & ((1 << 64) - 1))
    elif op == "LLIL_REG_SSA":
        out["reg"] = e.src.reg.name
        out["v"] = e.src.version
    elif op == "LLIL_REG_SSA_PARTIAL":
        out["reg"] = e.full_reg.reg.name
        out["v"] = e.full_reg.version
        out["sz"] = e.size
    elif op in ("LLIL_LOAD", "LLIL_LOAD_SSA"):
        out["sz"] = e.size
        out["addr"] = expr_skeleton(e.src, depth + 1, max_depth)
    elif op in ("LLIL_ADD", "LLIL_SUB", "LLIL_AND", "LLIL_OR", "LLIL_XOR",
                "LLIL_MUL", "LLIL_LSL", "LLIL_LSR", "LLIL_ASR"):
        out["sz"] = e.size
        out["l"] = expr_skeleton(e.left, depth + 1, max_depth)
        out["r"] = expr_skeleton(e.right, depth + 1, max_depth)
    elif op in ("LLIL_SX", "LLIL_ZX", "LLIL_LOW_PART", "LLIL_NEG", "LLIL_NOT"):
        out["sz"] = e.size
        out["x"] = expr_skeleton(e.src, depth + 1, max_depth)
    return out

def def_skeleton(ssa, ssa_reg, depth=0, max_depth=4, seen=None):
    """Walk SSA reg definition chain, summarized for human reading."""
    if seen is None:
        seen = set()
    key = (ssa_reg.reg.name, ssa_reg.version)
    if key in seen:
        return {"reg": ssa_reg.reg.name, "v": ssa_reg.version, "cycle": True}
    if depth > max_depth:
        return {"reg": ssa_reg.reg.name, "v": ssa_reg.version, "trunc": True}
    seen = seen | {key}
    defn = ssa.get_ssa_reg_definition(ssa_reg)
    if defn is None:
        return {"reg": ssa_reg.reg.name, "v": ssa_reg.version, "external": True}
    op = defn.operation.name
    node = {"reg": ssa_reg.reg.name, "v": ssa_reg.version, "def_op": op, "pc": hex(defn.address)}
    if op == "LLIL_REG_PHI":
        node["phi_sources"] = [def_skeleton(ssa, src, depth + 1, max_depth, seen) for src in defn.src]
    elif op in ("LLIL_SET_REG_SSA", "LLIL_SET_REG_SSA_PARTIAL"):
        node["expr"] = expr_skeleton(defn.src, 0, 6)
    return node

ssa = fn.low_level_il.ssa_form
indirect_pcs = []
for blk in fn.low_level_il:
    for il in blk:
        if il.operation.name in ("LLIL_JUMP", "LLIL_JUMP_TO"):
            indirect_pcs.append(il.address)

log(f"indirect jumps: {len(indirect_pcs)}")

ij = []
for pc in indirect_pcs:
    il = fn.get_low_level_il_at(pc)
    if il is None:
        continue
    ssa_il = il.ssa_form
    ibs = sorted(int(ib.dest_addr) for ib in fn.get_indirect_branches_at(pc))
    rec = {
        "pc": hex(pc),
        "n_targets": len(ibs),
        "targets": [hex(t) for t in ibs[:8]],
        "more_targets": max(0, len(ibs) - 8),
    }
    if hasattr(ssa_il, "dest"):
        rec["dest_skel"] = expr_skeleton(ssa_il.dest, 0, 6)
        # If dest is just a reg, also walk one level of SSA def
        d = ssa_il.dest
        if d.operation.name == "LLIL_REG_SSA":
            rec["dest_def"] = def_skeleton(ssa, d.src, 0, 4)
        elif d.operation.name == "LLIL_REG_SSA_PARTIAL":
            rec["dest_def"] = def_skeleton(ssa, d.full_reg, 0, 4)
    ij.append(rec)

# Mark indirect-ending blocks in CFG.
indirect_set = set(indirect_pcs)
for b, c in zip(blocks, cfg):
    # last instruction's address.
    last_pc = b.end - 4
    if last_pc in indirect_set:
        c["ends_indirect"] = True

# 3. .data load addresses observed in indirect-jump expressions.
# Walk every jump's expr, collect const_ptr addrs that are loaded from.
def collect_load_addrs(skel, out):
    op = skel.get("op")
    if op in ("LLIL_LOAD", "LLIL_LOAD_SSA"):
        addr = skel.get("addr") or {}
        if addr.get("op") in ("LLIL_CONST", "LLIL_CONST_PTR"):
            out.add((addr["k"], skel.get("sz", 8)))
        elif addr.get("op") == "LLIL_ADD":
            l = addr.get("l", {}); r = addr.get("r", {})
            for s in (l, r):
                if s.get("op") in ("LLIL_CONST", "LLIL_CONST_PTR"):
                    out.add((s["k"], skel.get("sz", 8)))
    for k, v in skel.items():
        if isinstance(v, dict):
            collect_load_addrs(v, out)
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, dict):
                    collect_load_addrs(x, out)

load_addrs = set()
for r in ij:
    if "dest_skel" in r:
        collect_load_addrs(r["dest_skel"], load_addrs)
    if "dest_def" in r:
        collect_load_addrs(r["dest_def"], load_addrs)
log(f"distinct .data const-pointer load bases used by indirect jumps: {len(load_addrs)}")
for k, sz in sorted(load_addrs):
    log(f"  load{sz} @ {k}")

# 4. Sample first/middle/last indirect-jump records for the report.
samples = []
if ij:
    samples = [ij[0], ij[len(ij)//2], ij[-1]]

profile = {
    "func": "JNI_OnLoad",
    "addr": hex(PC),
    "fde": [hex(fde[0]), hex(fde[1]), fde[1] - fde[0]],
    "cfg_blocks": len(blocks),
    "covered_pct": report["audit"]["coverage_pct"],
    "indirect_jump_pcs": [hex(p) for p in indirect_pcs],
    "n_indirect_jumps": len(indirect_pcs),
    "data_load_bases": sorted(list(load_addrs)),
    "indirect_jumps": ij,
    "cfg": cfg,
    "samples": samples,
}

with open("/Users/fallw1nd/Documents/claude_project/bn/.temp/jnionload_profile.json", "w") as f:
    json.dump(profile, f, indent=2)
log(f"written: .temp/jnionload_profile.json ({len(json.dumps(profile))} bytes)")

# Also: classify n_targets distribution.
from collections import Counter
hist = Counter(r["n_targets"] for r in ij)
log(f"target-count histogram: {dict(sorted(hist.items()))}")

# Look for the dispatch-table pattern: dest = load(const_base + index*8), index in {const set}
table_jumps = 0
direct_jumps = 0
phi_jumps = 0
for r in ij:
    s = r.get("dest_skel") or {}
    # csel/phi style: dest_def has phi_sources of constants
    dd = r.get("dest_def") or {}
    if dd.get("def_op") == "LLIL_REG_PHI" and any(p.get("def_op", "").startswith("LLIL_SET_REG_SSA") for p in dd.get("phi_sources", [])):
        phi_jumps += 1
    if s.get("op") in ("LLIL_LOAD", "LLIL_LOAD_SSA"):
        table_jumps += 1
    if s.get("op") in ("LLIL_CONST", "LLIL_CONST_PTR"):
        direct_jumps += 1

log(f"jump shape classification: load_dispatch={table_jumps} const={direct_jumps} phi_via_reg={phi_jumps} other={len(ij) - table_jumps - direct_jumps - phi_jumps}")

result = {
    "blocks": len(blocks),
    "covered_pct": report["audit"]["coverage_pct"],
    "indirect_jumps": len(indirect_pcs),
    "load_bases": len(load_addrs),
    "target_histogram": dict(sorted(hist.items())),
    "load_dispatch": table_jumps,
    "direct_const": direct_jumps,
    "phi_via_reg": phi_jumps,
}
