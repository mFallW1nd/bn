"""Deep SSA-def trace for the 6-target and 2-target indirect jumps in JNI_OnLoad."""

import json, sys, struct
sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/.temp")
sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/plugin/bn_deobf")
import importlib, deobfuscator, eh_frame as ef
importlib.reload(deobfuscator); importlib.reload(ef)

PC = 0x1a0b8c
fn = bv.get_function_at(PC)  # noqa: F821

# Make sure we're in resolved state.
ranges = ef.parse_eh_frame(bv)  # noqa: F821
fde = next((s, e) for s, e in ranges if s == PC)
for blk in fn.low_level_il:
    for il in blk:
        if il.operation.name in ("LLIL_JUMP", "LLIL_JUMP_TO"):
            try: fn.set_user_indirect_branches(il.address, [])
            except: pass
bv.update_analysis_and_wait()  # noqa: F821
deobfuscator.run(fn, fde)

ssa = fn.low_level_il.ssa_form
profile = json.load(open("/Users/fallw1nd/Documents/claude_project/bn/.temp/jnionload_profile.json"))

# Pick the 6-target and 2-target examples.
six_targets = [j for j in profile["indirect_jumps"] if j["n_targets"] == 6]
two_targets = [j for j in profile["indirect_jumps"] if j["n_targets"] == 2]

def expr_skel(e, depth=0, max_depth=8):
    if depth > max_depth: return {"op": "...", "trunc": True}
    op = e.operation.name
    out = {"op": op}
    if op in ("LLIL_CONST", "LLIL_CONST_PTR"):
        out["k"] = hex(e.constant & ((1 << 64) - 1))
    elif op == "LLIL_REG_SSA":
        out["reg"] = e.src.reg.name; out["v"] = e.src.version
    elif op == "LLIL_REG_SSA_PARTIAL":
        out["reg"] = e.full_reg.reg.name; out["v"] = e.full_reg.version; out["sz"] = e.size
    elif op in ("LLIL_LOAD", "LLIL_LOAD_SSA"):
        out["sz"] = e.size; out["addr"] = expr_skel(e.src, depth+1, max_depth)
    elif op in ("LLIL_ADD", "LLIL_SUB", "LLIL_AND", "LLIL_OR", "LLIL_XOR", "LLIL_MUL"):
        out["sz"] = e.size; out["l"] = expr_skel(e.left, depth+1, max_depth); out["r"] = expr_skel(e.right, depth+1, max_depth)
    elif op in ("LLIL_LSL", "LLIL_LSR", "LLIL_ASR"):
        out["sz"] = e.size; out["l"] = expr_skel(e.left, depth+1, max_depth); out["r"] = expr_skel(e.right, depth+1, max_depth)
    elif op in ("LLIL_SX", "LLIL_ZX", "LLIL_LOW_PART", "LLIL_NEG", "LLIL_NOT"):
        out["sz"] = e.size; out["x"] = expr_skel(e.src, depth+1, max_depth)
    return out

def trace_reg(ssa, ssa_reg, depth=0, max_depth=10, seen=None):
    if seen is None: seen = set()
    key = (ssa_reg.reg.name, ssa_reg.version)
    if key in seen: return {"reg": key[0], "v": key[1], "cycle": True}
    if depth > max_depth: return {"reg": key[0], "v": key[1], "trunc": True}
    seen = seen | {key}
    defn = ssa.get_ssa_reg_definition(ssa_reg)
    if defn is None:
        # entry value
        return {"reg": key[0], "v": key[1], "external": True}
    op = defn.operation.name
    n = {"reg": key[0], "v": key[1], "def_op": op, "pc": hex(defn.address)}
    if op == "LLIL_REG_PHI":
        n["phi"] = [trace_reg(ssa, src, depth+1, max_depth, seen) for src in defn.src]
    elif op == "LLIL_SET_REG_SSA":
        n["expr"] = expr_skel(defn.src)
        # Recurse into reg children of expr
        n["children"] = []
        for child in defn.src.operands:
            if hasattr(child, "operation"):
                co = child.operation.name
                if co == "LLIL_REG_SSA":
                    n["children"].append(trace_reg(ssa, child.src, depth+1, max_depth, seen))
                elif co == "LLIL_REG_SSA_PARTIAL":
                    n["children"].append(trace_reg(ssa, child.full_reg, depth+1, max_depth, seen))
    elif op == "LLIL_SET_REG_SSA_PARTIAL":
        n["expr"] = expr_skel(defn.src)
        n["partial_size"] = defn.size
    return n

def trace_indirect_jump(jump_pc):
    il = fn.get_low_level_il_at(jump_pc)
    ssa_il = il.ssa_form
    d = ssa_il.dest
    if d.operation.name == "LLIL_REG_SSA":
        return trace_reg(ssa, d.src)
    elif d.operation.name == "LLIL_REG_SSA_PARTIAL":
        return trace_reg(ssa, d.full_reg)
    return None

deep = {}
deep["six_targets"] = []
for j in six_targets[:2]:  # just 2 examples
    pc = int(j["pc"], 16)
    deep["six_targets"].append({"pc": j["pc"], "targets": j["targets"], "trace": trace_indirect_jump(pc)})

deep["two_targets"] = []
for j in two_targets[:3]:
    pc = int(j["pc"], 16)
    deep["two_targets"].append({"pc": j["pc"], "targets": j["targets"], "trace": trace_indirect_jump(pc)})

# Also dump .data slots referenced by ldr instructions in the function.
data_slots = set()
for blk in fn.low_level_il:
    for il in blk:
        for op in (il, *getattr(il, "operands", [])):
            if not hasattr(op, "operation"): continue
            if op.operation.name in ("LLIL_LOAD", "LLIL_LOAD_SSA"):
                # check for const+const or reg+const
                if hasattr(op.src, "operation") and op.src.operation.name == "LLIL_ADD":
                    for x in (op.src.left, op.src.right):
                        if hasattr(x, "operation") and x.operation.name in ("LLIL_CONST", "LLIL_CONST_PTR"):
                            pass  # we tracked via x.constant earlier
# Skip — we'll just read known .data slots from disasm.
# Read .data values and resolve targets.
key_slots = [0x74acd0, 0x74ac80, 0x74acb0, 0x74acb8, 0x74acc0, 0x74acc8]
data_vals = {}
for a in key_slots:
    raw = bv.read(a, 8)  # noqa: F821
    if raw and len(raw) == 8:
        data_vals[hex(a)] = hex(struct.unpack("<Q", raw)[0])
deep["data_keys"] = data_vals

with open("/Users/fallw1nd/Documents/claude_project/bn/.temp/jnionload_deep.json", "w") as f:
    json.dump(deep, f, indent=2)

result = {"six_n": len(deep["six_targets"]), "two_n": len(deep["two_targets"])}
