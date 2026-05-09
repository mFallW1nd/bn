"""分支支配关系分析：分发块 vs 真实块 in JNI_OnLoad

定义:
  分发块 (dispatch / merge): preds > 1 的基本块。这些块的开头有 LLIL_REG_PHI,
                              对应经典 fla 中 dispatcher 的 state phi.
  真实块 (real):              preds <= 1 的基本块.

输出:
  1. 每个分发块的 immediate_dominator / post_dominator
  2. 13 个分发块构成的 dominator subtree (只保留分发块之间的 dom 关系)
  3. 每个分发块"管辖"哪些真实块 (在 dom tree 中由该分发块严格支配但不被其它分发块严格支配)
  4. 整体属性: 是否存在某个分发块支配所有其他分发块? Post-dominate?
"""

import json, sys
sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/.temp")
sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/plugin/bn_deobf")
import importlib, deobfuscator, eh_frame as ef
importlib.reload(deobfuscator); importlib.reload(ef)

PC = 0x1a0b8c
fn = bv.get_function_at(PC)  # noqa: F821
ranges = ef.parse_eh_frame(bv)  # noqa: F821
fde = next((s, e) for s, e in ranges if s == PC)

# 重新跑反混淆 (确保 100% 状态)
for blk in fn.low_level_il:
    for il in blk:
        if il.operation.name in ("LLIL_JUMP", "LLIL_JUMP_TO"):
            try: fn.set_user_indirect_branches(il.address, [])
            except: pass
bv.update_analysis_and_wait()  # noqa: F821
deobfuscator.run(fn, fde)

blocks = sorted(fn.basic_blocks, key=lambda b: b.start)
b_by_start = {b.start: b for b in blocks}

# 分类
def n_preds(b):
    return len(list(b.incoming_edges))

dispatch = [b for b in blocks if n_preds(b) > 1]
real     = [b for b in blocks if n_preds(b) <= 1]

print(f"total blocks: {len(blocks)}  dispatch (preds>1): {len(dispatch)}  real (preds<=1): {len(real)}")

# 拿 BN 的 dominators / post_dominators 关系
# BasicBlock.dominators -> set of BasicBlock that dominate this block (incl self)
# BasicBlock.immediate_dominator -> the BasicBlock that immediately dominates
# BasicBlock.post_dominators / immediate_post_dominator 同理
def dom_starts(b):
    try:
        return {d.start for d in b.dominators}
    except Exception:
        return set()

def pdom_starts(b):
    try:
        return {d.start for d in b.post_dominators}
    except Exception:
        return set()

# 完整 dom tree: idom(b)
idoms = {}
ipdoms = {}
for b in blocks:
    try:
        idoms[b.start] = b.immediate_dominator.start if b.immediate_dominator else None
    except Exception:
        idoms[b.start] = None
    try:
        ipdoms[b.start] = b.immediate_post_dominator.start if b.immediate_post_dominator else None
    except Exception:
        ipdoms[b.start] = None

dispatch_starts = {b.start for b in dispatch}
real_starts = {b.start for b in real}

# Q1: 13 个分发块两两之间, 谁支配谁?
print("\n=== 分发块两两 dom 关系 (a strictly dominates b) ===")
dispatch_pairs = []
for a in dispatch:
    for b in dispatch:
        if a.start == b.start:
            continue
        if a.start in dom_starts(b) and a.start != b.start:
            # a dominates b strictly
            dispatch_pairs.append((a.start, b.start))

print(f"  pairs (a strictly dominates b): {len(dispatch_pairs)}")
# 抽出: 对每个分发块, 它被多少个其他分发块支配
dom_count_in = {b.start: 0 for b in dispatch}  # 多少个其他分发块严格支配它
for a, b in dispatch_pairs:
    dom_count_in[b] += 1

# entry-most 分发块 (没有任何其他分发块支配它的)
top_disp = [d for d, k in dom_count_in.items() if k == 0]
print(f"  top-level dispatches (no other dispatch dominates): {len(top_disp)} -> {[hex(x) for x in sorted(top_disp)]}")

# Q2: 分发块之间的 idom 关系 (在 dom tree 上, 离它最近的分发块祖先是谁?)
def nearest_dispatch_ancestor(start):
    """在 dom tree 上向上爬, 找到第一个 dispatch 块 (不含 start 自己)."""
    p = idoms.get(start)
    while p is not None and p != start:
        if p in dispatch_starts:
            return p
        p = idoms.get(p)
    return None

dispatch_tree = {}  # parent_dispatch -> [child_dispatches]
for d in dispatch:
    parent = nearest_dispatch_ancestor(d.start)
    dispatch_tree.setdefault(parent, []).append(d.start)

print("\n=== 分发块构成的 dominator subtree (parent dispatch -> child dispatch) ===")
def render_subtree(node, depth=0):
    indent = "  " * depth
    label = f"{hex(node)}" if node is not None else "(root)"
    n_real_below = sum(1 for r in real if (idoms.get(r.start) == node or
                                            nearest_dispatch_ancestor(r.start) == node))
    preds = n_preds(b_by_start[node]) if node is not None else 0
    print(f"{indent}{label}  preds={preds}  immediate-real-children≈{n_real_below}")
    for c in sorted(dispatch_tree.get(node, [])):
        render_subtree(c, depth + 1)

render_subtree(None)

# Q3: 每个分发块"管辖"的真实块 (nearest dispatch ancestor == 该分发块)
print("\n=== 每个分发块直接管辖的真实块 ===")
governance = {}
for r in real:
    nd = nearest_dispatch_ancestor(r.start)
    governance.setdefault(nd, []).append(r.start)

for d in sorted(dispatch_starts):
    rs = sorted(governance.get(d, []))
    print(f"  dispatch {hex(d)}  preds={n_preds(b_by_start[d])}  manages {len(rs)} real blocks: {[hex(x) for x in rs[:6]]}{'...' if len(rs)>6 else ''}")
top_real = sorted(governance.get(None, []))
print(f"  (top, no dispatch ancestor): {len(top_real)} real blocks: {[hex(x) for x in top_real]}")

# Q4: 是否存在"全局根 dispatcher" - 一个支配所有其他分发块的分发块?
all_dispatch_doms = None
for d in dispatch:
    dms = dom_starts(d) & dispatch_starts
    dms.discard(d.start)
    # `dms` 是支配 d 的所有其他分发块
print(f"\n=== Q: 是否有 root-dispatch (支配所有其他 dispatch)? ===")
candidates = []
for d in dispatch:
    # d 支配的所有其他 dispatch
    dom_others = sum(1 for d2 in dispatch if d2.start != d.start and d.start in dom_starts(d2))
    if dom_others == len(dispatch) - 1:
        candidates.append(d.start)
print(f"  支配所有其他 dispatch 的块: {[hex(x) for x in candidates]}")

# Q5: post-dominator 角度 - 是否存在"出口分发"概念?
print(f"\n=== Q: 是否有分发块 post-dominate 其他分发块? ===")
pd_pairs = []
for a in dispatch:
    for b in dispatch:
        if a.start == b.start: continue
        if a.start in pdom_starts(b):
            pd_pairs.append((a.start, b.start))
print(f"  post-dom pairs (a strictly post-dominates b): {len(pd_pairs)}")
candidates_pd = []
for d in dispatch:
    pd_others = sum(1 for d2 in dispatch if d2.start != d.start and d.start in pdom_starts(d2))
    if pd_others == len(dispatch) - 1:
        candidates_pd.append(d.start)
print(f"  post-dominate 所有其他 dispatch 的块: {[hex(x) for x in candidates_pd]}")

# Q6: 分发块"链长" - 从 entry 到每个分发块途经多少个其他分发块
print(f"\n=== 分发块在 dom 链上的深度 ===")
for d in sorted(dispatch_starts):
    # 走 idom 链, 数 dispatch 出现次数
    chain = []
    p = idoms.get(d)
    while p is not None and p != d:
        if p in dispatch_starts:
            chain.append(p)
        p = idoms.get(p)
    print(f"  {hex(d)}: dom-chain depth (via dispatches)={len(chain)} -> {[hex(x) for x in chain[:6]]}")

# Q7: 真实块的"流入" - 真实块全部 immediate-dominate by 分发块? 还是被另一个真实块 immediate-dominate?
print(f"\n=== 真实块的 immediate dominator 类型 ===")
real_idom_dispatch = sum(1 for r in real if idoms.get(r.start) in dispatch_starts)
real_idom_real    = sum(1 for r in real if idoms.get(r.start) in real_starts)
real_idom_self    = sum(1 for r in real if idoms.get(r.start) == r.start)
print(f"  real 被 dispatch immediate-dominate: {real_idom_dispatch}")
print(f"  real 被 real     immediate-dominate: {real_idom_real}")
print(f"  real 自身 immediate-dominator (entry): {real_idom_self}")

# 输出 JSON 给后续用
out = {
    "n_blocks": len(blocks),
    "dispatch": sorted(hex(x) for x in dispatch_starts),
    "n_dispatch": len(dispatch),
    "n_real": len(real),
    "dispatch_pred_counts": {hex(b.start): n_preds(b) for b in dispatch},
    "dispatch_pairs_strict_dom": [[hex(a), hex(b)] for a, b in dispatch_pairs],
    "dispatch_subtree": {(hex(k) if k is not None else "ROOT"): [hex(x) for x in v]
                         for k, v in dispatch_tree.items()},
    "governance": {(hex(k) if k is not None else "ROOT"): [hex(x) for x in sorted(v)]
                   for k, v in governance.items()},
    "root_dispatch_candidates": [hex(x) for x in candidates],
    "exit_dispatch_pdom_candidates": [hex(x) for x in candidates_pd],
    "real_idom_dispatch": real_idom_dispatch,
    "real_idom_real": real_idom_real,
    "real_idom_self": real_idom_self,
}
with open("/Users/fallw1nd/Documents/claude_project/bn/.temp/dom_analysis.json", "w") as f:
    json.dump(out, f, indent=2)

result = {
    "blocks": len(blocks),
    "dispatch": len(dispatch_starts),
    "real": len(real),
    "dispatch_pairs": len(dispatch_pairs),
    "root_candidate": [hex(x) for x in candidates],
    "exit_candidate": [hex(x) for x in candidates_pd],
}
