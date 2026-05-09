# JNI_OnLoad 支配关系分析：从 dispatcher 角度看混淆的"骨架"

> 数据来源: `.temp/dom_analysis.json` (BN 直接给出的 dominator/post-dominator 关系)
> 函数: `JNI_OnLoad @ 0x1a0b8c`，57 块 / 13 分发块 / 44 真实块
> 分发块定义: preds > 1 (即开头有 `LLIL_REG_PHI` 的块)
> 真实块定义: preds ≤ 1

---

## 1. 一句话结论

> **分发器没有被删除——它被分解成了一个 SESE (single-entry single-exit) 区域：**
> - **入口分发块 `0x1a10bc` 严格支配 (strictly-dominate) 所有其他 12 个分发块、以及全部 44 个真实块；**
> - **出口分发块 `0x1a1460` 严格后支配 (strictly post-dominate) 所有其他 12 个分发块及全部真实块；**
> - **中间 11 个分发块全是 `0x1a10bc` 的 immediate-dom 孩子**（除唯一一对嵌套 `0x1a0c24 → 0x1a1800`）；
> - 真实块 40 / 44 个直接挂在某个分发块下面，剩下 3 个挂在另一个真实块下面，1 个是 entry。
>
> 这意味着改良版**只把经典 fla 那一个 dispatcher 块「水平 fan-out 拆成了 11 个区域分发器」**，但 SESE 区域的"必经入口 + 必经出口"这一最强的支配性质被完整保留。

---

## 2. 实测数字

```
total blocks                                         57
dispatch (preds > 1)                                 13
real (preds ≤ 1)                                     44

dispatch-pairs where A strictly dominates B          13   ← 几乎全是"根支配子"形态
top-level dispatch (no other dispatch dominates)      1   = 0x1a10bc      ← 入口分发
dispatch that strictly post-dominates ALL others      1   = 0x1a1460      ← 出口分发
(post-dominator pairs across all dispatches)         17

real blocks immediate-dominated by a dispatch        40
real blocks immediate-dominated by a real             3
real blocks at entry (no dom ancestor)                1   = 0x1a0b8c
```

> 13 对严格支配关系 = 12 (root → 各子分发) + 1 (`0x1a0c24` → `0x1a1800`，唯一的二级嵌套)。除此以外，**11 个分发块互为兄弟、不互相支配**。

---

## 3. dispatcher 支配树

```
ROOT (function entry, 0x1a0b8c)
 │
 └─ 0x1a10bc                   ★ 入口分发器 (4 preds, 直接管 6 个 real)
    ├─ 0x1a0c24                (4 preds, 管 7 real)
    │   └─ 0x1a1800            (2 preds, 0 real)        ← 唯一的"二级"分发
    ├─ 0x1a0e30                (3 preds, 0 real)        ← "纯转发"分发
    ├─ 0x1a0e50                (3 preds, 管 6 real)
    ├─ 0x1a109c                (4 preds, 0 real)
    ├─ 0x1a1258                (3 preds, 0 real)
    ├─ 0x1a127c                (6 preds, 管 6 real)
    ├─ 0x1a1440                (5 preds, 0 real)
    ├─ 0x1a1460                (5 preds, 管 8 real)     ★ 同时是出口分发器 (post-dom-all)
    ├─ 0x1a1644                (6 preds, 管 4 real)
    ├─ 0x1a1860                (5 preds, 管 6 real)
    └─ 0x1a18d4                (4 preds, 0 real)
```

`★` 是结构性的极点：

- `0x1a10bc` = 整个 SESE 区域的 **唯一 entry**
- `0x1a1460` = 整个 SESE 区域的 **唯一 exit**

它们一头一尾合起来等价于经典 fla 的"那一个" dispatcher，只不过把 entry 与 exit 分到了两个块。

---

## 4. 分发块之间的关系（4 类）

### 4.1 根分发 vs 子分发：**严格 1:N 支配**

| 关系 | 数量 | 说明 |
|---|---|---|
| `0x1a10bc` 严格支配 X | 12 | X 是其他 12 个分发块的全部 |
| `0x1a1460` 严格 post-dominate X | 12 | X 是其他 12 个分发块的全部 |

> 这两条等价于经典 fla 的"必经 dispatcher"：每条路径从 `0x1a10bc` 进入区域，必经过 `0x1a1460` 离开。

### 4.2 子分发互相之间：**绝大多数兄弟，仅 1 对嵌套**

| 关系 | 数量 |
|---|---|
| 子分发 A 严格支配子分发 B | 1   ( `0x1a0c24` → `0x1a1800` ) |
| 子分发 A 与 B 互不支配（即兄弟） | C(11,2) − 1 = 54 |

12 个子分发中**只有 1 对**形成 dom 关系（`0x1a0c24` 是 `0x1a1800` 的祖先）。其余 11 对互为 dom 兄弟。这意味着：

- 任意两条路径从入口分发出发，**最早一定要在 11 个子分发中"挑一个"**——这个"挑选动作"就是经典 fla 中"读 state 然后 switch"那一刀，被分散到了入口分发的 br 上（它本身就 fan-out ≥ 6）。

### 4.3 子分发的"管辖深度"：**几乎全是 depth-1**

```
dom-chain depth (沿支配链经过多少个 dispatch):
  0x1a10bc:  0     ← 根
  其余 11 个: 1     ← 直接挂在 0x1a10bc 下面
  0x1a1800:  2     ← 唯一的二级 (在 0x1a0c24 下面)
```

**整棵分发器树的高度只有 2** (root + leaves) 加上一个例外。这是一棵**几乎纯扁平的星图 (star graph)**，不是分层 dispatcher。

### 4.4 "纯转发分发"：6 个分发块管 0 个真实块

| 分发块 | preds | 直接管的真实块 |
|---|---|---|
| `0x1a0e30` | 3 | 0 |
| `0x1a109c` | 4 | 0 |
| `0x1a1258` | 3 | 0 |
| `0x1a1440` | 5 | 0 |
| `0x1a1800` | 2 | 0 |
| `0x1a18d4` | 4 | 0 |

这 6 个分发块**只 merge 上游再转向其他分发**，自身不直接拥有任何 real 子节点。它们是经典 fla 中"中间 stage" 的角色——把多条路径合并成一束，再 br 回某个真正分配 real 工作的分发块（例如 `0x1a0e50`、`0x1a127c`、`0x1a1644` 等）。

> 这 6 个块给"分发器二次平摊"提供了原料：**与其让某个 dispatch 块入度爆到 12，不如建几个 3-入度的小 merge 节点先合一合**。这正是为了把 fan-in 散布开来。

---

## 5. 分发块与真实块的关系

### 5.1 直辖关系

```
real → 分发 immediate-dominator   40 / 44       (≈ 91%)
real → real    immediate-dominator  3 / 44       (≈ 7%)
real → 自身    (entry block)        1 / 44       (≈ 2%)
```

> 真实块**绝大多数**直接挂在一个分发块下，构成一个一级的 dom 子树:
>
>     dispatch_X
>      ├─ real_a
>      ├─ real_b
>      ├─ real_c
>      └─ ...
>
> 这复刻了经典 fla 的"dispatcher → real_block"直跳关系——**不绕道**。

### 5.2 为什么有 3 个 real → real 的链

这 3 处 real-immediately-dominate-real 的情况说明：**有少量真实块没有立刻 br 回分发，而是顺序通过另一个真实块再到分发**。这是一种把 real block 拼成 2 块的局部逃避"每块 ≤ 24 字节"的限制的写法（看上去更像普通函数）。

> 量的上界很小（44 中的 3），所以并没有破坏 dispatcher 模型的整洁性；它只是给"分布式 dispatcher"加了一点点边角的干扰。

### 5.3 每个分发块"管辖区域"大小

```
0x1a10bc (entry)      6
0x1a0c24             7
0x1a0e50             6
0x1a127c             6
0x1a1460             8     ← 区域最大
0x1a1644             4
0x1a1860             6
其余 6 个 (转发型)   0
```

> **总和 = 43**（再加 1 个 entry real block = 44）。
> 划分均匀：除 `0x1a1460` 略多 (8)，其它非空区域都在 4–7 之间。这种平均化让攻击者无法用"最大区域块"反向定位 dispatcher——经典 fla 的"找 dispatcher = 找最大区域所有人都来"在这里直接失效。

---

## 6. SESE 区域结构（关键的"不变骨架"）

把 `0x1a10bc` 和 `0x1a1460` 当成区域两端，得到的形状：

```
   函数入口  0x1a0b8c   (1 个 real block, 不在 SESE 内)
                │
                ▼
        ┌───────────────┐
        │  0x1a10bc     │   ★ entry-dispatch  (dom-all)
        └───┬─────────┬─┘
            │         │
            ▼         ▼   ── 11 个 sub-dispatch + 它们各自的 real subtree ──
        ... 11 路 fan-out, 每路一片小 region ...
            │         │
            ▼         ▼
        ┌───────────────┐
        │  0x1a1460     │   ★ exit-dispatch  (pdom-all)
        └───────┬───────┘
                │
                ▼
            ret / tail-call
```

这是一个**严格 SESE region**：
- 有且仅有一条 incoming 边（来自 entry real block）
- 有且仅有一条 outgoing 边（去往 ret 路径）
- 内部 11 个分发块、44 个真实块，构成完整的混淆"内核"

> 经典 fla 的 dispatcher 是 SESE 的一种退化形式（entry==exit，区域大小=1）。本样本把这个"自反"的 dispatcher 拉伸成了**两端，中间塞 11 个区域分发器**——SESE 性质被刻意保留下来。

---

## 7. 这个支配结构对反混淆器意味着什么

| 经典 fla 反制思路 | 在本样本上是否还工作？ |
|---|---|
| "找入度最大的块当 dispatcher" | ❌ 入度均匀，最大仅 6 |
| "找 SESE 区域，把 region 的 dispatcher 抽出" | ✅ **完全可用**：用 dom + post-dom 求 SESE region(0x1a10bc, 0x1a1460)；区域内部就是混淆核心 |
| "看 dispatcher 是否同时 dominate & post-dominate region" | ⚠️ 这里 dispatcher 被拆成两端，单一块不再既支配又后支配 |
| "把 dispatcher 替换成直跳" | ⚠️ 需要替换两端 + 11 个子分发的 br 重定向，而不是 1 处 |
| "用支配树找区域分发器" | ✅ **本质工具**：12 个子分发 = `0x1a10bc` 的 idom-children，13 个区域 = 子分发树的子树 |

> 换一种说法：**改良版只破坏了"dispatcher 是单点"这一假设；它没有破坏支配树的可计算性。** 任何基于 dom-tree 的反混淆思路都能经过适配后照常工作——SESE 区域的入口和出口在 dom/post-dom 上**唯一确定**，攻击者只需把"dispatcher" 概念升级为"SESE region 的两端"即可。

---

## 8. 对照：我们这个反混淆器为什么没有显式用支配关系？

我们的 `_Eval` 是一个**纯 SSA 多值传播**的求值器，从 br 处反向走 `LLIL_REG_PHI / SET_REG / LOAD / ADD ...`，没有显式构造 dom-tree。但事实上，SSA 的 phi 已经**等价编码了支配关系**：

- 一个块开头有 `LLIL_REG_PHI` 当且仅当它是**支配前沿** (dominance frontier) 的合流点；
- phi 的每个 source 对应**支配该块的唯一前驱路径**上最后一次写该寄存器；
- 我们沿 phi 反向求值，等价于沿支配树反向走。

所以我们 "没有用 dom-tree" 只是表象——SSA 已经替我们做完了 dom-tree 计算。这也解释了为什么求值器虽然只 ~300 行却能 1:1 还原：**SSA 是"支配关系的编程接口"，phi 展开就是支配树展开**。

---

## 9. 与经典 fla 的支配等价表

| 元素 | 经典 fla | 本样本（改良版） |
|---|---|---|
| dispatcher 节点 | 1 (既 dominate-all 又 pdom-all) | 拆成 2 端：`0x1a10bc` (dom-all) + `0x1a1460` (pdom-all) |
| state phi | dispatcher 入口的 1 个 phi | 13 个分发块入口各自的 phi |
| switch | dispatcher 内的 cmp/b.eq 链 | 13 个分发块尾部的 `xACC += δ; br xACC` |
| state-to-PC 表 | dispatcher 拥有的 1 个 jump table | `.data` 中 6 个 64-bit key + 每块的 mov+movk 立即数 |
| 真实块挂载 | 全部 immediate-dominate by dispatcher | 40 / 44 immediate-dominate by 13 个分发之一 |
| dispatcher 入度 | = 真实块数 N (≈ 44) | 最大 6, 平均 ≈ 4.0 |
| SESE 区域属性 | dispatcher 自反 SESE | 真正二端 SESE，11 个内部子区域 |

> 经典 fla → 改良版的"形变"在 dom-tree 上是一种**可逆映射**：
>
>     classical: 1×{dom=pdom} dispatcher → 1×N real blocks
>     improved:  2 endpoints + 11 mid-dispatchers → 11 子区域 → 44 real blocks
>
> 信息量、SESE 结构、支配关系都没有变，**只是 fan-out / fan-in 的"重心"被分摊开来**。
