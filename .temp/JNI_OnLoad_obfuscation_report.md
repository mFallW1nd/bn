# libtiny.so JNI_OnLoad 混淆原理分析报告

> 样本：`libtiny.so` (rednote 9.27.1, ARM64 ELF)
> 目标函数：`JNI_OnLoad @ 0x1a0b8c`，FDE 大小 3796 字节
> 已通过 `bn_deobf` 还原至 100% 覆盖（57 基本块、3796/3796 字节、40 轮收敛、3.1 s）

---

## 1. 一句话定位

> **这是一个把 OLLVM 风格控制流平坦化（CFG flattening）的"集中式 dispatcher" 拆散到每个基本块尾部、并用"累加器 + 立即数 = 下条 PC" 替代"switch(state) 查表"的改良版本。**

它从 OLLVM 的 fla pass 演化出来，但每一处经典 fla 的可侦测特征都被刻意抹去了。下面把它和经典平坦化逐项对比，再讲它最终为什么仍然是可静态完全还原的。

---

## 2. 与经典 CFG 平坦化的对照

### 2.1 OLLVM `-fla` 的标准结构

```text
entry:                     ┌──────────────────┐
    state = S0      ──────►│   dispatcher     │── switch(state) ──┐
                           │                  │                   │
                           └──────────────────┘                   │
                                  ▲                               ▼
                                  │                       ┌────────────────┐
                                  │                       │  real_block A  │
                                  │                       │  ... 工作 ...  │
                                  │                       │  state = SA'   │
                                  │   goto dispatcher ◄───┤  goto disp     │
                                  │                       └────────────────┘
                                  │                       ┌────────────────┐
                                  └─── goto dispatcher ◄──┤  real_block B  │
                                                          │ ...  state=SB' │
                                                          │  goto disp     │
                                                          └────────────────┘
```

特征不变量（也是它的"指纹"）：

| # | 经典 fla 的不变量 | 攻击者用什么打它 |
|---|---|---|
| F1 | **存在唯一 dispatcher 节点**（最大入度块） | 找入度最大的块 |
| F2 | dispatcher 用 `switch(state)` 路由 | 抓 `cmp/b.eq` 链 / jump table |
| F3 | state 是 **小整数**（0..N） | 整数追踪、值集合分析（VSA） |
| F4 | state-to-PC 表在 `.rodata` 或 `.text` | 静态读 jump table |
| F5 | 每个 real block 末尾 **回跳到 dispatcher** | dispatcher fan-in 极高 |

### 2.2 这个样本是怎么"逐条改良"的

| # | 经典 fla 的不变量 | 本样本的改写 | 改写的攻击面意图 |
|---|---|---|---|
| F1 | 唯一 dispatcher | **删掉 dispatcher 节点本身**：把 `switch(state)` 这一句下沉到**每个块的尾部**，每块结尾都是 `br xACC` | 没有 dispatcher 块；fan-in 分散；入度直方图正常（最大 6） |
| F2 | switch(state) | **改成"加法 + br"**：`xACC += δ_block; br xACC` | 没有 cmp / b.eq / jump table 这些指纹 |
| F3 | state ∈ {0..N} | **state ∈ 全 64-bit 地址空间**：state **本身就是未来的 PC**（再加一次 δ 就变成 br 目标） | VSA 看到一堆形如 `0x05011090` 的"伪指针"，没有"小整数"这个突破口 |
| F4 | jump table 在 `.rodata` | **改成 `.data` 一处 64-bit "key"**：函数入口 `ldr xACC, [.data slot]` 注入；后续算数全是 immediate | 没有 N 项的表；只有 6 个 8-byte slot（key bank），任何"找 jump table"的启发式失效 |
| F5 | 每块回跳 dispatcher | **每块 br 直接到下一个块**（无回跳） | CFG 长得像普通函数；没有"全集中"的 fan-in 异常 |

### 2.3 把改良版与经典版叠在一起看

```
经典 fla：           中央 dispatcher                改良版（本样本）：分布式 dispatcher

   real_A                                              real_A_tail:
    │                                                     xACC += δ_A
    ▼                                                     br xACC ─────►  ┐
   ┌───────┐                                                              │
   │ disp  │── switch ──► A/B/C/...                                       ▼
   │       │                                              real_B_head:
   └───────┘                                                  xACC = phi(...)  ◄── 多入射边的"merge"就是 dispatcher 当年承担的合流职责
    ▲       ▲                                              real_B_tail:
    │       │                                                  xACC += δ_B
   real_B  real_C                                              br xACC

  state ∈ {0,1,2,...}                                  xACC ∈ 64-bit (= 真实 PC 减去常数)
  switch 是查表                                          "switch" = `+= δ` 是即时算术
```

> 形象地说：改良版**把 dispatcher 这一个节点摊平进了 N 个块的最后两条指令里**。每个块的尾巴都是一个微型 dispatcher：
> ```
>     [每块结尾]
>     mov   xN, #imm_lo
>     movk  xN, #imm_hi, lsl #0x10
>     add   xACC, xACC, xN
>     br    xACC
> ```
> 这两条 mov+movk 就是"原 fla 中 dispatcher 的 switch case 标签"——只不过现在它**直接编码下一条 PC 的偏移**，不再是一个抽象 state id。

---

## 3. 用本样本的实测数字验证这个对照

### 3.1 拓扑层

```
basic blocks .................... 57
indirect jumps (br x*) .......... 54        ← 几乎每块都以 indirect 收尾，与改良版 F1 一致
direct branches (b /b.cc) .......  0        ← 没有 dispatcher → 经典 F2 失效
target-count histogram .......... {1: 39, 2: 8, 4: 1, 6: 6}
merge nodes (preds > 1) ......... 13        ← 这 13 个就是"分布式 dispatcher 的合流点"
predecessor histogram (merge) ... [2,3,3,3,4,4,4,4,5,5,5,6,6]    最大 6
block-size median ............... 68 字节   ≈ 17 条指令
```

**13 / 57 ≈ 23 % 的块是合流点**——它们就是经典 fla 的 dispatcher 被拆散后的"碎片"。每一个合流点上 SSA 形态会出现 `LLIL_REG_PHI`，phi 的 source 数就是该处 incoming 边数（直方图里的 2..6 就是这些 phi 的宽度）。

> 经典 fla：1 个块入度 = N
> 改良版：N 个块入度 ≤ 6，分布式承担同一职责。

### 3.2 数据流层（"state 就是未来 PC"）

入口块（精简）：

```asm
adrp  x12, 0x74a000
ldr   x11, [x12, #0xcd0]            ; ★ key = .data[0x74acd0] = 0x3be1814
mov   x13, #0xfffffffffffff8a8
movk  x13, #0xfc5b, lsl #0x10       ; δ = 0xfffffffffc5bf8a8 (= signed -0x3a40758)
add   x9,  x11, x13                  ; x9 = key + δ = 0x1a10bc
br    x9                             ; 第一跳 → 0x1a10bc  ✓
```

`.data` 中本函数用到的 6 个 key slot：

| slot | value |
|---|---|
| `0x74ac80` | `0x3ff7190` |
| `0x74acb0` | `0x363ebb8` |
| `0x74acb8` | `0x3be8f90` |
| `0x74acc0` | `0x3a1c0a4` |
| `0x74acc8` | `0x332179c` |
| `0x74acd0` | `0x3be1814` |

> 这就是经典 fla "jump table in .rodata" 的对位物——只不过表项数从 N 缩成 6，且每项是 64-bit key 而非 PC 本身。任何块的 br 目标都可以表达成：
>
> `target = key_chain_i + Σ δ_j`
>
> 其中 `i ∈ {0..5}` 选 key 链，`Σ δ` 是从入口到该 br 沿路的 mov+movk 立即数累加。

### 3.3 csel 怎么编码"原 if/switch"

经典 fla 在 dispatcher 之前用 `state = csel(cond, S_true, S_false)` 选择下一个 state。改良版做了同一件事，只是 csel 的两个 arm 是**两个不同的 δ 或两个不同的 key**：

- **加性形态**：`csel xACC, xACC_arm_true, xACC_arm_false, cond` → SSA 上 `x_phi = phi(arm_true, arm_false)`，phi 后再 `+= δ_block; br`。每个 arm 在前几个块累加出不同的总和，phi 把两个总和并起来；最后 br 落到两个不同的目标。这就是 8 个 2-target jump 的来源。
- **表形态**：`csel x_idx, idx_true, idx_false, cond` → ldr `[x22 + x_idx]` → 不同 key 加同一组小偏置 → 不同 target。

6-target jump 例（`0x1a10c8`，最具有"原 switch"色彩）：

```
    block 0x1a10bc 入口:
        x8 = phi( x8_v3,  x8_v58,  x8_v143,  x8_v244 )    ← 4 路 incoming, 但
                                                            x8_v58/v143/v244 自身是 phi
                                                            (2/2/3 路) → 总展开 8 个候选

    block 0x1a10bc 尾巴:
        x9   = 0xfffffffffc7000bc    (movn + movk)
        x8  += x9
        br x8

    展开后 8 个候选 + FDE 过滤 → 6 个目标:
        0x1a10cc, 0x1a1108, 0x1a114c, 0x1a1184, 0x1a11c4, 0x1a1214
```

这正是把 6-way switch 编进 dataflow 的样子。**经典 fla 的"switch case 6 个分支"被 phi 4 路 + 上游 phi 2/2/3 路的复合替代**——总信息量一致，只是分散到了多个块的合流点上。

### 3.4 "混淆器还顺手把状态值加密了一次"

注意上一例里 `x8_v3 = 0x1a114c + 0x038fff44 = 0x05011090` 这种**完全不像地址**的中间值。它的作用相当于经典 fla 中"state 用 XOR key 加密"的同质改良——只是这里的"加密"是直接利用 64-bit 加法和大负数 δ 在 mod 2^64 下相消：

```
   accumulator (运行中):  0x05011090   ← 在 .text/.data 任何地方都不存在的"伪指针"
                          0x3aa1010    ← 同样
                          ...
   br 之前最后一加:       + 0xfffffffffc7000bc   (= -0x38ffff44)
                         = 0x1a10cc 等真实 PC

   解密的代价：在 64-bit ALU 里走完一遍
```

这条把"state 加密"和"state-to-PC 翻译"**合并成单一加法操作**——经典 fla 还要 dispatcher 里查表，这里不用。所有"加密"和"翻译"都被静默地折叠进了同一条 `add xACC, xACC, xN`。

---

## 4. 攻击者视角：哪些经典反平坦化技术会失败

| 技术族 | 在经典 fla 上有效 | 在本改良版上失效的原因 |
|---|:---:|---|
| 找入度最高的块（dispatcher 检测） | ✅ | dispatcher 已被均匀拆到 13 个合流块；最大入度仅 6 |
| 抓 `cmp/b.eq` switch 模式 | ✅ | 没有 cmp/b.eq；switch 改成 `add+br` |
| 抽 jump table from `.rodata` | ✅ | 没 jump table；只有 `.data` 6×8B key slot |
| state 整数 VSA | ✅ | state 是 64-bit，"伪指针"分布稀疏，VSA 收敛性差 |
| 拷贝 dispatcher 块然后替换成直跳 | ✅ | 无 dispatcher 可拷贝；得对 54 个 br 都做替换 |
| symbolic execution 沿路径求解 cond | ⚠️部分 | 仍可，但路径数 ≈ ∏(merge 处 phi 宽度)，对 6-way 处会膨胀 |

> 改良版的设计哲学：**让 fla 的"形态指纹"分散到每个块里**，使一切建立在"找出 dispatcher → 移除 dispatcher"双步流程上的工具失效。

---

## 5. 我们的反混淆器为什么能 1:1 把它打回原形

虽然形态被掩盖，但**信息量没有变化**——所有经典 fla 的语义都被忠实翻译到了 SSA 上：

| 经典 fla 概念 | 在 SSA 上的对应 |
|---|---|
| dispatcher 的 `phi(state from real blocks)` | 合流块入口的 `LLIL_REG_PHI` |
| `switch(state)` 选择下一个 PC | 合流块尾部 `xACC += δ; br xACC` |
| state 加密 / 解密 | mov+movk 的 64-bit 立即数（纯算术） |
| jump table | `.data` 中的 6 × 64-bit key |
| `csel state` | 上游块尾巴写入 xACC 的 mov+movk +/或 ldr |

我们的求值器在 LLIL SSA 上做的事情就是"反向编译这五个概念"：

1. **`LLIL_REG_PHI` → 多值 union**：把 dispatcher 当年的 phi 还原成集合；
2. **`add / orr / movk / lsl` → 集合上的纯函数**：状态转换在集合上自动分配；
3. **`ldr [.data const]` → `bv.read()`**：jump table 静态读；
4. **`set ∩ FDE`**：把"加密-中-未解密"的伪指针过滤掉；
5. **多轮 `step()` 直到不动点**：每轮发现的新 br 暴露新块，下一轮新块上的 phi 再 union——经典 fla 的"反复展开 dispatcher"被"反复跑一轮 step"等价化。

完整代码不到 300 行（`.temp/deobfuscator.py`），也完全没有 csel 模板匹配。这说明：**改良版混淆把信息隐藏在了 SSA 的"形状"里，但只要你愿意在 SSA 上跑一个多值评估器，形状就会自己解开。**

---

## 6. 这个改良版的"理论上限"在哪里

要让我们这套方法失效，混淆器至少必须打破下面其中一条：

| 条件 | 当前状态 | 打破它的代价 |
|---|---|---|
| `.data` key 静态可读 | ✅ 可读 | 改成运行时 derive（如 `mprotect`+解密、anti-debug 后才设置）；但这要求**所有使用该 key 的 br** 都晚于解密点，意味着函数得先跑一段才能解出后段——和 JIT 自修改非常接近，引入的工程复杂度远超本混淆 |
| 寄存器算术全是纯函数 | ✅ add/orr/movk/ldr | 引入哈希、模乘、查表 with 不可静态推断 idx；但这又会被 SMT 求解 |
| FDE 边界过滤有效 | ✅ 真目标必落入函数 | 让"假目标"也落入 FDE，强迫求值器无法用范围裁剪 — 这样混淆器自己会陷入"哪些是真目标"的歧义 |
| SSA 上 phi 完全可枚举 | ✅ phi 宽度 ≤ 6 | 把 csel 链改成 N 极大的"虚拟分发"，让 phi 宽度爆炸；但这又会让代码体积爆炸 |
| 自递归靠 SSA 截断 | ✅ `_active` 集合 | 引入真递归（间接尾调本函数）— 但这破坏了"函数"概念本身 |

经典 fla 输给"找 dispatcher"。改良版输给"在 SSA 上跑多值评估"。**它所有节省的攻击面都用来对付前一代分析器，但碰上 SSA-aware 的分析器时，改良反而让 dataflow 表达更显式、更可机械化展开。**

---

## 7. 概念图（最终版）

```
                                     ┌────────────────────────────────────┐
                  .data[0x74ac80..d8] │   6 × 64-bit key (经典 fla 的       │
                                     │   jump-table 缩成 6 个 slot)        │
                                     └────────────────┬───────────────────┘
                                                      │ ldr （仅一次/每条 key 链）
                                                      ▼
                                             ┌────────────────┐
        分布式 dispatcher：                   │  xACC = key    │
        每个块尾巴 4 条指令充当 1 个微型      └────────┬───────┘
        switch case，把"下条 PC"直接                   │
        编进 mov+movk 立即数里                         │ 每个块都对 xACC 做一次:
                                                      │   xACC += δ_block
                                                      │   br xACC
                                                      ▼
        合流块入口 = 经典 fla 的 dispatcher phi:
                                            ┌────────────────────┐
                                            │ xACC = phi(...)    │  ◄── 13 个这样的合流点取代了 1 个 dispatcher
                                            │ xACC += δ_block    │
                                            │ br xACC            │
                                            └─────────┬──────────┘
                                                      │ 多值 SSA 评估展开:
                                                      │   {target_1, ..., target_k}
                                                      ▼
                                             ─────────┴─────────
                                             ↓                 ↓
                                         block_a           block_b ...
```

> 一句话总结这张图：**一切经典 CFG flattening 必须做的事都还在做，只是从"集中在一个 dispatcher 节点"散到了每块尾部 4 条指令里；从"switch 表"压缩成"key + 立即数"。**
> 这是 fla 朝静态分析隐蔽化方向的**形式上的进化**，但因为改良没有触碰它**计算上**的纯函数本质，SSA 多值评估器就能把进化反推回去。
