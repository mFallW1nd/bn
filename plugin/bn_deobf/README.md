# bn_deobf

Per-function indirect-branch deobfuscator for Binary Ninja, designed around a
**hot-reloadable core** so you can iterate on the analysis logic without
restarting BN.

Targets the libtiny.so style of obfuscation: chained indirect jumps through
`.data` dispatch tables, csel-driven control flow flattening. The driver is a
multi-value SSA evaluator over LLIL; it commits resolved targets via
`Function.set_user_indirect_branches`.

## Architecture

Two layers:

```
┌──────────────────────────────────────────────────────┐
│ __init__.py                                  LOCKED  │  ← edit this → restart BN
│   • registers Workflow + 3 PluginCommands            │
│   • _action() and _cmd_*() are persistent callbacks  │
│   • _reload_all() reloads everything below before    │
│     calling into business logic                      │
└──────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────┐
│ core.py        state.py    eh_frame.py    deobf.py   │  ← hot-reloadable
│ (action body)  (toggle +    (DWARF FDE     (SSA      │     edit → save →
│                FDE cache)    decoder)       evaluator)│     right-click → see effect
└──────────────────────────────────────────────────────┘
```

`__init__.py` runs **once** at BN startup. The Activity action and PluginCommand
callbacks it registers all call `_reload_all()` first, then dispatch into the
business modules. So every right-click triggers `importlib.reload` of the
business layer before doing real work — your last save always runs.

`deobfuscator.py` is a symlink to `../../.temp/deobfuscator.py`, shared with
the standalone `bn py exec` driver (so improvements made in either context
flow to both).

## Installation

```bash
ln -s "$PWD/plugin/bn_deobf" "$HOME/Library/Application Support/Binary Ninja/plugins/bn_deobf"
# Restart Binary Ninja once.
```

Then open a binary that has `.eh_frame`. The plugin registers a
function-level Activity (`analysis.plugins.bn_deobf`) inserted before
`core.function.generateHighLevelIL`, and three right-click commands.

## PluginCommands

| Command | When to use |
|---|---|
| **Deobfuscator: run once (no Workflow)** | Daily iteration. Bypasses the Activity, calls `deobfuscator.run()` to fixpoint outside the analysis pipeline, wraps in a single undoable transaction. Reload-aware. |
| **Deobfuscator: toggle on this function** | Test the Workflow path. Calls `WorkflowMachine.override_set` to flip the per-function override, then `fn.reanalyze()`. Each reanalyze fires the Activity and runs ONE pass; repeat to converge. Session-only (lost on BN restart). |
| **Deobfuscator: clear FDE cache** | If you edit the binary or want to force re-parsing of `.eh_frame`. |

## Iterative develop loop (no BN restart)

```
1. Edit .temp/deobfuscator.py or plugin/bn_deobf/{core,state,eh_frame}.py
2. Save
3. In BN: right-click target function → "Deobfuscator: run once (no Workflow)"
4. Inspect console output and HLIL
5. Goto 1
```

Each right-click runs `_reload_all()` first:

```python
def _reload_all():
    importlib.reload(eh_frame)
    importlib.reload(state)             # imports eh_frame
    importlib.reload(core.deobfuscator)
    importlib.reload(core)              # imports deobfuscator + state
```

Order is dependency-bottom-up so each upper module rebinds its `from . import`
references to the freshly-reloaded lower modules.

## What hot-reloads vs what needs a restart

| Edit | Hot-reload? |
|---|---|
| `.temp/deobfuscator.py` body — `step` / `run` / `_Eval` / `_BIN` / `_UNARY` | ✅ |
| `core.py` — `run_for_function` / `run_oneshot` | ✅ |
| `state.py` — `fde_for` / `is_enabled` / `toggle_and_reanalyze` / cache logic | ✅ |
| `eh_frame.py` — DWARF decoder, encoding handlers | ✅ |
| `__init__.py` — `_CONFIG` (activity name, `auto.default`) | ❌ restart |
| `__init__.py` — `wf.insert(...)` position / Workflow shape | ❌ restart |
| `__init__.py` — `_action` / `_cmd_*` / `_reload_all` function bodies | ❌ restart |
| `__init__.py` — adding / removing a `PluginCommand` | ❌ restart |
| `plugin.json` | ❌ restart |

The line is: anything BN holds a Python object reference to (function callbacks,
workflow definitions) is locked at registration time. The function bodies of
those callbacks just need to call into reloadable modules.

## Per-function targeting

Activity is registered with `eligibility: {auto: {default: false}}`. By default
it does NOT run on any function. To enable it on one function:

```python
# Programmatic:
from binaryninja.workflow import WorkflowMachine
WorkflowMachine(fn.handle).override_set("analysis.plugins.bn_deobf", True)
fn.reanalyze()

# Or right-click → "Deobfuscator: toggle on this function".
```

`override_set` is **session-only** — toggle state is lost on BN restart. If you
want persistence across sessions, the cleanest approach is to scan
`bv.query_metadata` at plugin load and replay overrides; not implemented today.

## Files

| File | Lines | Role |
|---|---|---|
| `__init__.py` | ~88 | Workflow shell + PluginCommand registrations. Locked. |
| `core.py` | ~50 | Activity action body + oneshot driver. Hot-reloadable. |
| `state.py` | ~95 | Per-function override toggle + FDE range cache. Hot-reloadable. |
| `eh_frame.py` | ~225 | Self-contained DWARF FDE decoder. Hot-reloadable. |
| `deobfuscator.py` | symlink | → `../../.temp/deobfuscator.py`. Shared with the CLI driver. |
| `plugin.json` | 11 | BN plugin metadata. |

## Verification

After install + first restart, with `libtiny.so` open:

1. **One-shot** — right-click `JNI_OnLoad` (`0x1a0b8c`) → **Deobfuscator: run once (no Workflow)**. Console:
   ```
   [bn_deobf] oneshot JNI_OnLoad @ 0x1a0b8c: 100.0% (57 blocks, 3796/3796 bytes), 1 rounds
   ```

2. **Workflow path** — `bv.undo()` to revert. Right-click → **Deobfuscator: toggle on this function**. Function reanalyzes, console shows `[bn_deobf] step JNI_OnLoad ... new=N pruned=M`. Repeat reanalyze (Python: `fn.reanalyze(); bv.update_analysis_and_wait()`) until size stabilizes.

3. **Hot-reload** — add `print("V2")` to `step()` in `.temp/deobfuscator.py`, save. Right-click → "run once". `V2` appears with no BN restart.

4. **Negative** — right-click a function with no override (e.g. `_start`) and reanalyze. No `[bn_deobf]` console output: confirms `auto.default: false` correctly gates dispatch without a custom eligibility callback.

## Workflow path semantics

The Activity fires **once per function reanalysis** and runs ONE `step()` pass
(not a fixpoint). To converge through the Workflow, reanalyze repeatedly. To
converge in one shot, use **run once (no Workflow)** instead — it calls
`deobfuscator.run()` outside the pipeline and iterates to fixpoint.

Inside the Activity, `step()` is called with `wait=False` to avoid recursing
into `bv.update_analysis_and_wait()` (which would deadlock the running pipeline).
The `wait` kwarg was added to `deobfuscator.step()` for exactly this reason;
the CLI driver path keeps `wait=True` (the default) and works as before.

## Known limits

- Workflow registration is one-shot per BN session. There is no
  `Workflow.unregister`, so the workflow shape (insert position, activity
  name, JSON config) cannot be changed without a restart. The hot-reload
  story is for the **action body** only.
- `WorkflowMachine.override_set` does not persist across BN restarts. Toggle
  per-function before each session, or replay from a stored list at plugin
  load (not implemented).
- `eh_frame.py` parses ARM64 ELF `.eh_frame` (pcrel sdata4 + a few related
  encodings). Other encodings are silently skipped; `state.fde_for` falls
  back to BN's own function bounds in that case.
- The Activity inserts before `core.function.generateHighLevelIL`. If your
  workflow path needs a different insertion point, edit `__init__.py` and
  restart BN.
