"""BN Deobfuscator plugin shell — locked at session start.

Edit `core.py`, `deobfuscator.py`, `state.py`, or `eh_frame.py` to iterate;
those reload on every Activity firing. Edits to THIS file or to the Workflow
shape (the JSON config / insert position / eligibility) require a Binary
Ninja restart.

Per-function targeting is delegated to BN itself: the activity is registered
with `auto.default: False`, so it stays inert by default. Right-click
"toggle" calls `WorkflowMachine.override_set(activity, True)` to enable it
on a single function. No custom eligibility callback, no metadata bookkeeping.
"""

from __future__ import annotations

import importlib
import json

from binaryninja import PluginCommand
from binaryninja.workflow import Activity, Workflow

from . import core, eh_frame, state


_CONFIG = json.dumps({
    "name": state.ACTIVITY_NAME,
    "title": "BN Deobfuscator",
    "description": "Resolve indirect branches via SSA multi-value evaluator. "
                   "Disabled by default; enable per-function with the "
                   "'Deobfuscator: toggle on this function' command.",
    "eligibility": {"auto": {"default": False}},
})


def _reload_all():
    """Reload every dev-loop module, in dependency order, so any code edit
    takes effect on the next Activity firing or PluginCommand invocation
    without restarting Binary Ninja."""
    importlib.reload(eh_frame)
    importlib.reload(state)         # imports eh_frame
    importlib.reload(core.deobfuscator)
    importlib.reload(core)          # imports deobfuscator + state


def _action(ctx):
    _reload_all()
    core.run_for_function(ctx)


def _register_workflow():
    try:
        wf = Workflow("core.function.metaAnalysis").clone()
        wf.register_activity(Activity(configuration=_CONFIG, action=_action))
        wf.insert("core.function.generateHighLevelIL", [state.ACTIVITY_NAME])
        wf.register()
    except Exception as exc:
        print(f"[bn_deobf] workflow registration skipped: {exc}")


def _cmd_toggle(bv, fn):
    _reload_all()
    state.toggle_and_reanalyze(bv, fn)


def _cmd_oneshot(bv, fn):
    _reload_all()
    core.run_oneshot(bv, fn)


def _cmd_clear_cache(bv, _fn):
    _reload_all()
    state.invalidate_cache(bv)
    print("[bn_deobf] FDE cache cleared")


_register_workflow()

PluginCommand.register_for_function(
    "Deobfuscator: toggle on this function",
    "Flip the per-function override on/off via WorkflowMachine.override_set, "
    "then reanalyze. The Activity runs one pass per reanalyze.",
    _cmd_toggle,
)
PluginCommand.register_for_function(
    "Deobfuscator: run once (no Workflow)",
    "Bypass the Workflow and iterate deobfuscator.run() to fixpoint outside "
    "the analysis pipeline. Wrapped in a single undoable transaction.",
    _cmd_oneshot,
)
PluginCommand.register_for_function(
    "Deobfuscator: clear FDE cache",
    "Drop cached .eh_frame FDE ranges for this BV (re-parse on next access).",
    _cmd_clear_cache,
)
