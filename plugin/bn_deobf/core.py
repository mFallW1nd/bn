"""Activity action body + one-shot driver. Hot-reloadable.

`__init__.py` `importlib.reload`s this module before each Activity firing,
so edits here (and in `deobfuscator.py`) take effect on the next reanalyze
without restarting Binary Ninja.
"""

from __future__ import annotations

from . import deobfuscator, state


def run_for_function(ctx) -> None:
    """Activity action: ONE pass per pipeline firing.

    Inside an Activity we cannot call `bv.update_analysis_and_wait()` — the
    pipeline is already running. `wait=False` skips that call; the pipeline
    will pick up the new user_indirect_branches as it finishes the current
    analysis stage.

    To converge to fixpoint via this path, the user reanalyzes the function
    multiple times (each reanalyze re-fires this Activity).
    """
    func = ctx.function
    if func is None:
        return
    fde = state.fde_for(ctx.view, func.start)
    result = deobfuscator.step(func, fde, undoable=False, wait=False)
    print(f"[bn_deobf] step {func.name} @ {hex(func.start)} "
          f"new={result['new_edges']} pruned={result['pruned']}")


def run_oneshot(bv, func) -> dict:
    """Right-click "run once" handler: bypass the Workflow, iterate to fixpoint.

    Outside the analysis pipeline, so it's safe to call `update_analysis_and_wait`
    inside `step()` (default `wait=True`). Wrapped in a single undoable_transaction
    so Cmd-Z reverts the whole sweep.
    """
    if func is None:
        return {}
    fde = state.fde_for(bv, func.start)
    report = deobfuscator.run(func, fde)
    audit = report["audit"]
    print(f"[bn_deobf] oneshot {func.name} @ {hex(func.start)}: "
          f"{audit['coverage_pct']}% ({audit['blocks']} blocks, "
          f"{audit['covered_bytes']}/{audit['fde_size']} bytes), "
          f"{len(report['history'])} rounds")
    return report
