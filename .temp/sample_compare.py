"""Stratified sampling: compare old fixed defaults vs adaptive defaults.

Writes progress incrementally to /tmp/sample_compare.log so we can tail it
even though `bn py exec` only flushes stdout at script end.
"""

import json
import random
import sys
import time

LOG = "/tmp/sample_compare.log"

def log(msg):
    with open(LOG, "a") as f:
        f.write(msg + "\n")

# truncate
open(LOG, "w").close()

sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/.temp")
sys.path.insert(0, "/Users/fallw1nd/Documents/claude_project/bn/plugin/bn_deobf")

import importlib
import deobfuscator
import eh_frame as ef

importlib.reload(deobfuscator)
importlib.reload(ef)

ranges = ef.parse_eh_frame(bv)  # noqa: F821
log(f"FDE ranges: {len(ranges)}")

BUCKETS = [
    ("XS_<=1k",     0,        1024),
    ("S_1k-8k",     1024,     8192),
    ("M_8k-32k",    8192,     32768),
    ("L_32k-128k",  32768,    131072),
    ("XL_128k+",    131072,   1 << 30),
]

per_bucket = {name: [] for name, *_ in BUCKETS}
for s, e in ranges:
    sz = e - s
    for name, lo, hi in BUCKETS:
        if lo <= sz < hi:
            per_bucket[name].append((s, e, sz))
            break

random.seed(42)
SAMPLES_PER_BUCKET = {"XS_<=1k": 20, "S_1k-8k": 20, "M_8k-32k": 15, "L_32k-128k": 8, "XL_128k+": 4}

sample = []
for name, lo, hi in BUCKETS:
    pool = per_bucket[name]
    n = min(len(pool), SAMPLES_PER_BUCKET[name])
    if n:
        sample.extend(((name, *t) for t in random.sample(pool, n)))
    log(f"  {name}: pool={len(pool)} sampled={n}")
log(f"Total sample: {len(sample)}")

def clear(fn):
    for blk in fn.low_level_il:
        for il in blk:
            if il.operation.name in ("LLIL_JUMP", "LLIL_JUMP_TO"):
                try:
                    fn.set_user_indirect_branches(il.address, [])
                except Exception:
                    pass

def measure(fn, fde, *, fixed: bool):
    clear(fn)
    bv.update_analysis_and_wait()  # noqa: F821
    t0 = time.time()
    if fixed:
        rep = deobfuscator.run(fn, fde, max_set=32, max_depth=32, max_rounds=30)
    else:
        rep = deobfuscator.run(fn, fde)
    dt = time.time() - t0
    a = rep["audit"]
    return a["coverage_pct"], len(rep["history"]), dt, a["covered_bytes"], a["fde_size"]

# Ensure functions exist
for _, s, _e, _sz in sample:
    if not bv.get_function_at(s):  # noqa: F821
        bv.add_function(s)  # noqa: F821
bv.update_analysis_and_wait()  # noqa: F821

results = []
for i, (bucket, s, e, sz) in enumerate(sample):
    fn = bv.get_function_at(s)  # noqa: F821
    if fn is None:
        log(f"  [{i+1}] no function at {hex(s)} skip")
        continue
    cov_fix, r_fix, t_fix, cb_fix, fdesz = measure(fn, (s, e), fixed=True)
    cov_ad, r_ad, t_ad, cb_ad, _ = measure(fn, (s, e), fixed=False)
    row = {
        "bucket": bucket, "addr": hex(s), "size": sz,
        "fixed":    {"cov": cov_fix, "rounds": r_fix, "secs": round(t_fix,2), "covered": cb_fix},
        "adaptive": {"cov": cov_ad,  "rounds": r_ad,  "secs": round(t_ad,2),  "covered": cb_ad},
    }
    results.append(row)
    log(f"  [{i+1}/{len(sample)}] {bucket} {hex(s)} sz={sz} "
        f"fix={cov_fix:.1f}% {r_fix}r {t_fix:.1f}s "
        f"adp={cov_ad:.1f}% {r_ad}r {t_ad:.1f}s "
        f"Δ={cov_ad-cov_fix:+.2f}")

log("\n=== AGGREGATE ===")
agg = {}
for name, *_ in BUCKETS:
    rows = [r for r in results if r["bucket"] == name]
    if not rows:
        continue
    avg_fix = sum(r["fixed"]["cov"] for r in rows) / len(rows)
    avg_ad  = sum(r["adaptive"]["cov"] for r in rows) / len(rows)
    bytes_fix = sum(r["fixed"]["covered"] for r in rows)
    bytes_ad  = sum(r["adaptive"]["covered"] for r in rows)
    bytes_total = sum(r["size"] for r in rows)
    t_fix = sum(r["fixed"]["secs"] for r in rows)
    t_ad  = sum(r["adaptive"]["secs"] for r in rows)
    agg[name] = {
        "n": len(rows),
        "fixed_avg_cov": round(avg_fix, 2),
        "adaptive_avg_cov": round(avg_ad, 2),
        "delta": round(avg_ad - avg_fix, 2),
        "fixed_bytes_pct": round(bytes_fix/bytes_total*100, 2),
        "adaptive_bytes_pct": round(bytes_ad/bytes_total*100, 2),
        "fixed_total_secs": round(t_fix, 1),
        "adaptive_total_secs": round(t_ad, 1),
    }
    log(f"  {name:14s} n={len(rows):3d}  fix_avg={avg_fix:6.2f}%  adp_avg={avg_ad:6.2f}%  Δ={avg_ad-avg_fix:+6.2f}  "
        f"fix_bytes={bytes_fix/bytes_total*100:6.2f}%  adp_bytes={bytes_ad/bytes_total*100:6.2f}%  "
        f"time fix={t_fix:.0f}s ad={t_ad:.0f}s")

with open("/Users/fallw1nd/Documents/claude_project/bn/.temp/sample_compare_results.json", "w") as f:
    json.dump({"buckets": agg, "rows": results}, f, indent=2)

result = agg
