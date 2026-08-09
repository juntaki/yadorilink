# DST Agent Runbook

Normative runbook for an agent (or human) acting on a DST failure. It is the
warm-start context: read this, not the harness source. It is kept honest by
`tests/dst_runbook_freshness_lint.rs`, which fails if a lane alias or `xtask`
flag documented here no longer exists (or vice-versa).

> Status: integrated. The real
> triage verdict (`dst_support::triage::TriageVerdict`), the signature memory,
> and the failure-branch pipeline that emits a bundle, runs the shrinker, scans
> the corpus, and records the signature all exist and are unit-tested — the
> single entry point is `dst_support::diagnostics::record_failure`. Two seams
> stay caller-fed by design: the first-divergence observer needs a per-event-
> boundary replay hook the scenarios do not expose yet (so `first_divergence`
> is supplied when available, else localizes to `none`), and `record_failure`
> is adopted per scenario as each scenario's failure branch is migrated to call
> it (the pipeline is proven end-to-end in `diagnostics::tests`).

## 1. When a DST failure lands: read one bundle

Every violation produces one self-contained JSON bundle under
`target/dst-failures/<signature>-<seed>.json`, hard-capped at ~64 KiB so one
`Read` gives you everything. You should not need to open scenario source or full
logs to start.

Bundle shape (a `"form": "full"` bundle, elided):

```json
{
  "schema_version": 1,
  "form": "full",
  "scenario": "dst_two_device_chaos",
  "seed": 43981,
  "signature": "Convergence|X/dst-N.bin@Convergence",
  "case": { "seed": 43981, "topology": {...}, "workload": [...], "content_table": {...} },
  "case_min": { "...": "the shrunk minimal case, when shrinking ran" },
  "violations": [
    { "kind": "Convergence", "path": "g/dst-02.bin", "devices": [0, 1],
      "detail": "devices disagree on g/dst-02.bin",
      "triage": "LikelyProductBug" }
  ],
  "first_divergence": { "sim_time_nanos": 512000, "event_index": 87, "oracle_kind": "Convergence" },
  "timeline": [ { "event_index": 80, "sim_time_nanos": 470000, "device": 0, "summary": "..." } ],
  "path_states": [
    { "path": "g/dst-02.bin",
      "per_device": [ { "device": 0, "index_row": {...}, "content_hash": "…" },
                      { "device": 1, "index_row": null, "content_hash": null } ] }
  ],
  "truncated": null,
  "full_log_pointer": null
}
```

Read it in this order: `violations[].triage` (is it a product bug or a
harness artifact?), `signature` (have we seen it — see §4), `first_divergence`
(where to look), the `timeline` slice around that point, then `path_states` for
who-has-what. A `LikelyHarnessArtifact` verdict is emitted as a **slim** bundle
(`"form": "slim"`, verdict + knob only) — don't spend attention on it unless the
knob surprises you.

If `truncated` is non-null, the timeline slice was capped; `full_log_pointer`
names the full on-disk log as the escape hatch.

## 2. Reproduce with one command

No env-var archaeology — the `xtask` sets `RUSTFLAGS="--cfg madsim"`, the seed,
and the scenario internally:

```
cargo dst-replay target/dst-failures/<signature>-<seed>.json
```

Flags:
- `--trace <path>` — filter event tracing to matching paths. Only
  `dst_two_device_chaos` reads the underlying selector today; for every
  other scenario this is currently a no-op.
- `--scenario <name>` — override the scenario (needed only for a corpus entry
  that predates the `scenario` field).
- `--until-divergence` and `--profile relaxed` are not implemented — no
  scenario reads the env var either would need — and `dst-replay` refuses
  to run rather than silently accept and ignore them.

`dst-replay` needs a scenario-specific single-seed entry point to reproduce
one seed in isolation; most scenarios have one, but
`dst_materialization_crash_recovery`, `dst_peer_reconcile_race`,
`dst_directory_move_edit_race`, and `dst_sec_convergence` run a fixed set of
seeds/orderings with no env-var seed selection, so `dst-replay` refuses on
those rather than running the wrong thing (or, as it used to, matching no
tests and reporting success).

A corpus entry replays the same way: `cargo dst-replay <corpus-file>.jsonl`.

## 3. Choosing a lane (cheapest sufficient test for your diff)

| Lane | Command | Cost | What it runs |
|------|---------|------|--------------|
| 0 | `cargo dst-lane0` | seconds | harness unit tests + lints (+ watcher conformance, pending harden) |
| 1 | `cargo dst-lane1 [--ops <n>]` | minutes | each scenario × 1 seed, reduced op budget — a smoke |
| 2 | `cargo dst-lane2 [--variations <n>] [--keep <n>]` | longer | the standard seed sweep + retention prune |
| 3 | `scripts/heat-run.sh` | soak | nightly/heat-run (out of this change's scope) |

Pick the cheapest lane that covers your diff using `impact_map.toml` (§5): if you
touched `src/conflict.rs`, the map names the scenarios that exercise it — run
those under lane 1 first. `cargo dst-prune [--keep <n>]` prunes old
bundle/coverage artifacts on demand (default keep 20).

### Confirming one specific seed or recorded case at real sample size

`cargo dst-lane2`'s fresh sweep and a targeted reproduction answer different
questions: a fresh sweep at `n>=30` finding zero violations does not mean a
*specific* known-bad seed or recorded case is fixed at that sample size, only
that the sweep's own (almost always different) seeds happened not to hit it.
Confirming one specific target means running exactly that target, repeatedly,
independent of the sweep's own seed selection — and every scenario's `#[test]`
fn replays its entire corpus before its targeted loop even starts, which makes
that measurement cost nearly as much as the whole corpus at real sample sizes
(n>=30).

A fresh seed and a recorded corpus case are NOT the same target, even when
they share a numeral: a corpus entry is persisted as a full `Case` IR
specifically so a promoted failure survives this repo's generator evolving out
from under it (see each scenario's own `corpus_path`/`load_corpus_cases` doc
comment) — so `--seed <n>` (fresh, generator-driven) and `--case <path>`
(the exact recorded case) can diverge once the generator changes. Reproducing
a specific known regression means `--case`; confirming the release gate's
fresh-sweep claim means `--seed`.

```
cargo dst-targeted --scenario <name> (--seed <n> | --case <path> [--seed <n>]) [--n <count>]
```

Flags:
- `--scenario <name>` — the scenario test-binary name, e.g.
  `dst_network_fault_chaos` (required).
- `--seed <n>` — the exact seed to run fresh, every repeat. Required unless
  `--case` is given; combined with `--case`, selects which entry to run out of
  a shared multi-line corpus file instead of naming a fresh seed.
- `--case <path>` — a recorded corpus entry to repeat instead of a fresh seed:
  either a single-entry bundle file, or a `.jsonl` corpus file (in which case
  `--seed <n>` selects which entry — an error if none matches, never a silent
  substitution).
- `--n <count>` — how many times to repeat it (default 1). Each repeat is a
  fresh `cargo test` invocation with `DST_BASE_SEED`/`DST_VARIATIONS=1` set to
  the resolved seed, and corpus replay genuinely skipped (not merely emptied)
  via the dedicated `DST_SKIP_CORPUS_REPLAY` flag every corpus-bearing
  scenario honors.

Prints a `TALLY scenario=... seed=... n=... pass=... fail=... pass_rate=...%`
line — read the tally against whatever n-of-N threshold your gate needs (e.g.
n>=30 zero-fail, or a specific pass-rate bound); this command reports the raw
counts rather than reducing them to one pass/fail exit code. Refuses to run at
all if `tests/dst_corpus/` already has uncommitted changes, since it restores
that directory with `git checkout --` after every repeat so a reproduced
failure never gets silently written back into the very corpus this command
exists to run without.

## 4. Signature / corpus workflow

Each failure has a stable **signature** = `(violation kind, seed-normalized path
pattern, first-observable oracle kind)`, so the same logical failure signs
identically across seeds. On a new failure the harness scans
`tests/dst_corpus/*.jsonl` and, if the signature is known, leads the report with:

```
KNOWN: <signature> — <verdict> — <note>
```

or `KNOWN-DIVERGENT: …` when the new shrunk case differs materially from the
stored `case_min` (worth a look — same signature, different shape).

**Your obligation:** when you finish investigating a failure, record a one-line
`note` on its corpus entry (verdict + one sentence of conclusion). That note is
the primary cross-session record — it is what stops the next session
re-deriving what you just learned. This replaces scattered inline `PF` comments
as the system of record (the `PF` tags remain only as in-code pointers).

Corpus entry fields: `case` and `verdicts` (the harden task-6.4 base — a
per-violation `TriageVerdict` list) plus the additive/optional diagnostics
fields `signature`, `note`, `case_min` (all `#[serde(default)]`, so a legacy
`{case, verdicts}` or bare-`Case` line stays valid, and an unknown field is
preserved verbatim through a flatten catch-all). The KNOWN report's `<verdict>`
is summarized from `verdicts` (product bug if any, else harness artifact).

## 5. Impact-map contract

`tests/dst_support/impact_map.toml` maps every `src/*.rs` module → the scenarios
that exercise it, and every scenario → the oracle kinds it asserts.
`tests/dst_impact_map_lint.rs` fails if a module or scenario is missing from the
map (both directions), so the map cannot silently rot. When you add a scenario
or a sync-core module, add its map entry in the same change.

## 6. Coverage gaps → next detection target

Each sweep emits `target/dst-coverage/sweep-<id>.json` with per-dimension counts
(op kind, fault kind, topology, pairwise op×fault) and an explicit
`never_exercised` list of valid-but-unseen combinations. To choose what to test
next, read `never_exercised` — it names concrete combinations expressible in the
Case IR, so you propose the next target from data, not a guess.
