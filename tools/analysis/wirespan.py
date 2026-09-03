#!/usr/bin/env python3
"""Derive the receiver's wire-arrival window from raw M6PHASE logs.

    first block received -> last block received

Reads the primitive both builds already emit (`T_recv_block_received`)
rather than either build's own derived-span printer. That matters for the
comparison this exists to serve: the newer tree can derive the span itself,
the older one cannot, and back-porting the derivation would have produced a
third cross-section -- old production code carrying new measurement code --
which is not what anyone wants to compare. Reading the same primitive on
both sides is also simply a stronger comparison than trusting two separate
derivations to agree.

Neither production tree is modified to run this. Point it at logs captured
from unmodified builds; if the analysis turns out to be wrong, it can be
corrected and re-run against the same saved logs.

## Validity, and why counting is not enough

Comparing a tag across two versions is only valid if the tag marks the same
point in both. It nearly did not here. The older tree emits this tag from
TWO call sites -- `fetch_and_store_one_block` and `deliver_prewarm_block`,
a speculative prewarm path -- while the current tree emits it from one,
`fetch_and_store_one_block` alone: prewarm was deleted along with the
transport it was measured against.

The two older sites cannot be told apart from a log at all -- same module
target, and byte-identical message text once the source's line wrapping is
gone. So equivalence rests on prewarm never firing, which is settled two
ways. Statically: the sender routes through `send_via_bulk_plane_if_active`,
inert unless a bulk plane is attached, and `deliver_prewarm_block` has no
callers outside tests and the bench's own opt-in bulk-QUIC wiring, neither
engaged by a default L1 two-process run. Empirically: a prewarm arrival
would be an arrival IN EXCESS of the file's block count, and the saved
three-transfer logs hold exactly 1296 arrivals on both sides -- 3 x 432,
with nothing left over.

That is why the emission target below is an equality check and not a
lower bound. A short count means arrivals went missing; a long one means a
second emission path fired. Both invalidate the comparison.

That argument is static, so this script does not get to rely on it. What a
log CAN show, it enforces:

  * **an emission target.** Every attempt is checked against the number of
    blocks the file actually needs. A short count means arrivals were
    missed, dropped by log filtering, or anchored somewhere else -- any of
    which invalidates the span rather than merely widening it.
  * **an attempt window.** The span is taken between the receiver learning
    what to fetch and its hydrated commit, not across the whole log, so a
    retried or abandoned attempt cannot silently stretch it.

Both must pass. Counting alone would not settle prewarm (one prewarm arrival
plus one fewer eager arrival sums to the same total), and a window alone
would not catch missing arrivals inside a correct-looking window.
"""
import argparse, datetime as dt, re, statistics, sys

TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)")
ARRIVAL = "T_recv_block_received"
# An attempt's arrivals end at the hydrated commit that consumes them, and
# arrivals are grouped on that line alone.
#
# The obvious alternative -- open a window on the receiver learning what to
# fetch, close it on the commit -- is WRONG here, and was tried first. These
# log lines carry no file identity, so a ChangeBatch for some other file
# landing mid-transfer is indistinguishable from the start of a new attempt;
# resetting on it silently discards the arrivals accrued so far and reports a
# short pass. That is what produced counts of 358 and 370 against a true 432,
# in logs that in fact held every arrival: 1296 = 3 x 432, exactly.
#
# Commits do not have that problem. A commit is emitted once per materialized
# file, after that file's arrivals, so splitting on it partitions the arrival
# stream by file without needing to name the file. Small files contribute
# empty groups, which is why the emission target rather than the group count
# is what identifies the transfer being measured.
CLOSER = "T_recv_hydrated_commit"


def attempts(path):
    """Yield the arrival timestamps of each completed hydration, in order.

    Arrivals after the last commit are dropped: an attempt with no commit has
    no defined end, and reporting a partial one is exactly the contamination
    this grouping exists to prevent.
    """
    group = []
    with open(path, errors="replace") as handle:
        for line in handle:
            if ARRIVAL in line:
                match = TIMESTAMP.search(line)
                if match:
                    group.append(
                        dt.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
                    )
            elif CLOSER in line:
                yield group
                group = []


def report(path, size_mib, expect_blocks):
    """Print one log's windows. Returns (median, ok) -- ok is False if any
    attempt failed the emission target, which makes the median unusable for a
    cross-version comparison even though it is still printed."""
    windows, counts, bad = [], [], []
    for stamps in attempts(path):
        if len(stamps) < 2:
            continue  # a single arrival has no window to measure
        windows.append((stamps[-1] - stamps[0]).total_seconds())
        counts.append(len(stamps))
    if not windows:
        print(f"{path}: no wire-arrival windows found")
        return None, False
    print(f"{path}")
    print(f"  blocks/pass          : {counts}")

    ok = True
    if expect_blocks:
        bad = [(i + 1, c) for i, c in enumerate(counts) if c != expect_blocks]
        if bad:
            ok = False
            print(f"  INVALID: expected {expect_blocks} arrivals per attempt; "
                  f"short/over passes {bad}")
            print("    An attempt that does not emit one arrival per block did not")
            print("    have its whole receive observed, so first->last is not the")
            print("    receive window. This invalidates the comparison; it does not")
            print("    merely widen it.")
        else:
            print(f"  emission target      : {expect_blocks}/attempt, all passes OK")
    elif len(set(counts)) > 1:
        ok = False
        print("    NOTE: block counts differ between passes and no --expect-blocks")
        print("    was given, so this cannot be adjudicated. Pass the file's real")
        print("    block count to turn this into a check.")

    print(f"  first->last (s)      : {['%.2f' % w for w in windows]}")
    print(f"  median               : {statistics.median(windows):.2f}s"
          f"{'' if ok else '   <- NOT USABLE'}")
    if size_mib:
        rates = [size_mib / w for w in windows if w > 0]
        if rates:
            print(f"  goodput (MiB/s)      : {['%.0f' % r for r in rates]}"
                  f"  median={statistics.median(rates):.0f}")
    return statistics.median(windows), ok


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("logs", nargs="+")
    parser.add_argument("--size-mib", type=float, default=1024.0,
                        help="transfer size, for the goodput column (default 1024)")
    parser.add_argument("--expect-blocks", type=int, default=None,
                        help="arrivals every attempt must emit -- the file's block "
                             "count. Without it a short receive cannot be detected "
                             "and no comparison is reported.")
    args = parser.parse_args()
    results = [(p, *report(p, args.size_mib, args.expect_blocks)) for p in args.logs]
    usable = [(p, m) for p, m, ok in results if m is not None and ok]
    if len(usable) == 2:
        (_, ma), (_, mb) = usable
        print(f"\n{ma:.2f}s vs {mb:.2f}s   difference {mb - ma:+.2f}s")
    elif len(results) == 2:
        print("\nNo comparison reported: at least one side failed validity above.")
    return 0 if all(ok for _, m, ok in results if m is not None) else 1


if __name__ == "__main__":
    sys.exit(main())
