use super::*;

/// The batch is a knob with a small default, and a build yields between batches while idle
/// polling stays slow.
#[test]
fn the_batch_is_a_knob_and_a_build_yields_between_batches() {
    assert_eq!(batch_from(None), 1_000);
    assert_eq!(batch_from(Some("250")), 250);
    assert_eq!(batch_from(Some(" 4000 ")), 4_000);
    for bad in ["0", "-3", "many", ""] {
        assert_eq!(batch_from(Some(bad)), 1_000, "{bad:?}");
    }
    assert_eq!(next_delay(&Tick { projected: 1_000, became_ready: false }), YIELD);
    assert_eq!(next_delay(&Tick::default()), POLL);
    assert!(YIELD < POLL);
}
