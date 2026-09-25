#![cfg(test)]

use super::ItemId;

#[test]
fn successor_carries_across_bytes() {
    let id = ItemId::from_bytes([0x00; 32]);
    assert_eq!(id.successor().unwrap(), {
        let mut bytes = [0x00; 32];
        bytes[31] = 1;
        ItemId::from_bytes(bytes)
    });

    let mut bytes = [0x00; 32];
    bytes[31] = 0xff;
    let id = ItemId::from_bytes(bytes);
    let mut expected = [0x00; 32];
    expected[30] = 1;
    assert_eq!(id.successor().unwrap(), ItemId::from_bytes(expected));
}

#[test]
fn the_largest_identifier_has_no_successor() {
    assert_eq!(ItemId::from_bytes([0xff; 32]).successor(), None);
}

#[test]
fn ordering_is_lexicographic_not_numeric_on_bytes() {
    let mut low = [0x00; 32];
    low[0] = 0x01;
    let mut high = [0x00; 32];
    high[1] = 0xff;
    assert!(ItemId::from_bytes(high) < ItemId::from_bytes(low));
}
