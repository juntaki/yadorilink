#![cfg(test)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

thread_local! {
    static STORE: RefCell<HashMap<String, [u8; 32]>> = RefCell::new(HashMap::new());
    static AVAILABLE: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn set_available(value: bool) {
    AVAILABLE.with(|a| a.set(value));
}

fn is_available() -> bool {
    AVAILABLE.with(Cell::get)
}

pub(super) fn reset() {
    STORE.with(|s| s.borrow_mut().clear());
    set_available(false);
}

pub(super) fn get(key: &str) -> Option<[u8; 32]> {
    if !is_available() {
        return None;
    }
    STORE.with(|s| s.borrow().get(key).copied())
}

pub(super) fn set(key: &str, value: &[u8; 32]) -> bool {
    if !is_available() {
        return false;
    }
    STORE.with(|s| s.borrow_mut().insert(key.to_string(), *value));
    true
}
