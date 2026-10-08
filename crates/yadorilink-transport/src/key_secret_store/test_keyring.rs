#![cfg(test)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

thread_local! {
    static STORE: RefCell<HashMap<String, [u8; 32]>> = RefCell::new(HashMap::new());
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static DISABLED: Cell<bool> = const { Cell::new(false) };
    static AVAILABLE: Cell<bool> = const { Cell::new(false) };
}

pub(super) fn set_available(value: bool) {
    AVAILABLE.with(|a| a.set(value));
}

fn is_available() -> bool {
    AVAILABLE.with(Cell::get)
}

pub(super) fn set_disabled(value: bool) {
    DISABLED.with(|d| d.set(value));
}

pub(super) fn disabled() -> bool {
    DISABLED.with(Cell::get)
}

/// Backend operations (get/set) issued so far on this thread.
pub(super) fn calls() -> usize {
    CALLS.with(Cell::get)
}

fn count_call() {
    CALLS.with(|c| c.set(c.get() + 1));
}

pub(super) fn reset() {
    CALLS.with(|c| c.set(0));
    set_disabled(false);
    STORE.with(|s| s.borrow_mut().clear());
    set_available(false);
}

pub(super) fn get(key: &str) -> Option<[u8; 32]> {
    count_call();
    if !is_available() {
        return None;
    }
    STORE.with(|s| s.borrow().get(key).copied())
}

pub(super) fn set(key: &str, value: &[u8; 32]) -> bool {
    count_call();
    if !is_available() {
        return false;
    }
    STORE.with(|s| s.borrow_mut().insert(key.to_string(), *value));
    true
}
