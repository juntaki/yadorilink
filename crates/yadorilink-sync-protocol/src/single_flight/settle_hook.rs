#![cfg(test)]

use std::cell::RefCell;

thread_local! {
    static HOOK: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
}

pub(super) fn set(hook: impl Fn() + 'static) {
    HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
}

pub(super) fn clear() {
    HOOK.with(|h| *h.borrow_mut() = None);
}

pub(super) fn fire() {
    // Taken out while running so a hook that re-enters `run` does not
    // recurse into itself.
    let hook = HOOK.with(|h| h.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
