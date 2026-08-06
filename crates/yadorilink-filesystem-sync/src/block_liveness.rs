//! Process-wide exclusion between block-reference commits and physical
//! deletion -- a real filesystem/execution-coordination primitive with zero
//! index/SQL/state dependency, moved out of `yadorilink-sync-core` in Phase
//! 7D-9C alongside the eviction/materialization logic it serializes (see
//! `docs/design/phase7d9-dependency-plan.md`'s 7D-9C routing rules; this
//! gate is one of the named "behavior to preserve exactly" invariants,
//! "block liveness").

use std::sync::{Condvar, Mutex};

#[derive(Default)]
struct State {
    writers: usize,
    deleting: bool,
}

#[derive(Default)]
pub struct BlockLivenessGate {
    state: Mutex<State>,
    changed: Condvar,
}

impl BlockLivenessGate {
    pub fn begin_reference_write(&self) -> BlockReferenceWriteGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while state.deleting {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.writers += 1;
        BlockReferenceWriteGuard { gate: self }
    }

    pub fn begin_physical_deletion(&self) -> BlockPhysicalDeletionGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while state.deleting || state.writers != 0 {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.deleting = true;
        BlockPhysicalDeletionGuard { gate: self }
    }
}

pub struct BlockReferenceWriteGuard<'a> {
    gate: &'a BlockLivenessGate,
}

impl Drop for BlockReferenceWriteGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        state.writers -= 1;
        if state.writers == 0 {
            self.gate.changed.notify_all();
        }
    }
}

pub struct BlockPhysicalDeletionGuard<'a> {
    gate: &'a BlockLivenessGate,
}

impl Drop for BlockPhysicalDeletionGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        state.deleting = false;
        self.gate.changed.notify_all();
    }
}
