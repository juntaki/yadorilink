//! A small concrete protocol for kernel tests: changes are indices into an
//! arena, paths are strings, authors are small integers.

#![allow(dead_code)]

use std::collections::BTreeMap;

use yadorilink_dcf_kernel::{KernelOp, KernelPreservation, Protocol, SafeProtocol, State};

pub type Change = u32;
pub type Path = String;
pub type Author = u8;
pub type TestState = State<Path, Change, Author>;

#[derive(Clone, Debug, Default)]
pub struct ChangeData {
    pub author: Author,
    pub seq: u64,
    pub ops: Vec<KernelOp<Path, Change>>,
    /// Version landed per path; paths not listed have version 0.
    pub versions: BTreeMap<Path, u64>,
    pub preservations: Vec<KernelPreservation<Path, Change>>,
}

pub struct Arena {
    pub changes: Vec<ChangeData>,
    pub conflict: fn(&Path, &Change) -> Path,
}

pub fn default_conflict_path(path: &Path, source: &Change) -> Path {
    format!("{path}~{source}")
}

impl Default for Arena {
    fn default() -> Self {
        Self { changes: Vec::new(), conflict: default_conflict_path }
    }
}

impl Arena {
    pub fn push(&mut self, data: ChangeData) -> Change {
        self.changes.push(data);
        u32::try_from(self.changes.len() - 1).expect("arena index fits u32")
    }

    pub fn data(&self, change: Change) -> &ChangeData {
        &self.changes[change as usize]
    }
}

impl Protocol for Arena {
    type Change = Change;
    type Path = Path;
    type Author = Author;

    fn author(&self, change: &Change) -> Author {
        self.data(*change).author
    }

    fn seq(&self, change: &Change) -> u64 {
        self.data(*change).seq
    }

    fn ops(&self, change: &Change) -> Vec<KernelOp<Path, Change>> {
        self.data(*change).ops.clone()
    }
}

impl SafeProtocol for Arena {
    type Version = u64;

    fn version(&self, change: &Change, path: &Path) -> u64 {
        self.data(*change).versions.get(path).copied().unwrap_or(0)
    }

    fn preservations(&self, change: &Change) -> Vec<KernelPreservation<Path, Change>> {
        self.data(*change).preservations.clone()
    }

    fn conflict_path(&self, path: &Path, source: &Change) -> Path {
        (self.conflict)(path, source)
    }
}

pub fn op(path: &str, lands: bool, basis: &[Change]) -> KernelOp<Path, Change> {
    KernelOp { path: path.to_owned(), lands, basis: basis.to_vec() }
}

pub fn change(author: Author, seq: u64, ops: Vec<KernelOp<Path, Change>>) -> ChangeData {
    ChangeData { author, seq, ops, ..ChangeData::default() }
}

pub fn path(name: &str) -> Path {
    name.to_owned()
}
