//! Compact basis encodings relative to the pre-state heads.
//!
//! Most edits consume every current head of a path, so a basis can be
//! written as "all current heads", "all current heads except these", or an
//! explicit list, and decoded against the pre-state heads the author-side
//! check runs on. This is an encoding for proof and witness pipelines that
//! already hold that pre-state; a signed change carries its decoded basis.
//!

/// A basis written relative to the pre-state heads of its path.
///
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BasisEncoding<C> {
    /// Every current head.
    AllCurrent,
    /// Every current head except the listed ones.
    Except(Vec<C>),
    /// Exactly the listed members.
    Explicit(Vec<C>),
}

impl<C: Clone + Eq> BasisEncoding<C> {
    /// The basis this encoding denotes against the pre-state `heads`.
    ///
    /// Over duplicate-free heads, `AllCurrent` always meets the per-path
    /// clauses of the strict author-side check, and `Except` does when no
    /// head of the author is excepted.
    ///
    pub fn decode(&self, heads: &[C]) -> Vec<C> {
        match self {
            Self::AllCurrent => heads.to_vec(),
            Self::Except(excepted) => {
                heads.iter().filter(|head| !excepted.contains(head)).cloned().collect()
            }
            Self::Explicit(members) => members.clone(),
        }
    }

    /// The members the encoding itself carries.
    ///
    pub fn encoded_members(&self) -> &[C] {
        match self {
            Self::AllCurrent => &[],
            Self::Except(members) | Self::Explicit(members) => members,
        }
    }
}
