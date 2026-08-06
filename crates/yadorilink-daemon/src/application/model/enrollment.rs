//! Protocol-independent results the Enrollment coordination port returns --
//! owned by `application`, not borrowed from the coordination-client
//! module, so this module never needs to know how those results were
//! transported.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollmentPrepareResult {
    Prepared {
        group_id: String,
    },
    /// The remote prepare was NOT committed.
    DefinitelyRejected {
        detail: String,
    },
    /// This operation_id already names a differently-shaped request.
    Conflict {
        detail: String,
    },
    /// Transport failure or an unparseable success response -- may or may
    /// not have committed.
    Ambiguous {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollmentActivationResult {
    Activated,
    AlreadyActive,
    /// A CONFIRMED terminal answer: the coordination plane has nothing left
    /// to activate for this operation.
    Deleted,
    TransientFailure {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollmentCancellationResult {
    /// Includes an already-deleted/already-swept/already-active no-op.
    Confirmed,
    /// A request-identity mismatch, not a routine absence.
    Conflict {
        detail: String,
    },
    Ambiguous {
        detail: String,
    },
}
