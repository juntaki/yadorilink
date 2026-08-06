//! The reserved on-disk artefact namespace.
//!
//! Filesystem-transaction artefacts (staged writes, captured preimages,
//! backups, retained-custody copies and filesystem-capability probe
//! artefacts) live *beside* the user object they belong to, under the same
//! parent directory, so their commit — or, for a probe, the operation it
//! measures — can share the same filesystem and volume as the object
//! itself. That only works if every path-consuming entry point in this
//! crate — the watcher, local change processing, the initial scan, DAG
//! import, peer admission and stale-file cleanup — agrees on exactly which
//! names are reserved, and agrees on it *before* user ignore rules run: a
//! user can configure `.yadorilinkignore` to un-ignore anything, but must
//! never be able to make an artefact name eligible for ordinary indexing.
//!
//! This module is that single shared predicate. It is a naming *protocol*,
//! not a convention a caller can opt out of: a path component that matches
//! is never content, regardless of what created it or what any ignore file
//! says.
//!
//! # Ownership rule
//!
//! Recognizing a name as reserved is not the same as owning it. A component
//! matching this predicate that no journal row (or, for the legacy marker,
//! no in-flight writer this process itself started) claims is an unknown
//! artefact: leftover from a crash, a different process, or a future
//! version this build doesn't understand. An unknown reserved-looking file
//! must never be deleted, imported, indexed or treated as user content —
//! see [`crate::error::SyncError::ReservedNamespaceCollision`] for the
//! fail-closed signal a caller raises when it finds one somewhere it did
//! not expect one.
//!
//! This module only recognizes names. It does not yet track which artefact
//! a given journal row owns — that arrives with the journal itself.
//!
//! # Two predicates, not one
//!
//! There are two different questions a caller can ask, and they must not be
//! collapsed into a single function:
//!
//! - **"Should this stay out of ordinary sync?"** — [`is_reserved_component`]
//!   / [`path_has_reserved_component`]. True for both a versioned artefact
//!   and the legacy marker. Used by the watcher, the initial scan, local
//!   change processing and DAG import: every place that decides what to
//!   index or track. `fs_capabilities`'s probe artefacts rely on exactly
//!   this predicate to stay invisible to those entry points for the brief
//!   window between their creation and their own removal — see
//!   [`ArtefactKind::Probe`].
//! - **"May a peer or a local writer *name* this path at all?"** —
//!   [`is_artefact_component`] / [`path_has_artefact_component`]. True only
//!   for a versioned artefact, never for the legacy marker. Used by DAG
//!   admission and peer materialization: every place that fails a whole
//!   operation closed.
//!
//! The legacy marker is exclusion-only by design (see
//! [`ReservedComponent::Legacy`]): `contains_legacy_marker` is a substring
//! test within a component, deliberately looser than the versioned kinds'
//! whole-component match, because arbitrary user content can precede it
//! (`report.yadorilink-tmp.old`) — `materialization::cleanup_stale_temp_
//! files` already refuses to delete exactly such a look-alike. Two things
//! follow from that looseness, and both are why the legacy marker must
//! never reach a rejection site:
//!
//! - A change or a peer write naming a legacy-marked path is not
//!   necessarily an artefact at all — it can be an ordinary user file that
//!   merely contains the substring, and rejecting it would make a real file
//!   permanently un-syncable, in direct conflict with the GC's own
//!   preservation of that same file.
//! - History predating this module can already contain a legacy-marked
//!   path, admitted back when nothing excluded it (that gap is exactly the
//!   latent bug this module closes at the exclusion sites). If admission
//!   used the exclusion predicate, an upgraded peer would refuse that
//!   already-signed change forever — turning a client-side fix into a
//!   group-wide sync stall.
//!
//! So exclusion is deliberately over-inclusive (better to skip indexing a
//! look-alike than risk treating a real artefact as content), while
//! rejection is deliberately narrow (only a name this module itself can
//! construct is grounds for refusing an entire operation).

use std::ffi::OsStr;
use std::path::Path;

/// Every reserved-component name (including the legacy marker) is bounded
/// by this length, in bytes, once encoded — the portable floor most
/// filesystems enforce for a single path component (`NAME_MAX` on Linux,
/// `_PC_NAME_MAX` elsewhere, ext4/APFS/NTFS all at or above it). A
/// generated name that would exceed this is a construction error, never a
/// silently truncated one: a truncated artefact name could collide with
/// another truncated name, or with unrelated user content.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Identifies exactly which version of this module's rejection rules —
/// `path_has_artefact_component_in_wire_path` and
/// `path_has_non_portable_wire_component`, and everything either calls —
/// produced a verdict. **Bump this whenever those rules change** — the
/// legacy/artefact predicate split, the Windows trailing-dot/space
/// normalization, the ADS-suffix/dual-separator wire canonicalization,
/// `path_has_non_portable_wire_component`'s general portability predicate
/// (trailing dot/space, `:`, reserved Windows device names, and the other
/// Win32-reserved filename characters, for *any* path, not only
/// reserved-artefact look-alikes), and (this bump) that same predicate's
/// short-name-alias-shape, superscript-device-name and control-character
/// checks — each changed which paths this module considers reserved —
/// exactly the situation this constant exists for.
///
/// `dag_store::rejected_changes` stamps every durable admission rejection
/// with this value and refuses to trust a row stamped with an older one as
/// a settled, permanent verdict — see that module's doc comment. Forgetting
/// to bump this when the rules change reintroduces the same failure mode as
/// the silent-stranding bug this namespace's exclusion sites were fixed to
/// avoid, arriving through a different door: a change rejected under
/// yesterday's rules stays permanently unadmittable even after today's
/// rules would accept it, because nothing ever re-evaluates a "settled"
/// verdict.
///
/// Also bumped for [`ArtefactKind::Probe`]: adding a kind to
/// [`ArtefactKind::ALL`] widens `parse_artefact_component`, which backs
/// both the host and the wire predicates — a wire path shaped
/// `.yadorilink-v1-probe.<id>` now classifies as
/// [`ReservedComponent::Artefact`] where it previously classified as
/// ordinary content, exactly the "which paths this module considers
/// reserved" change this constant exists to version. No legitimate change
/// ever wants that literal path (a probe artefact is never journaled or put
/// on the wire), so the practical effect is only that a peer can no longer
/// name a file that shape — but the verdict for that shape changed, so the
/// version must too.
pub const RULES_VERSION: u32 = 4;

/// The versioned artefact kinds from the reserved namespace. Each maps to a
/// literal ASCII prefix that appears in `.yadorilink-v1-<kind>.<id>` — see
/// [`ReservedComponent::kind_prefix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtefactKind {
    /// A write staged beside its eventual target, not yet committed.
    Stage,
    /// A captured preimage of an object about to be replaced or removed.
    Preimage,
    /// A backup produced by a platform commit adapter as part of an atomic
    /// replace (e.g. Windows `ReplaceFileW`'s backup file).
    Backup,
    /// A preimage retained past its transaction's commit, held for later
    /// custody/repair purposes rather than GC'd immediately.
    Retained,
    /// A throwaway artefact created and removed within a single
    /// [`crate::fs_capabilities`] probe call (a birth-time-granularity
    /// sample, an exchange/clone/flush probe target, and so on). Distinct
    /// from the other three kinds in one respect: no journal row ever
    /// claims one, by design — a probe artefact's whole lifetime is
    /// contained inside one function call on this process, so there is
    /// nothing for a journal to record. It still needs its own reserved
    /// name, for the same reason the others do: it is created inside a
    /// live sync directory, beside real user content, and must be invisible
    /// to the watcher, the initial scan and local change processing for the
    /// window between its creation and its own removal — an unreserved name
    /// there would let a race admit it as an ordinary file (see
    /// `fs_capabilities::probe_artefact_name`'s doc for the concrete
    /// mechanism this closes).
    Probe,
}

impl ArtefactKind {
    const ALL: [ArtefactKind; 5] = [
        ArtefactKind::Stage,
        ArtefactKind::Preimage,
        ArtefactKind::Backup,
        ArtefactKind::Retained,
        ArtefactKind::Probe,
    ];

    /// The lowercase ASCII token that follows `.yadorilink-v1-` in a
    /// generated name, e.g. `"stage"` for [`ArtefactKind::Stage`].
    fn kind_prefix(self) -> &'static str {
        match self {
            ArtefactKind::Stage => "stage",
            ArtefactKind::Preimage => "preimage",
            ArtefactKind::Backup => "backup",
            ArtefactKind::Retained => "retained",
            ArtefactKind::Probe => "probe",
        }
    }
}

/// Prefix shared by every versioned artefact name, before the kind token.
const V1_PREFIX: &str = ".yadorilink-v1-";

/// The legacy temp-file marker `chunker::unique_tmp_path` (and
/// `yadorilink-local-storage`'s equivalent) has always appended. It predates
/// this module and keeps its own strict-suffix shape and its own GC matcher
/// (`materialization::cleanup_stale_temp_files`) rather than being folded
/// into the versioned namespace — see [`ReservedComponent::Legacy`]'s doc
/// comment for why.
const LEGACY_MARKER: &str = ".yadorilink-tmp.";

/// A path component recognized by the reserved namespace, distinguishing an
/// artefact this module can name and construct from the legacy marker it
/// only recognizes for exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedComponent<'a> {
    /// A `.yadorilink-v1-<kind>.<id>` artefact this module owns the naming
    /// scheme for.
    Artefact { kind: ArtefactKind, id: &'a str },
    /// The pre-existing `.yadorilink-tmp.<pid>.<counter>` marker. Additive:
    /// this module recognizes it purely so it is excluded from indexing
    /// alongside the versioned kinds, but does not construct, parse or own
    /// it beyond that — `chunker::unique_tmp_path` still mints it and
    /// `materialization::cleanup_stale_temp_files` still collects it with
    /// its own, unchanged, strict-suffix matcher. A daemon upgrade must not
    /// orphan an in-flight temp file from the previous version with no
    /// collector, so the legacy marker keeps working exactly as it always
    /// has; this variant only ever appears for **exclusion**, never for
    /// construction.
    Legacy,
}

/// Why `artefact_component_name` refused to build a name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtefactNameError {
    /// The constructed name would exceed [`MAX_COMPONENT_BYTES`] once
    /// encoded. Returned instead of silently truncating, since a truncated
    /// name could collide with another artefact or with unrelated user
    /// content.
    #[error(
        "reserved artefact name for id {id:?} is {actual_bytes} bytes, exceeding the \
         {MAX_COMPONENT_BYTES}-byte portable component limit"
    )]
    TooLong { id: String, actual_bytes: usize },
    /// `id` contains a byte outside the reserved namespace's token
    /// alphabet (ASCII alphanumeric, `-` and `_`). In particular `id` may
    /// not contain `.` or `/`: allowing either would make the boundary
    /// between "kind token" and "id" ambiguous when re-parsing the name
    /// with [`parse_artefact_component`], and a `/` could be misread as a
    /// path separator by a caller that treats the returned string as a
    /// single component without checking.
    #[error(
        "reserved artefact id {id:?} contains a byte outside [A-Za-z0-9_-]; \
         constructed component names must stay unambiguous to re-parse"
    )]
    InvalidId { id: String },
}

/// Whether every byte of `id` is in the reserved namespace's token
/// alphabet — see [`ArtefactNameError::InvalidId`].
fn is_valid_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Builds the on-disk component name for `(kind, id)`: exactly
/// `.yadorilink-v1-<kind>.<id>`. `id` must be a non-empty run of ASCII
/// alphanumerics, `-` and `_` (e.g. hex or base32 both fit) — see
/// [`ArtefactNameError::InvalidId`] for why the alphabet is restricted.
pub fn artefact_component_name(kind: ArtefactKind, id: &str) -> Result<String, ArtefactNameError> {
    if !is_valid_id(id) {
        return Err(ArtefactNameError::InvalidId { id: id.to_string() });
    }
    let name = format!("{V1_PREFIX}{}.{id}", kind.kind_prefix());
    if name.len() > MAX_COMPONENT_BYTES {
        return Err(ArtefactNameError::TooLong { id: id.to_string(), actual_bytes: name.len() });
    }
    Ok(name)
}

/// Parses a path component's name back into `(kind, id)`, or `None` if it
/// does not match any versioned artefact kind. ASCII case-folded, matching
/// [`is_reserved_component`] — `.YADORILINK-V1-STAGE.x` parses the same as
/// `.yadorilink-v1-stage.x`. Returns a borrow of `id` from `name`, so the
/// id is returned exactly as spelled on disk (not case-folded). `id` must
/// pass [`is_valid_id`]; anything else (in particular, a `.`-separated
/// trailer after what looks like an id) is not a well-formed artefact name
/// and is treated as ordinary content rather than guessed at.
pub fn parse_artefact_component(name: &str) -> Option<(ArtefactKind, &str)> {
    let lower_prefix_len = V1_PREFIX.len();
    if name.len() < lower_prefix_len || !name.is_char_boundary(lower_prefix_len) {
        return None;
    }
    if !name[..lower_prefix_len].eq_ignore_ascii_case(V1_PREFIX) {
        return None;
    }
    let rest = &name[lower_prefix_len..];
    for kind in ArtefactKind::ALL {
        let prefix = kind.kind_prefix();
        let Some(len) = prefix.len().checked_add(1) else { continue };
        if rest.len() < len || !rest.is_char_boundary(prefix.len()) || !rest.is_char_boundary(len) {
            continue;
        }
        if rest[..prefix.len()].eq_ignore_ascii_case(prefix)
            && rest.as_bytes()[prefix.len()] == b'.'
        {
            let id = &rest[len..];
            if !is_valid_id(id) {
                continue;
            }
            return Some((kind, id));
        }
    }
    None
}

/// Whether `name` is the legacy temp-file marker `chunker::unique_tmp_path`
/// generates, recognized only for exclusion — see [`ReservedComponent::Legacy`].
/// ASCII case-folded and component-exact in the same sense as
/// [`is_reserved_component`]: it requires the literal marker to appear as a
/// substring (matching the shape `unique_tmp_path` actually produces —
/// `<original-name>.yadorilink-tmp.<pid>.<counter>`, where arbitrary user
/// content precedes the marker within the same component), not that the
/// whole component equal it. `materialization::is_own_stale_temp_file_name`
/// additionally validates the `<pid>.<counter>` suffix shape for its own
/// (stricter) deletion decision; this function only decides "exclude from
/// indexing," which must be at least as permissive as that stricter check
/// so nothing importable slips through the gap between the two.
fn contains_legacy_marker(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains(&LEGACY_MARKER.to_ascii_lowercase())
}

/// Windows silently drops trailing `.` and ` ` characters from a path
/// component in most Win32 APIs (`CreateFileW` and friends): a caller that
/// asks for `"foo. "` or `"foo.."` gets a file literally named `"foo"` on
/// disk. Applied here, on every platform, before matching against the
/// versioned artefact shape — this predicate is a wire-facing security
/// boundary (a peer on any platform authors the path; the device that
/// eventually materializes it may be a Windows device regardless of which
/// platform is running this check right now), so a peer-supplied
/// `".yadorilink-v1-stage.<id> "` (one trailing space) or
/// `".yadorilink-v1-stage.<id>."` (trailing dot) must classify exactly the
/// same as the un-suffixed name: neither is component-exact as *typed*, but
/// both land on disk, on Windows, as the literal reserved name. Matching
/// only the untrimmed name here would let a peer plant — or later collide
/// with, or falsely block via `ReservedNamespaceCollision` — an artefact
/// this module owns, without ever spelling its exact name on the wire.
///
/// Deliberately NOT applied to the legacy-marker substring check below:
/// `contains_legacy_marker` already matches through arbitrary trailing
/// content (it is a substring test, not a full match), so trailing
/// dots/spaces on a legacy-shaped name change nothing about whether the
/// marker is present.
fn strip_windows_trailing_normalization(name: &str) -> &str {
    name.trim_end_matches(['.', ' '])
}

/// Truncates at the first `:` — strips an NTFS alternate-data-stream
/// suffix. `filename::$DATA` addresses `filename`'s own default stream
/// (they are the same on-disk object), and `filename:stream:$DATA`
/// addresses a named stream *on* `filename` — both mutate `filename`
/// itself, not some other file. `:` is not a legal NTFS filename
/// character outside this syntax, but `change::validate_path` (the wire
/// validator) permits it — it only rejects a drive-qualified first
/// segment — and a POSIX filesystem allows a literal `:` in a name, so a
/// peer can spell `".yadorilink-v1-stage.<id>::$DATA"` or
/// `".yadorilink-v1-stage.<id>:payload:$DATA"` and have neither
/// `validate_path` nor a naive component-exact match ever notice it is an
/// alias for the reserved artefact `<id>`. Truncating before matching is
/// what makes `parse_artefact_component` see the same name a Windows
/// materializer's disk actually resolves to.
pub(crate) fn strip_alternate_data_stream_suffix(name: &str) -> &str {
    name.split(':').next().unwrap_or(name)
}

/// Core classification shared by every predicate in this module: matches
/// `normalized` against the versioned artefact shape, and `raw` against
/// the legacy substring marker. Callers differ only in how they arrive at
/// `normalized` (host-`Path`-component callers strip Windows trailing
/// dot/space; wire-path callers additionally strip an ADS suffix and split
/// on both separators before ever reaching here) — the match itself, and
/// the ASCII-only case folding it performs, must be identical either way.
/// `raw` is deliberately never normalized for the legacy check: it is
/// already a substring test, permissive by design (see
/// [`contains_legacy_marker`]), so trimming its input can only ever widen
/// what it matches, never narrow it, and there is no bypass to close.
fn classify_normalized_component<'a>(
    normalized: &'a str,
    raw: &'a str,
) -> Option<ReservedComponent<'a>> {
    if let Some((kind, id)) = parse_artefact_component(normalized) {
        return Some(ReservedComponent::Artefact { kind, id });
    }
    if contains_legacy_marker(raw) {
        return Some(ReservedComponent::Legacy);
    }
    None
}

/// Classifies a single path component (a `Path::components()` item's
/// `.as_os_str()`, or any other single filename/directory-name string —
/// never a multi-segment path), or `None` if it is ordinary user content.
///
/// This is the **host** form: it consults this process's own
/// `std::path::Path` (via its `OsStr` input) to have already found the
/// component boundary, and applies Windows trailing-dot/space
/// normalization but NOT alternate-data-stream stripping (a real
/// directory listing, on any OS, never hands back an ADS-suffixed entry
/// name — that syntax only exists at the point a caller opens a path, not
/// as a name anything enumerates). Suitable for a path that this
/// process itself walked off a real, local directory tree: the watcher,
/// the initial scan, local change processing, `link_preflight`, stale-file
/// cleanup. NOT suitable for a peer-authored path string — see
/// [`path_has_artefact_component_in_wire_path`] for why that needs the
/// separate wire form.
///
/// ASCII case-folded (never Unicode case folding — the reserved names are
/// pure ASCII, and Unicode case folding could map an unrelated user
/// filename onto one of them in some locale/normalization forms).
/// Component-exact for the versioned kinds, up to Windows's trailing
/// dot/space normalization (see [`strip_windows_trailing_normalization`]):
/// `notes.yadorilink-v1-stage.x` does not match, only a component that *is*
/// the artefact name (modulo that trailing-character stripping). This
/// mirrors the precedent in `materialization::cleanup_stale_temp_files`'s
/// doc comment, which deliberately rejects treating a user file that merely
/// *contains* `.yadorilink-tmp.` as one of its own temp files.
pub fn classify_component(name: &OsStr) -> Option<ReservedComponent<'_>> {
    let name = name.to_str()?;
    let normalized = strip_windows_trailing_normalization(name);
    classify_normalized_component(normalized, name)
}

/// Whether a single path component is reserved, in either sense
/// ([`ReservedComponent::Artefact`] or [`ReservedComponent::Legacy`]) — the
/// predicate every entry point applies before user ignore rules. See
/// [`classify_component`] for case-folding and component-exactness details.
pub fn is_reserved_component(name: &OsStr) -> bool {
    classify_component(name).is_some()
}

/// Whether any component of `relative_path` is reserved. `relative_path`
/// must already be root-relative (this makes no attempt to resolve `..` or
/// symlinks — callers combine this with their own root-confinement checks).
/// This is the path-level form of [`is_reserved_component`]: a reserved
/// component anywhere in the path — not only the final one — makes the
/// whole path reserved, since a transaction artefact used as an
/// intermediate directory is exactly as impermissible as one used as a
/// leaf.
pub fn path_has_reserved_component(relative_path: &Path) -> bool {
    relative_path.components().any(|c| is_reserved_component(c.as_os_str()))
}

/// Like [`path_has_reserved_component`], but returns the specific
/// component found, for callers that want to report or classify it rather
/// than only exclude it.
pub fn find_reserved_component(relative_path: &Path) -> Option<ReservedComponent<'_>> {
    relative_path.components().find_map(|c| classify_component(c.as_os_str()))
}

/// Whether a single path component is a versioned artefact this module
/// owns the naming scheme for — `false` for the legacy marker. This is the
/// **rejection** predicate for a **host**-sourced component (one this
/// process itself walked off a real local directory tree — see
/// [`classify_component`]'s doc comment on that distinction). See the
/// module doc's "Two predicates, not one" section for why the legacy
/// marker must not reach a rejection site, and [`is_reserved_component`]
/// for the (deliberately broader) exclusion predicate used everywhere
/// else.
pub fn is_artefact_component(name: &OsStr) -> bool {
    matches!(classify_component(name), Some(ReservedComponent::Artefact { .. }))
}

/// The path-level form of [`is_artefact_component`] — true if any component
/// of `relative_path` is a versioned artefact. Never true for a
/// legacy-marked path; see [`is_artefact_component`].
///
/// `relative_path` must be a **host** path this process itself produced
/// (from an actual `Path::components()` walk) — NOT a raw path string that
/// arrived off the wire. For that, use
/// [`path_has_artefact_component_in_wire_path`] instead; see its doc
/// comment for why the two must not be interchanged.
pub fn path_has_artefact_component(relative_path: &Path) -> bool {
    relative_path.components().any(|c| is_artefact_component(c.as_os_str()))
}

/// Splits a peer-authored path **string** into components the same way
/// `change::validate_path` accepts it: on **both** `/` and `\`, regardless
/// of which OS is evaluating it right now.
///
/// A path string reaching this function was authored on an arbitrary
/// remote peer and will be evaluated — and, once the transaction engine
/// lands, ultimately materialized — on an arbitrary local platform. Using
/// this process's own `std::path::Path` to find component boundaries (as
/// [`path_has_artefact_component`] correctly does for a path this process
/// itself walked off disk) would silently make admission depend on which
/// OS happens to be running the check: `safe\.yadorilink-v1-stage.x` is
/// ONE component on Unix (so it is admitted) and TWO on Windows (so the
/// second, `.yadorilink-v1-stage.x`, is rejected) — an authorized peer's
/// signed change would then be admitted by every Unix peer and refused
/// forever by every Windows peer, permanently splitting the group along
/// platform lines behind a `Path` that never actually got resolved on
/// either device. This function is the canonical, host-independent
/// definition of "a path component" for reserved-namespace REJECTION of a
/// wire path; nothing here consults `std::path::Path`, and nothing in this
/// module's wire-path functions should.
pub(crate) fn wire_path_components(path: &str) -> impl Iterator<Item = &str> {
    path.split(['/', '\\'])
}

/// [`classify_component`]'s wire-path counterpart: same ASCII case-folded,
/// component-exact match, but additionally strips an alternate-data-stream
/// suffix (see [`strip_alternate_data_stream_suffix`]) before matching,
/// since a wire component was never enumerated off a real directory (where
/// that syntax cannot appear) — it was typed by a peer, which can spell
/// one.
fn classify_wire_component(component: &str) -> Option<ReservedComponent<'_>> {
    let ads_stripped = strip_alternate_data_stream_suffix(component);
    let normalized = strip_windows_trailing_normalization(ads_stripped);
    classify_normalized_component(normalized, component)
}

/// Whether a single wire-path component is a versioned artefact — the
/// wire-path counterpart to [`is_artefact_component`]. See
/// [`classify_wire_component`] and [`wire_path_components`] for what makes
/// this different from (and required instead of) the host form.
fn is_artefact_wire_component(component: &str) -> bool {
    matches!(classify_wire_component(component), Some(ReservedComponent::Artefact { .. }))
}

/// Whether any component of a peer-authored path **string** is a versioned
/// reserved-namespace artefact — the **rejection** predicate for
/// wire-sourced paths, paralleling [`path_has_artefact_component`] for
/// host-sourced ones.
///
/// Use this (never the host-`Path` form) at every site that rejects a
/// whole operation because of a path a peer supplied, rather than one this
/// process discovered on its own disk: DAG admission
/// (`dag_store::admit_change`) and peer materialization
/// (`PeerSyncSession::materialize`) are the two such sites today. Splits
/// on both `/` and `\` (see [`wire_path_components`]) and strips an
/// NTFS alternate-data-stream suffix per component (see
/// [`strip_alternate_data_stream_suffix`]) before matching, so
/// `".yadorilink-v1-stage.<id>::$DATA"`, `"safe\.yadorilink-v1-stage.<id>"`
/// and ordinary `".yadorilink-v1-stage.<id>"` are all rejected identically,
/// on every platform running the check, regardless of which platform
/// authored the path or will eventually materialize it.
pub fn path_has_artefact_component_in_wire_path(path: &str) -> bool {
    wire_path_components(path).any(is_artefact_wire_component)
}

/// Windows reserves these device names as a whole filename component,
/// case-insensitively, matched against the component's **stem** — the
/// part before its first `.` — not its whole name: `"CON"`, `"con.txt"`
/// and `"COM1.tar.gz"` are all reserved (Windows resolves the device by
/// stem alone; the rest of the name is never reached). Creating a file
/// under one of these names fails outright, every time, on every Windows
/// device — deterministic, not a silent alias, but the same "one
/// platform can never do this, another does it without complaint"
/// property as everything else in this module. A file literally named
/// `"CON"` is perfectly legal on Linux/macOS. Includes `CONIN$` and
/// `CONOUT$`, the console input/output device names, alongside the more
/// commonly listed `CON`/`PRN`/`AUX`/`NUL`/`COM*`/`LPT*` set.
const WINDOWS_RESERVED_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
    "CONOUT$",
];

/// Windows additionally reserves these device-name spellings using the
/// Unicode superscript-digit forms — `COM¹` (U+00B9), `COM²` (U+00B2),
/// `COM³` (U+00B3), and the `LPT` equivalents — as aliases for
/// `COM1`-`COM3` and `LPT1`-`LPT3` respectively; see
/// <https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file>.
/// Matched against the component's **stem**, exactly like
/// [`WINDOWS_RESERVED_DEVICE_NAMES`], but as an exact Unicode string rather
/// than ASCII case-folded: a digit has no case variant, so there is nothing
/// to fold.
const WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS: &[&str] =
    &["COM\u{00B9}", "COM\u{00B2}", "COM\u{00B3}", "LPT\u{00B9}", "LPT\u{00B2}", "LPT\u{00B3}"];

/// See [`WINDOWS_RESERVED_DEVICE_NAMES`] and
/// [`WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS`]. ASCII case-folded for the
/// former, exact-match for the latter, matching this module's other
/// predicates.
fn is_windows_reserved_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    WINDOWS_RESERVED_DEVICE_NAMES.iter().any(|reserved| stem.eq_ignore_ascii_case(reserved))
        || WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS.contains(&stem)
}

/// Every character Win32's `CreateFile` family refuses outright in a
/// filename, everywhere, on every Windows version — `<`, `>`, `"`, `|`,
/// `?`, `*` — plus `:`, which Win32 accepts syntactically but reinterprets
/// as the alternate-data-stream separator rather than an ordinary
/// character (see [`wire_component_is_non_portable`]'s doc comment for why
/// `:` is grouped with these rather than treated identically to them).
/// Each of `< > " | ? *` is a perfectly ordinary, legal character in a
/// Linux/macOS filename. Deliberately narrow: this is exactly Win32's own
/// reserved set, not every character a cautious tool might avoid (a
/// forward slash or backslash can never reach this function at all — see
/// [`wire_path_components`]). ASCII control characters are a distinct,
/// separately documented check below (see
/// [`contains_ascii_control_character`]) rather than folded into this list,
/// since they are a whole class rather than a fixed set of symbols.
const WINDOWS_RESERVED_FILENAME_CHARS: &[char] = &['<', '>', '"', '|', '?', '*'];

/// Whether `component` contains a byte in `U+0001`..=`U+001F` — every ASCII
/// control character except NUL (`U+0000`; already excluded from a wire
/// path elsewhere, and not a printable filename character on any
/// platform). Win32's `CreateFile` family refuses every one of these in a
/// filename outright, on every Windows version, the same "permanent
/// platform split, no aliasing" hazard as
/// [`is_windows_reserved_device_name`]: a path containing one materializes
/// on Linux/macOS (where control characters are legal, if unusual, filename
/// bytes) but can never be created on any Windows device.
fn contains_ascii_control_character(component: &str) -> bool {
    component.bytes().any(|b| (0x01..=0x1f).contains(&b))
}

/// Whether `component`'s stem (the part before its first `.`) has the
/// *shape* Windows generates for an 8.3 short-name alias of a long
/// filename: `NAME~N`, where `NAME~N` together is at most 8 characters,
/// `N` is one or more ASCII digits, and everything before the last `~` is
/// non-empty. The optional extension (the part after the first `.`, if
/// any) must itself be a single component of at most 3 ASCII characters
/// with no further `.` — 8.3 names have exactly one dot.
///
/// This is a **shape** match, not a computation of the actual alias: see
/// [`wire_component_is_non_portable`]'s doc comment for why the real
/// algorithm cannot be evaluated host-independently, and why refusing the
/// shape is the predicate this module can actually stand behind. It is
/// deliberately over-inclusive within that shape (it does not further
/// restrict which characters may appear before the `~`, and accepts any
/// digit run after it, even lengths Windows would never actually generate)
/// — the false-positive cost of that breadth is exactly what this
/// function's caller's doc comment weighs and accepts.
fn has_short_name_alias_shape(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    if stem.is_empty() || stem.len() > 8 || !stem.is_ascii() {
        return false;
    }
    let Some(tilde_pos) = stem.rfind('~') else { return false };
    if tilde_pos == 0 {
        return false;
    }
    let digits = &stem[tilde_pos + 1..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let rest = &component[stem.len()..];
    if rest.is_empty() {
        return true;
    }
    let Some(ext) = rest.strip_prefix('.') else { return false };
    !ext.is_empty() && ext.len() <= 3 && ext.is_ascii() && !ext.contains('.')
}

/// Whether a single wire-path component cannot be faithfully, unambiguously
/// stored on every platform this group may sync to. Several independent
/// Windows-specific hazards, all folded into one predicate because they
/// share the same fix (refuse identically, regardless of which platform
/// runs the check), even though they split into two different harm
/// classes:
///
/// **Aliasing** — two distinct peer-authored paths land on ONE Windows
/// on-disk object, so admitting both as independent index rows lets
/// whichever materializes second silently overwrite the other with no
/// conflict ever detected (see [`path_has_non_portable_wire_component`]'s
/// doc comment for the full mechanism):
/// - A literal `:` anywhere in the component. Windows parses `:` as the
///   alternate-data-stream separator (`filename:stream`), addressing a
///   stream *on* `filename` — not a distinct file. Two independent-looking
///   peer-authored paths `"notes"` and `"notes:draft"` are both ordinary,
///   independent files on Linux/macOS (where `:` is just a character), but
///   a Windows materializer resolves the second one onto the first one's
///   own data stream. (A drive-qualified first segment such as `"C:"` or
///   `"C:foo"` is already rejected earlier, by `change::validate_path`;
///   this check is broader — it also catches a `:` anywhere inside a
///   component, not only that one position-specific shape.)
/// - Trailing `.`/` ` stripping (see
///   [`strip_windows_trailing_normalization`]): a component that is not
///   byte-identical to its own stripped form is not portable — a Windows
///   materializer stores it under a *different* name than the one on the
///   wire, which is how e.g. `"a"` and `"a "` collide.
/// - [`has_short_name_alias_shape`]: on an NTFS volume with 8.3 short-name
///   generation enabled (still the default on the Windows system volume),
///   materializing a long filename also creates an automatically generated
///   short alias for it, and a *separate* peer-authored path equal to that
///   alias then resolves to the same on-disk object as the long name — two
///   independent-looking index rows collide into one file the moment the
///   long name materializes on Windows, exactly the same harm as the
///   trailing-dot/space case, just triggered by a second, unrelated path
///   rather than a suffix on the same one. Unlike every other check here,
///   the actual generated alias is not something this predicate can
///   compute: the algorithm depends on the numeric-tail collision count
///   already present in the target directory (state a peer proposing a
///   change cannot observe) and on whether 8.3 generation is even enabled
///   on the eventual target volume (a per-volume, changeable setting, not
///   a property of the path). Neither is available, or stable, at
///   admission time, and a check that could disagree with itself across
///   peers or across time would violate this module's basic contract that
///   every peer reach the identical verdict for the identical wire path.
///   So instead of computing the alias, this refuses any component with
///   the *shape* an alias always has (`NAME~N` or `NAME~N.EXT`, at most 8
///   characters before the extension): no long name can ever coincide with
///   an authored path in that shape, so no alias of it can either. The
///   cost is real and accepted deliberately: a POSIX file genuinely named
///   e.g. `REPORT~1.TXT` is not exotic, and this makes it permanently
///   unsyncable for the whole group, forever, even for a group with no
///   Windows member and no 8.3 generation anywhere in it. That is the same
///   trade this module already makes for a reserved device name or a
///   trailing dot — refuse a look-alike rather than risk the silent
///   collision — applied to a shape that is admittedly far more likely to
///   occur in real, intentional filenames than `CON` or a trailing space
///   is.
///
/// **Permanent platform split, no aliasing** — Windows does not
/// silently rename these, it refuses to create them at all,
/// deterministically, every time. There is no on-disk collision to cause,
/// but admitting the path still splits the group along platform lines
/// exactly as [`wire_path_components`]'s own doc comment reasons about for
/// a drive-qualified path: a change every non-Windows member accepts and
/// materializes forever is one every Windows member can never materialize,
/// forever — and (separately) the index row it leaves behind on that
/// Windows device can never match a disk entry, the identical
/// index/disk-divergence shape as the aliasing cases, just triggered by an
/// outright creation failure instead of a silent rename:
/// - [`is_windows_reserved_device_name`]: the component names a reserved
///   Windows device, including the Unicode superscript-digit spellings of
///   `COM1`-`COM3`/`LPT1`-`LPT3` (see
///   [`WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS`]) as well as the ASCII
///   ones.
/// - [`WINDOWS_RESERVED_FILENAME_CHARS`]: the component contains a
///   character Win32 refuses in a filename outright.
/// - [`contains_ascii_control_character`]: the component contains an ASCII
///   control character (`U+0001`-`U+001F`), which Win32 also refuses
///   outright in a filename.
///
/// General portability predicate, not specific to the reserved-artefact
/// namespace the rest of this module owns: it applies to *any*
/// peer-authored path, not only look-alikes of a reserved name. The
/// artefact predicate ([`is_artefact_wire_component`]) only asks "does
/// this look like one of our own reserved names"; this one asks "can this
/// path be faithfully, unambiguously stored on every member's platform at
/// all."
///
/// Deliberately does NOT reject: a case-only collision (`"Notes.txt"` vs
/// `"notes.txt"`, which collide on Windows/macOS's default case-insensitive
/// filesystems but not on Linux) — a real, but different-shaped hazard
/// this codebase already has dedicated machinery for (see `hazard.rs`'s
/// and `peer_session.rs`'s case-fold-sibling handling), not a "refuse the
/// path outright" fix. Nor a path-length limit (historic Windows `MAX_PATH`
/// is opt-in-extendable per-device today, so unlike every check above it
/// does not fail identically on every Windows install — rejecting for it
/// here would sacrifice a file for a group whose Windows members may all
/// have long-path support enabled). Nor a leading or interior space/dot,
/// or any other whitespace: Win32 only strips a *trailing* one; everything
/// else round-trips exactly and is left alone.
fn wire_component_is_non_portable(component: &str) -> bool {
    if component.contains(':')
        || component.chars().any(|c| WINDOWS_RESERVED_FILENAME_CHARS.contains(&c))
        || contains_ascii_control_character(component)
    {
        return true;
    }
    if is_windows_reserved_device_name(component) {
        return true;
    }
    if has_short_name_alias_shape(component) {
        return true;
    }
    strip_windows_trailing_normalization(component) != component
}

/// Whether any component of a peer-authored path **string** cannot be
/// faithfully, unambiguously stored on every platform this group may sync
/// to — see [`wire_component_is_non_portable`] for the hazards (two harm
/// classes) this folds together. Splits on both `/` and `\` (see
/// [`wire_path_components`])
/// for the same host-independence reason as
/// [`path_has_artefact_component_in_wire_path`]: whether a path is
/// portable cannot depend on which platform happens to be running the
/// check, so every peer in a group — DAG admission
/// (`dag_store::admit_change`) and, as defense-in-depth, peer
/// materialization (`PeerSyncSession::materialize`) — must reach the
/// identical verdict for the identical wire path.
///
/// Without the trailing-dot/space and colon checks specifically, two
/// distinct logical paths that alias to one Windows filesystem name (e.g.
/// `"a"` / `"a "`, or `"notes"` / `"notes:draft"`) are both admitted as
/// independent index rows, and silently collide onto the same on-disk
/// object the moment either one materializes on a Windows device —
/// whichever writes second overwrites the other's bytes with no conflict
/// ever detected (they are different paths, so no DAG conflict machinery
/// ever compares them), while the index keeps believing both are
/// correctly, independently `Hydrated`. Refusing the path at admission is
/// what prevents that divergence from ever being created in the first
/// place.
pub fn path_has_non_portable_wire_component(path: &str) -> bool {
    wire_path_components(path).any(wire_component_is_non_portable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_each_kind_round_trip() {
        for kind in ArtefactKind::ALL {
            let name = artefact_component_name(kind, "abc123").unwrap();
            let (parsed_kind, id) = parse_artefact_component(&name).unwrap();
            assert_eq!(parsed_kind, kind);
            assert_eq!(id, "abc123");
        }
    }

    #[test]
    fn recognizes_each_kind_as_reserved() {
        for kind in ArtefactKind::ALL {
            let name = artefact_component_name(kind, "id").unwrap();
            assert!(is_reserved_component(OsStr::new(&name)), "{name} should be reserved");
            assert_eq!(
                classify_component(OsStr::new(&name)),
                Some(ReservedComponent::Artefact { kind, id: "id" })
            );
        }
    }

    #[test]
    fn case_folded_ascii_only() {
        assert!(is_reserved_component(OsStr::new(".YADORILINK-V1-STAGE.x")));
        assert!(is_reserved_component(OsStr::new(".Yadorilink-V1-Preimage.42")));
        let (kind, id) = parse_artefact_component(".YADORILINK-V1-BACKUP.id7").unwrap();
        assert_eq!(kind, ArtefactKind::Backup);
        assert_eq!(id, "id7");
    }

    #[test]
    fn whole_component_matching_not_substring() {
        // A user file that merely contains the marker text is not reserved —
        // only a component that *is* the artefact name.
        assert!(!is_reserved_component(OsStr::new("notes.yadorilink-v1-stage.x.txt")));
        assert!(!is_reserved_component(OsStr::new("prefix.yadorilink-v1-stage.x")));
        assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-stage.x.suffix")));
    }

    /// Windows drops trailing `.`/` ` in most Win32 path APIs, so a peer
    /// that spells the reserved name with one trailing dot or space types
    /// a name that is not literally the reserved name but lands on disk,
    /// on a Windows device, as exactly the reserved name. The predicate
    /// must catch it regardless of which platform is running the check.
    #[test]
    fn trailing_dot_or_space_still_classifies_as_the_artefact() {
        let base = artefact_component_name(ArtefactKind::Stage, "abc").unwrap();

        let trailing_space = format!("{base} ");
        assert!(is_artefact_component(OsStr::new(&trailing_space)));
        assert_eq!(
            classify_component(OsStr::new(&trailing_space)),
            Some(ReservedComponent::Artefact { kind: ArtefactKind::Stage, id: "abc" })
        );

        let trailing_dot = format!("{base}.");
        assert!(is_artefact_component(OsStr::new(&trailing_dot)));
        assert_eq!(
            classify_component(OsStr::new(&trailing_dot)),
            Some(ReservedComponent::Artefact { kind: ArtefactKind::Stage, id: "abc" })
        );

        // Multiple trailing dots/spaces, and a mix of both, still strip down
        // to the reserved name.
        let trailing_mix = format!("{base}. . ");
        assert!(is_artefact_component(OsStr::new(&trailing_mix)));

        // A LEADING dot/space is not Windows trailing normalization and
        // must not be stripped — this is not the same bug in reverse.
        let leading_space = format!(" {base}");
        assert!(!is_artefact_component(OsStr::new(&leading_space)));
    }

    #[test]
    fn unknown_kind_token_is_not_reserved() {
        assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-bogus.x")));
        // No id at all is not a valid artefact name.
        assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-stage.")));
        assert!(!is_reserved_component(OsStr::new(".yadorilink-v1-stage")));
    }

    #[test]
    fn nested_component_makes_whole_path_reserved() {
        let path = Path::new("a/b/.yadorilink-v1-preimage.deadbeef/c.txt");
        assert!(path_has_reserved_component(path));
        assert!(!path_has_reserved_component(Path::new("a/b/c.txt")));
    }

    #[test]
    fn length_bound_is_an_error_not_a_truncation() {
        let long_id = "x".repeat(MAX_COMPONENT_BYTES);
        match artefact_component_name(ArtefactKind::Stage, &long_id) {
            Err(ArtefactNameError::TooLong { id, actual_bytes }) => {
                assert_eq!(id, long_id);
                assert!(actual_bytes > MAX_COMPONENT_BYTES);
            }
            other => panic!("expected TooLong, got {other:?}"),
        }

        let short_id = "x".repeat(4);
        assert!(artefact_component_name(ArtefactKind::Stage, &short_id).is_ok());
    }

    #[test]
    fn id_alphabet_is_restricted_so_reparsing_is_unambiguous() {
        assert!(matches!(
            artefact_component_name(ArtefactKind::Stage, "has.dot"),
            Err(ArtefactNameError::InvalidId { .. })
        ));
        assert!(matches!(
            artefact_component_name(ArtefactKind::Stage, "has/slash"),
            Err(ArtefactNameError::InvalidId { .. })
        ));
        assert!(matches!(
            artefact_component_name(ArtefactKind::Stage, ""),
            Err(ArtefactNameError::InvalidId { .. })
        ));
        assert!(artefact_component_name(ArtefactKind::Stage, "abc-123_XYZ").is_ok());
    }

    #[test]
    fn legacy_marker_is_reserved_but_distinguishable() {
        let legacy_name = "report.yadorilink-tmp.12345.7";
        assert!(is_reserved_component(OsStr::new(legacy_name)));
        assert_eq!(classify_component(OsStr::new(legacy_name)), Some(ReservedComponent::Legacy));

        // Case-folded too.
        assert!(is_reserved_component(OsStr::new("REPORT.YADORILINK-TMP.12345.7")));

        // Never confused with a versioned artefact.
        let v1_name = artefact_component_name(ArtefactKind::Backup, "id").unwrap();
        assert_ne!(classify_component(OsStr::new(&v1_name)), Some(ReservedComponent::Legacy));
    }

    #[test]
    fn path_level_finds_the_specific_component() {
        let path = Path::new("dir/report.yadorilink-tmp.1.2/leaf.txt");
        assert_eq!(find_reserved_component(path), Some(ReservedComponent::Legacy));
    }

    /// The rejection predicate (`is_artefact_component`/
    /// `path_has_artefact_component`) must be `false` for a legacy-marked
    /// path even though the exclusion predicate
    /// (`is_reserved_component`/`path_has_reserved_component`) is `true`
    /// for the same path — see the module doc's "Two predicates, not one"
    /// section. This is what lets DAG admission and peer materialization
    /// (which must key on the rejection predicate) leave a legacy-marked
    /// path alone, while the watcher/scan/import (which key on exclusion)
    /// still keep it out of ordinary sync. Mutation-checked: this fails if
    /// either call site is pointed back at `path_has_reserved_component`.
    #[test]
    fn artefact_predicate_excludes_the_legacy_marker() {
        let legacy_name = "report.yadorilink-tmp.12345.7";
        assert!(!is_artefact_component(OsStr::new(legacy_name)));
        assert!(is_reserved_component(OsStr::new(legacy_name)));

        let legacy_path = Path::new("dir/report.yadorilink-tmp.1.2/leaf.txt");
        assert!(!path_has_artefact_component(legacy_path));
        assert!(path_has_reserved_component(legacy_path));

        // A versioned artefact is caught by both.
        let v1_name = artefact_component_name(ArtefactKind::Stage, "id").unwrap();
        assert!(is_artefact_component(OsStr::new(&v1_name)));
        assert!(is_reserved_component(OsStr::new(&v1_name)));
    }

    /// NTFS `filename::$DATA` addresses `filename`'s own default stream —
    /// the same on-disk object — and `filename:stream:$DATA` addresses a
    /// named stream on it; both mutate `filename` itself. Neither is
    /// component-exact against the un-suffixed reserved name, so the wire
    /// predicate must strip the ADS suffix before matching, or a peer can
    /// alias the artefact without ever spelling its exact name.
    #[test]
    fn wire_predicate_strips_an_alternate_data_stream_suffix() {
        let base = artefact_component_name(ArtefactKind::Stage, "deadbeef").unwrap();

        let default_stream = format!("{base}::$DATA");
        assert!(is_artefact_wire_component(&default_stream));
        assert!(path_has_artefact_component_in_wire_path(&default_stream));

        let named_stream = format!("{base}:payload:$DATA");
        assert!(is_artefact_wire_component(&named_stream));
        assert!(path_has_artefact_component_in_wire_path(&format!("some/dir/{named_stream}")));

        // The un-suffixed name is unaffected.
        assert!(is_artefact_wire_component(&base));
    }

    /// `change::validate_path` accepts both `/` and `\` as separators, so
    /// component boundaries in a wire path must not depend on which OS is
    /// running the check — using the host `Path` type here would make
    /// `safe\.yadorilink-v1-stage.x` one component on Unix (admitted) and
    /// two on Windows (rejected), splitting the group along platform
    /// lines. The wire predicate must reject it on every host.
    #[test]
    fn wire_predicate_splits_on_both_separators_regardless_of_host() {
        let artefact = artefact_component_name(ArtefactKind::Preimage, "cafef00d").unwrap();

        let backslash_path = format!("safe\\{artefact}");
        assert!(
            path_has_artefact_component_in_wire_path(&backslash_path),
            "a backslash-delimited artefact component must be found on every host"
        );

        let forward_slash_path = format!("safe/{artefact}");
        assert!(path_has_artefact_component_in_wire_path(&forward_slash_path));

        // An ORDINARY backslash-containing path (no reserved component at
        // all) must classify identically regardless of host: not reserved
        // either way. This is the direct converse of the split-brain bug —
        // proving the predicate doesn't just reject everything with a
        // backslash in it.
        assert!(!path_has_artefact_component_in_wire_path("safe\\ordinary-file.txt"));
        assert!(!path_has_artefact_component_in_wire_path("safe/ordinary-file.txt"));
    }

    /// Converse of both wire tests above: the ADS-suffix and
    /// separator-splitting normalization must not widen the narrow
    /// artefact predicate into the broad exclusion predicate. A
    /// legacy-marker look-alike with either suffix, or split across a
    /// backslash, is still just a substring match and must not be
    /// reachable through the wire artefact predicate.
    #[test]
    fn wire_predicate_still_excludes_the_legacy_marker_with_ads_and_backslash_suffixes() {
        assert!(!is_artefact_wire_component("report.yadorilink-tmp.old::$DATA"));
        assert!(!path_has_artefact_component_in_wire_path("safe\\report.yadorilink-tmp.old"));
    }

    /// Same property as the test above, for the trailing-dot/space
    /// normalization instead of the ADS/backslash forms: it must not widen
    /// the narrow artefact predicate into the broad exclusion predicate
    /// either. A legacy-marker look-alike with a trailing space is still
    /// just a substring match and must not be reachable through the wire
    /// artefact predicate.
    ///
    /// Pinned directly against the artefact predicate, not through
    /// `dag_store::admit_change` or `PeerSyncSession::materialize`: at
    /// those entry points, `path_has_non_portable_wire_component`
    /// unconditionally refuses any trailing-dot/space path before the
    /// artefact-vs-legacy classification is ever reached (see
    /// `dag_store::tests::admit_change_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker`
    /// and its `peer_session` sibling), so this specific combination can no
    /// longer be exercised through the full pipeline — the artefact
    /// predicate's own narrower contract still holds independently of that,
    /// and is what this test pins.
    #[test]
    fn wire_predicate_still_excludes_the_legacy_marker_with_a_trailing_space() {
        assert!(!is_artefact_wire_component("report.yadorilink-tmp.old "));
    }

    #[test]
    fn non_portable_predicate_catches_trailing_dot_or_space() {
        assert!(path_has_non_portable_wire_component("a "));
        assert!(path_has_non_portable_wire_component("a."));
        assert!(path_has_non_portable_wire_component("dir. /leaf"));
        assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
    }

    #[test]
    fn non_portable_predicate_catches_a_literal_colon_anywhere_in_a_component() {
        assert!(path_has_non_portable_wire_component("notes:draft"));
        assert!(path_has_non_portable_wire_component("notes::$DATA"));
        assert!(path_has_non_portable_wire_component("dir/notes:draft"));
        assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
    }

    #[test]
    fn non_portable_predicate_catches_reserved_windows_device_names() {
        for name in [
            "CON", "con", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1", "lpt9", "CONIN$", "conin$",
            "CONOUT$", "conout$",
        ] {
            assert!(path_has_non_portable_wire_component(name), "{name} should be non-portable");
            assert!(
                path_has_non_portable_wire_component(&format!("{name}.txt")),
                "{name}.txt should be non-portable (matched by stem, not whole name)"
            );
        }
        // The reserved name must match the whole stem, not merely appear
        // within it — "CONTACT" is not "CON", and "economics.txt"'s stem
        // is not "COM9".
        assert!(!path_has_non_portable_wire_component("CONTACT.txt"));
        assert!(!path_has_non_portable_wire_component("economics.txt"));
    }

    #[test]
    fn non_portable_predicate_catches_win32_reserved_filename_characters() {
        for ch in ['<', '>', '"', '|', '?', '*'] {
            let path = format!("notes{ch}draft.txt");
            assert!(path_has_non_portable_wire_component(&path), "{path:?} should be non-portable");
        }
        assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
    }

    /// Win32 only strips a *trailing* dot or space — a leading or interior
    /// one round-trips exactly and must not be swept up by an overly broad
    /// "no spaces/dots" rule (that would make ordinary, working Unix
    /// filenames unsyncable for no reason).
    #[test]
    fn non_portable_predicate_leaves_leading_and_interior_whitespace_and_dots_alone() {
        assert!(!path_has_non_portable_wire_component(" leading-space.txt"));
        assert!(!path_has_non_portable_wire_component("two  spaces.txt"));
        assert!(!path_has_non_portable_wire_component("v1.2.3.txt"));
        assert!(!path_has_non_portable_wire_component(".hidden-dotfile"));
    }

    #[test]
    fn non_portable_predicate_catches_superscript_reserved_device_names() {
        for name in [
            "COM\u{00B9}",
            "COM\u{00B2}",
            "COM\u{00B3}",
            "LPT\u{00B9}",
            "LPT\u{00B2}",
            "LPT\u{00B3}",
        ] {
            assert!(path_has_non_portable_wire_component(name), "{name} should be non-portable");
            assert!(
                path_has_non_portable_wire_component(&format!("{name}.txt")),
                "{name}.txt should be non-portable (matched by stem)"
            );
        }
        // A superscript digit not among the reserved three, or trailing
        // rather than replacing an ASCII digit, is not a reserved spelling.
        assert!(!path_has_non_portable_wire_component("COM\u{2074}")); // superscript 4
        assert!(!path_has_non_portable_wire_component("COM1\u{00B9}"));
    }

    #[test]
    fn non_portable_predicate_catches_ascii_control_characters() {
        assert!(path_has_non_portable_wire_component("notes\u{0001}draft.txt"));
        assert!(path_has_non_portable_wire_component("notes\u{001f}draft.txt"));
        assert!(path_has_non_portable_wire_component("notes\tdraft.txt")); // U+0009, TAB
        assert!(!path_has_non_portable_wire_component("ordinary/path.txt"));
    }

    /// A Windows volume with 8.3 short-name generation enabled mints an
    /// automatic alias, shaped `NAME~N` or `NAME~N.EXT`, for any long
    /// filename it materializes. A separate peer-authored path spelled in
    /// exactly that shape can then resolve to the same on-disk object as
    /// the long name once it materializes — refusing the shape outright,
    /// rather than trying to compute the specific alias (see
    /// [`wire_component_is_non_portable`]'s doc comment for why the actual
    /// algorithm can't be evaluated host-independently), is what closes
    /// that gap.
    #[test]
    fn non_portable_predicate_catches_short_name_alias_shape() {
        assert!(path_has_non_portable_wire_component("REPORT~1.TXT"));
        assert!(path_has_non_portable_wire_component("report~1.txt"));
        assert!(path_has_non_portable_wire_component("REPORT~1"));
        // Prefix shrinks to keep the 8-character basename bound as the
        // numeric tail grows past a single digit.
        assert!(path_has_non_portable_wire_component("TEXTF~10.TXT"));
        assert!(path_has_non_portable_wire_component("dir/REPORT~1.TXT"));
    }

    /// The over-rejection direction: an ordinary filename that merely
    /// contains a tilde, or a tilde-digit run too long to be a real 8.3
    /// alias, must not be refused.
    #[test]
    fn non_portable_predicate_leaves_ordinary_tilde_names_alone() {
        // Not digits after the tilde.
        assert!(!path_has_non_portable_wire_component("my~notes.txt"));
        // Digits after the tilde, but the basename exceeds the 8-character
        // 8.3 bound, so it can never be a generated alias.
        assert!(!path_has_non_portable_wire_component("backup~2020.txt"));
        // A leading tilde has no prefix for the alias to have been
        // generated from.
        assert!(!path_has_non_portable_wire_component("~1.txt"));
        // More than one dot is not the single-extension 8.3 shape.
        assert!(!path_has_non_portable_wire_component("v~1.2.3.txt"));
        // An extension longer than three characters is not 8.3-shaped.
        assert!(!path_has_non_portable_wire_component("REPORT~1.TEXT"));
    }
}
