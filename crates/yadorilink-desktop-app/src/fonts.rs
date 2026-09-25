//! Finding a font that can actually draw the text this app displays.
//!
//! `egui`'s built-in fonts are Latin-only. Every window in this crate
//! showed a row of `□` for anything outside that range -- a folder whose
//! name is in Japanese, a device someone named in their own language, the
//! path either of those sits under. The user's own folder names are the
//! first thing they see, so this is not an edge case for them.
//!
//! ## Why the system font rather than a bundled one
//!
//! A full CJK face is over ten megabytes per weight, which is a poor trade
//! against a binary that otherwise ships nothing of the sort. macOS,
//! Windows and mainstream Linux desktops all carry one already, so
//! searching for it costs nothing at runtime and nothing at download.
//!
//! ## Why coverage is PROVEN rather than assumed
//!
//! Finding a file, or matching a family name, does not establish that the
//! glyphs are there: `Hiragino Sans GB` and `AppleSDGothicNeo` both sit in
//! the same directory as the Japanese faces and both look like plausible
//! matches by name. So every candidate is parsed and asked, glyph by
//! glyph, whether it can draw a probe string, and one that cannot is
//! discarded. The question goes to `ab_glyph`, which is the rasteriser
//! `epaint` itself uses, so the answer is the one the renderer would give
//! rather than a second opinion that could disagree with it.
//!
//! `egui`'s own `Fonts::has_glyphs` would be the obvious way to ask, but
//! it panics before the first `Context::run()`, which is exactly when a
//! font has to be chosen.
//!
//! Matching by file NAME is avoided for a second reason: macOS stores
//! `ヒラギノ角ゴシック W3.ttc` in NFD, so the obvious composed-form
//! comparison misses the very files being looked for.
//!
//! ## Why a failure is recorded rather than swallowed
//!
//! If no candidate covers the probe, the app keeps running with Latin-only
//! text and writes that fact to [`STATUS_FILE_NAME`] in the config
//! directory, which `yadorilink diagnose` reports. Without that, a machine
//! with no CJK font renders exactly the same unexplained `□` as before,
//! except now with the false comfort that fonts are "handled".

use std::path::{Path, PathBuf};

use eframe::egui;

/// Written on every window startup so `yadorilink diagnose` can report
/// what the UI actually resolved, including the failure case.
pub const STATUS_FILE_NAME: &str = "desktop-font-status.json";

/// Characters the chosen font has to be able to draw.
///
/// Kana and kanji are separate coverage questions -- a Chinese face
/// carries the han characters and none of the kana -- so both are probed,
/// along with the full-width bracket that shows up in device names and the
/// Hangul and Cyrillic that would otherwise fail silently for other users.
const PROBE: &str = "高橋さんの（開発用）한글Кириллица";

/// The family name registered for the fallback face.
const FAMILY: &str = "system-cjk";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A font covering [`PROBE`] was found and installed.
    Installed { path: PathBuf, face_index: u32 },
    /// Nothing on this machine covered [`PROBE`]. Text outside the Latin
    /// range will render as `□`.
    NotFound { searched: Vec<PathBuf>, examined: usize },
}

impl Outcome {
    pub fn installed_path(&self) -> Option<&Path> {
        match self {
            Outcome::Installed { path, .. } => Some(path),
            Outcome::NotFound { .. } => None,
        }
    }
}

/// Directories to search, in preference order.
///
/// Deliberately directories rather than file paths: the exact file names
/// differ between OS versions and locales, and a hard-coded list of names
/// is the thing that breaks quietly on the next release.
fn font_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if cfg!(target_os = "macos") {
        dirs.push(PathBuf::from("/System/Library/Fonts"));
        dirs.push(PathBuf::from("/System/Library/Fonts/Supplemental"));
        dirs.push(PathBuf::from("/Library/Fonts"));
    } else if cfg!(target_os = "windows") {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        dirs.push(PathBuf::from(root).join("Fonts"));
    } else {
        dirs.push(PathBuf::from("/usr/share/fonts"));
        dirs.push(PathBuf::from("/usr/local/share/fonts"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        if cfg!(target_os = "macos") {
            dirs.push(home.join("Library/Fonts"));
        } else {
            dirs.push(home.join(".local/share/fonts"));
            dirs.push(home.join(".fonts"));
        }
    }
    dirs
}

/// Font files under `dir`, recursively, newest-path-order-independent
/// (sorted, so the choice is the same on every run rather than whatever
/// order the filesystem hands back).
///
/// Recursion is bounded: Linux font directories nest a couple of levels
/// (`/usr/share/fonts/opentype/noto/...`), and an unbounded walk of an
/// arbitrary directory is not something a UI startup path should do.
fn font_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 3 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut here: Vec<PathBuf> = Vec::new();
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if matches!(ext.as_str(), "ttf" | "ttc" | "otf" | "otc") {
            here.push(path);
        }
    }
    here.sort();
    subdirs.sort();
    out.append(&mut here);
    for sub in subdirs {
        font_files(&sub, depth + 1, out);
    }
}

/// Files worth trying first.
///
/// Only an ordering hint, never a filter: anything not matched here is
/// still tried afterwards. The names are matched case-insensitively
/// against the ASCII portion of the file name, so a locale-specific name
/// this list has never heard of simply sorts later instead of being
/// skipped.
///
/// A known consequence, kept deliberately: on a Japanese macOS the
/// Hiragino faces are stored under Japanese file names, which no ASCII
/// hint can match, so the search settles on `Arial Unicode` instead --
/// a complete Unicode face that renders the text correctly, just not the
/// one the platform would have picked. Matching those names properly
/// means normalising NFD and folding voiced kana, which is a lot of
/// machinery to buy a nicer typeface; coverage is what this module
/// guarantees, and coverage is satisfied either way.
const PREFERRED_HINTS: [&str; 10] = [
    "hiragino",
    "notosanscjk",
    "noto sans cjk",
    "notoserifcjk",
    "sourcehansans",
    "yugoth",
    "meiryo",
    "msgothic",
    "arial unicode",
    "pingfang",
];

fn preference_rank(path: &Path) -> usize {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    PREFERRED_HINTS
        .iter()
        .position(|hint| name.contains(&hint.replace(['-', '_', ' '], "")))
        .unwrap_or(PREFERRED_HINTS.len())
}

/// Installs a font that can draw [`PROBE`], if this machine has one.
///
/// Call once per window, right after the `egui::Context` exists and before
/// the first frame. Every window in this crate runs in its own process
/// with its own context, so "once at startup" means once per window.
pub fn install(ctx: &egui::Context) -> Outcome {
    let dirs = font_dirs();
    let mut candidates: Vec<PathBuf> = Vec::new();
    for dir in &dirs {
        font_files(dir, 0, &mut candidates);
    }
    candidates.sort_by_key(|path| (preference_rank(path), path.clone()));

    let mut examined = 0usize;
    for path in &candidates {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        // A collection holds several faces; only the first is tried. A
        // family whose FIRST face lacks the probe is not one to fall back
        // on anyway, and walking every face of every font file on the
        // machine is not a cost a window opening should pay.
        examined += 1;
        if covers_probe(&bytes, 0) {
            install_face(ctx, bytes, 0);
            tracing::info!(font = %path.display(), "installed a system font for non-Latin text");
            let outcome = Outcome::Installed { path: path.clone(), face_index: 0 };
            write_status(&outcome);
            return outcome;
        }
    }

    tracing::warn!(
        searched = ?dirs,
        examined,
        "no system font on this machine can draw non-Latin text; it will render as boxes"
    );
    let outcome = Outcome::NotFound { searched: dirs, examined };
    write_status(&outcome);
    outcome
}

/// Whether this face can draw every character of [`PROBE`].
///
/// `glyph_id` returns id 0 -- the `.notdef` box -- for a character the
/// face has no glyph for, which is precisely the `□` this whole module
/// exists to stop rendering.
fn covers_probe(bytes: &[u8], index: u32) -> bool {
    use ab_glyph::Font as _;
    let Ok(font) = ab_glyph::FontRef::try_from_slice_and_index(bytes, index) else {
        return false;
    };
    PROBE.chars().all(|c| font.glyph_id(c).0 != 0)
}

/// Registers `bytes` as the fallback face for both built-in families.
fn install_face(ctx: &egui::Context, bytes: Vec<u8>, index: u32) {
    let mut defs = egui::FontDefinitions::default();
    defs.font_data.insert(
        FAMILY.to_string(),
        egui::FontData { font: bytes.into(), index, tweak: egui::FontTweak::default() },
    );
    // Appended, not prepended: the built-in Latin face stays the first
    // choice so ASCII text keeps the metrics the layout was built around,
    // and this face is consulted only for what that one cannot draw.
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        defs.families.entry(family).or_default().push(FAMILY.to_string());
    }
    ctx.set_fonts(defs);
}

/// Records the outcome where `yadorilink diagnose` can read it.
///
/// Best-effort: a UI that cannot write its diagnostics file still has to
/// open. The failure is logged rather than propagated, because the caller
/// has nothing useful to do with it either.
fn write_status(outcome: &Outcome) {
    let payload = match outcome {
        Outcome::Installed { path, face_index } => serde_json::json!({
            "schema_version": 1,
            "resolved": true,
            "path": path.to_string_lossy(),
            "face_index": face_index,
        }),
        Outcome::NotFound { searched, examined } => serde_json::json!({
            "schema_version": 1,
            "resolved": false,
            "searched": searched.iter().map(|d| d.to_string_lossy()).collect::<Vec<_>>(),
            "examined": examined,
            "consequence": "text outside the Latin range renders as boxes",
        }),
    };
    let dir = crate::ipc_client::config_dir_public();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::debug!(error = %e, "could not create the config directory for the font status");
        return;
    }
    if let Err(e) = std::fs::write(dir.join(STATUS_FILE_NAME), payload.to_string()) {
        tracing::debug!(error = %e, "could not record the font status");
    }
}

#[cfg(test)]
mod tests;
