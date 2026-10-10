//! Where the Windows Cloud Files host put each provider root's sync root folder.
//!
//! A provider root has no directory the daemon reads, but the folder the user sees is a path
//! like any other, and a command that names a file in it (`yadorilink evict <path>`) has to be
//! turned into the root and the namespace path of that file. The host records every sync root
//! it serves as one `<root id hex>\t<folder path>` line in `%LOCALAPPDATA%\yadorilink\
//! cfapi_sync_roots.txt`, so a restarted host reconnects each root at the same place. The same
//! file answers this question, exactly, without re-deriving a folder name from a display name.

#![cfg_attr(not(windows), allow(dead_code))]

use std::path::PathBuf;

/// The host's record of its sync roots.
pub(crate) fn registry_file() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("yadorilink").join("cfapi_sync_roots.txt"))
}

/// `(root id hex, path relative to the root with `/` separators)` of an absolute path inside one
/// of the host's sync roots. `None` when no root holds it, or when it names the root itself.
pub(crate) fn locate(absolute_path: &str) -> Option<(String, String)> {
    let text = std::fs::read_to_string(registry_file()?).ok()?;
    locate_in(&text, absolute_path)
}

fn components(path: &str) -> Vec<String> {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    path.split(['\\', '/']).filter(|c| !c.is_empty()).map(str::to_lowercase).collect()
}

fn components_keeping_case(path: &str) -> Vec<String> {
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    path.split(['\\', '/']).filter(|c| !c.is_empty()).map(str::to_string).collect()
}

pub(crate) fn locate_in(registry: &str, absolute_path: &str) -> Option<(String, String)> {
    let wanted = components(absolute_path);
    let original = components_keeping_case(absolute_path);
    let mut best: Option<(&str, usize)> = None;
    for line in registry.lines() {
        let Some((root_id, root_path)) = line.split_once('\t') else { continue };
        let root = components(root_path.trim());
        if root.is_empty() || root.len() >= wanted.len() || wanted[..root.len()] != root[..] {
            continue;
        }
        if best.is_none_or(|(_, depth)| root.len() > depth) {
            best = Some((root_id.trim(), root.len()));
        }
    }
    let (root_id, depth) = best?;
    Some((root_id.to_string(), original[depth..].join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: &str = "aaaa\tC:\\Users\\me\\YadoriLink\\Photos\nbbbb\tC:\\Users\\me\\YadoriLink\\Photos (bbbb0001)\n\nbroken line\n";

    #[test]
    fn a_path_inside_a_sync_root_is_split_into_the_root_and_the_namespace_path() {
        assert_eq!(
            locate_in(REGISTRY, r"C:\Users\me\YadoriLink\Photos\docs\a.txt"),
            Some(("aaaa".into(), "docs/a.txt".into()))
        );
    }

    #[test]
    fn the_extended_length_prefix_and_letter_case_do_not_matter_but_the_namespace_path_keeps_its_case(
    ) {
        assert_eq!(
            locate_in(REGISTRY, r"\\?\c:\users\ME\yadorilink\photos\Docs\A.txt"),
            Some(("aaaa".into(), "Docs/A.txt".into()))
        );
    }

    #[test]
    fn a_sibling_folder_with_the_same_prefix_is_not_the_root() {
        assert_eq!(
            locate_in(REGISTRY, r"C:\Users\me\YadoriLink\Photos (bbbb0001)\x.txt"),
            Some(("bbbb".into(), "x.txt".into()))
        );
        assert_eq!(locate_in(REGISTRY, r"C:\Users\me\YadoriLink\PhotosX\x.txt"), None);
    }

    #[test]
    fn the_root_itself_and_unrelated_paths_are_not_items() {
        assert_eq!(locate_in(REGISTRY, r"C:\Users\me\YadoriLink\Photos"), None);
        assert_eq!(locate_in(REGISTRY, r"C:\Users\me\Documents\a.txt"), None);
    }
}
