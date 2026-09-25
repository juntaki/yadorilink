//! Denylist safety pass: applied to every free-text field that ends up
//! in a report (sanitized log lines, backtraces) as a second line of
//! defense on top of allowlist construction. Redaction is
//! pattern-based and intentionally conservative — a false positive
//! (over-redacting something harmless) is an acceptable cost; a false
//! negative (letting something sensitive through) is not.

use std::sync::LazyLock;

use regex::Regex;

/// One category of sensitive pattern this pass can find and remove.
/// Kept as an enum (not a raw string) so a redaction summary can be
/// built from a `Vec<RedactionCategory>` without allocating category
/// labels ad hoc at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RedactionCategory {
    AbsolutePath,
    HomeDirectory,
    BearerToken,
    PrivateKeyBlock,
    WireguardKey,
    IpAddress,
    CredentialedUrl,
    UuidLikeId,
    EmailAddress,
}

impl RedactionCategory {
    pub fn placeholder(self) -> &'static str {
        match self {
            RedactionCategory::AbsolutePath => "[REDACTED_PATH]",
            RedactionCategory::HomeDirectory => "[REDACTED_HOME]",
            RedactionCategory::BearerToken => "[REDACTED_TOKEN]",
            RedactionCategory::PrivateKeyBlock => "[REDACTED_PRIVATE_KEY]",
            RedactionCategory::WireguardKey => "[REDACTED_KEY]",
            RedactionCategory::IpAddress => "[REDACTED_IP]",
            RedactionCategory::CredentialedUrl => "[REDACTED_URL]",
            RedactionCategory::UuidLikeId => "[REDACTED_ID]",
            RedactionCategory::EmailAddress => "[REDACTED_EMAIL]",
        }
    }
}

struct Pattern {
    category: RedactionCategory,
    regex: &'static LazyLock<Regex>,
}

// Order matters: more specific/greedy patterns run first so a narrower
// pattern isn't left to match a fragment a broader one would have
// consumed whole (e.g. a credentialed URL's host shouldn't also get
// caught piecemeal by the bare-IP pattern after the URL is already
// redacted).
static PRIVATE_KEY_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .unwrap()
});
static CREDENTIALED_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@[^\s]+").unwrap());
static BEARER_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bbearer\s+[A-Za-z0-9\-_.=]{8,}").unwrap());
// This device's keys (the Ed25519 signing key, and the coordination
// plane's legacy transport-key field, which now just carries a copy of
// it) are 32 raw bytes, base64-encoded with padding: exactly 44
// characters, always ending in a single `=`. This deliberately also
// matches other unrelated base64 blobs of the same shape — an accepted
// false positive per this module's doc comment. No trailing `\b`: `=`
// is a non-word character, so a word boundary can never reliably fire
// right after it (a following non-word character, e.g. a comma, gives
// a non-word-to-non-word transition, which `\b` does not consider a
// boundary) — the leading `\b` plus the fixed 43-char run and the
// single literal `=` are enough on their own to anchor the match.
static WIREGUARD_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9+/]{43}=").unwrap());
static WINDOWS_HOME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[A-Za-z]:\\Users\\[^\\\s]+").unwrap());
static UNIX_HOME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:/Users|/home)/[^/\s]+").unwrap());
static WINDOWS_ABSOLUTE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[A-Za-z]:\\[^\s\x00"]+"#).unwrap());
static UNIX_ABSOLUTE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/(?:[^/\s\x00]+/)+[^/\s\x00]+").unwrap());
static EMAIL_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap());
static UUID_LIKE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
});
static IP_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){3,7}\b",
    )
    .unwrap()
});

fn patterns() -> Vec<Pattern> {
    vec![
        Pattern { category: RedactionCategory::PrivateKeyBlock, regex: &PRIVATE_KEY_BLOCK },
        Pattern { category: RedactionCategory::CredentialedUrl, regex: &CREDENTIALED_URL },
        Pattern { category: RedactionCategory::BearerToken, regex: &BEARER_TOKEN },
        Pattern { category: RedactionCategory::WireguardKey, regex: &WIREGUARD_KEY },
        Pattern { category: RedactionCategory::HomeDirectory, regex: &WINDOWS_HOME },
        Pattern { category: RedactionCategory::HomeDirectory, regex: &UNIX_HOME },
        Pattern { category: RedactionCategory::EmailAddress, regex: &EMAIL_ADDRESS },
        Pattern { category: RedactionCategory::UuidLikeId, regex: &UUID_LIKE },
        Pattern { category: RedactionCategory::IpAddress, regex: &IP_ADDRESS },
        // Absolute paths run last: home-directory paths are a more
        // specific sub-case already handled above, but any REMAINING
        // absolute path (e.g. a synced folder outside $HOME) still
        // needs catching.
        Pattern { category: RedactionCategory::AbsolutePath, regex: &WINDOWS_ABSOLUTE_PATH },
        Pattern { category: RedactionCategory::AbsolutePath, regex: &UNIX_ABSOLUTE_PATH },
    ]
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionSummary {
    /// One entry per category actually matched, with the number of
    /// occurrences removed — shown to the user in a report preview so
    /// they can see *what kind* of thing was stripped without the tool
    /// having to show them the sensitive value itself.
    pub categories: Vec<(RedactionCategory, usize)>,
}

impl RedactionSummary {
    pub fn is_empty(&self) -> bool {
        self.categories.is_empty()
    }
}

/// Runs every denylist pattern over `text` in order and replaces each
/// match with that category's placeholder. Idempotent: redacting
/// already-redacted text is a no-op (placeholders don't match any
/// pattern).
pub fn redact(text: &str) -> (String, RedactionSummary) {
    let mut result = text.to_string();
    let mut summary = RedactionSummary::default();
    for pattern in patterns() {
        let count = pattern.regex.find_iter(&result).count();
        if count > 0 {
            result =
                pattern.regex.replace_all(&result, pattern.category.placeholder()).into_owned();
            summary.categories.push((pattern.category, count));
        }
    }
    (result, summary)
}

/// Convenience for redacting every string in a list (e.g. sanitized log
/// lines) and merging their summaries into one.
pub fn redact_lines(lines: &[String]) -> (Vec<String>, RedactionSummary) {
    let mut merged = RedactionSummary::default();
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        let (redacted, summary) = redact(line);
        out.push(redacted);
        for (category, count) in summary.categories {
            match merged.categories.iter_mut().find(|(c, _)| *c == category) {
                Some((_, existing)) => *existing += count,
                None => merged.categories.push((category, count)),
            }
        }
    }
    (out, merged)
}

#[cfg(test)]
mod tests;
