//! Denylist safety pass (design.md D5): applied to every free-text field
//! that ends up in a report (sanitized log lines, backtraces) as a
//! second line of defense on top of allowlist construction. Redaction is
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
// WireGuard keys are 32 raw bytes, base64-encoded with padding: exactly
// 44 characters, always ending in a single `=`. This deliberately also
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
mod tests {
    use super::*;

    #[test]
    fn redacts_unix_absolute_path() {
        let (out, summary) =
            redact("failed to read /var/log/yadorilink/daemon.log: permission denied");
        assert!(!out.contains("/var/log"));
        assert!(out.contains("[REDACTED_PATH]"));
        assert!(!summary.is_empty());
    }

    #[test]
    fn redacts_home_directory_fragment_before_generic_absolute_path() {
        let (out, _) = redact("scanning /Users/alice/Documents/secret-project failed");
        assert!(!out.contains("/Users/alice"));
        assert!(!out.contains("alice"));
    }

    #[test]
    fn redacts_windows_home_directory() {
        let (out, _) = redact(r"C:\Users\alice\AppData\Roaming\yadorilink\sync-state.sqlite3");
        assert!(!out.contains("alice"));
    }

    #[test]
    fn redacts_bearer_token() {
        let (out, summary) =
            redact("request failed: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef123456");
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::BearerToken));
    }

    #[test]
    fn redacts_pem_private_key_block() {
        let key =
            "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQ==\n-----END PRIVATE KEY-----";
        let (out, _) = redact(&format!("dumping state: {key}"));
        assert!(!out.contains("MIIBVQIBADANBgkqhkiG9w0BAQ"));
        assert!(out.contains("[REDACTED_PRIVATE_KEY]"));
    }

    #[test]
    fn redacts_wireguard_style_base64_key() {
        // A syntactically-plausible 32-byte base64 key (44 chars,
        // trailing `=`) — not a real key, just shaped like one.
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        assert_eq!(key.len(), 44);
        let (out, summary) = redact(&format!("peer key: {key}"));
        assert!(!out.contains(key));
        assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::WireguardKey));
    }

    #[test]
    fn redacts_ipv4_address() {
        let (out, _) = redact("connecting to peer at 203.0.113.42:51820 failed");
        assert!(!out.contains("203.0.113.42"));
    }

    #[test]
    fn redacts_credentialed_url() {
        let (out, _) = redact("could not reach https://user:hunter2@relay.example.com/ws");
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("user:hunter2"));
    }

    #[test]
    fn redacts_uuid_like_device_or_group_id() {
        let (out, summary) =
            redact("device 11111111-2222-3333-4444-555555555555 is not authorized");
        assert!(!out.contains("11111111-2222-3333-4444-555555555555"));
        assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::UuidLikeId));
    }

    #[test]
    fn redacts_email_address() {
        let (out, _) = redact("account owner: alice@example.com");
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn leaves_clean_text_completely_unchanged() {
        let text = "sync failed: block hash mismatch on 4 of 12 chunks, retrying with backoff";
        let (out, summary) = redact(text);
        assert_eq!(out, text);
        assert!(summary.is_empty());
    }

    #[test]
    fn redaction_is_idempotent() {
        let text = "user alice@example.com hit /Users/alice/project with token Bearer abcd12345678";
        let (once, _) = redact(text);
        let (twice, summary_twice) = redact(&once);
        assert_eq!(once, twice);
        assert!(
            summary_twice.is_empty(),
            "re-redacting already-redacted text should find nothing new"
        );
    }

    #[test]
    fn redact_lines_merges_categories_across_multiple_lines() {
        let lines = vec![
            "line one: /Users/alice/secret".to_string(),
            "line two: token Bearer abcdefgh12345678".to_string(),
        ];
        let (out, summary) = redact_lines(&lines);
        assert_eq!(out.len(), 2);
        assert!(!out[0].contains("alice"));
        assert!(!out[1].contains("abcdefgh12345678"));
        assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::HomeDirectory));
        assert!(summary.categories.iter().any(|(c, _)| *c == RedactionCategory::BearerToken));
    }

    #[test]
    fn known_sensitive_example_fixture_produces_no_leaked_substrings() {
        // Task 1.6's "sensitive-pattern redaction" snapshot check, and
        // task 6.4's privacy-focused regression fixture, in one place:
        // a synthetic log line carrying one of every sensitive category
        // this module claims to catch, asserted to be fully gone after
        // redaction.
        let sensitive_fixture = concat!(
            "panic in sync engine while processing /Users/alice/Documents/taxes.pdf ",
            "for device 11111111-2222-3333-4444-555555555555, ",
            "peer at 203.0.113.42, ",
            "auth Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop, ",
            "wg key AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=, ",
            "reported by alice@example.com, ",
            "relay https://user:hunter2@relay.example.com"
        );
        let (out, summary) = redact(sensitive_fixture);
        let leaked = [
            "alice",
            "taxes.pdf",
            "11111111-2222-3333-4444-555555555555",
            "203.0.113.42",
            "eyJhbGciOiJIUzI1NiJ9.abcdefghijklmnop",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "hunter2",
        ];
        for needle in leaked {
            assert!(!out.contains(needle), "fixture leaked sensitive substring: {needle}");
        }
        assert!(summary.categories.len() >= 6, "expected most categories to fire on this fixture");
    }
}
