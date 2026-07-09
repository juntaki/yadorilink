//! Diagnostics-bundle redaction helpers.
//!
//! This module is intentionally pure and daemon-independent: callers hand it a
//! JSON value or free-text field, and it applies the same conservative
//! denylist pass used for optional reporting before any support bundle is
//! previewed or written.

use serde_json::Value;

use crate::redact::{redact, RedactionCategory, RedactionSummary};

pub fn redact_diagnostics_text(text: &str) -> (String, RedactionSummary) {
    redact(text)
}

pub fn redact_diagnostics_value(value: &Value) -> (Value, RedactionSummary) {
    let mut summary = RedactionSummary::default();
    let redacted = redact_value(value, &mut summary);
    (redacted, summary)
}

fn redact_value(value: &Value, summary: &mut RedactionSummary) -> Value {
    match value {
        Value::String(text) => {
            let (redacted, text_summary) = redact_diagnostics_text(text);
            merge_summary(summary, text_summary);
            Value::String(redacted)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| redact_value(item, summary)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter().map(|(key, value)| (key.clone(), redact_value(value, summary))).collect(),
        ),
        other => other.clone(),
    }
}

fn merge_summary(into: &mut RedactionSummary, incoming: RedactionSummary) {
    for (category, count) in incoming.categories {
        match into.categories.iter_mut().find(|(existing, _)| *existing == category) {
            Some((_, existing_count)) => *existing_count += count,
            None => into.categories.push((category, count)),
        }
    }
}

pub fn diagnostics_summary_count(summary: &RedactionSummary, category: RedactionCategory) -> usize {
    summary
        .categories
        .iter()
        .find_map(|(existing, count)| (*existing == category).then_some(*count))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::redact::RedactionCategory;

    #[test]
    fn redacts_sensitive_diagnostics_text() {
        let text = "failed reading /Users/alice/Project/secret.txt with Bearer abcdefgh12345678 from 192.168.1.10";

        let (redacted, summary) = redact_diagnostics_text(text);

        assert!(!redacted.contains("/Users/alice"));
        assert!(!redacted.contains("secret.txt"));
        assert!(!redacted.contains("abcdefgh12345678"));
        assert!(!redacted.contains("192.168.1.10"));
        assert!(diagnostics_summary_count(&summary, RedactionCategory::HomeDirectory) >= 1);
        assert!(diagnostics_summary_count(&summary, RedactionCategory::BearerToken) >= 1);
        assert!(diagnostics_summary_count(&summary, RedactionCategory::IpAddress) >= 1);
    }

    #[test]
    fn redacts_nested_diagnostics_json_values() {
        let bundle = json!({
            "link": {
                "path": "/Users/alice/Documents/Private",
                "device_id": "11111111-2222-3333-4444-555555555555",
                "peer": "10.0.0.4:7444"
            },
            "logs": [
                "token Bearer abcdefgh12345678",
                "key AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            ]
        });

        let (redacted, summary) = redact_diagnostics_value(&bundle);
        let rendered = serde_json::to_string(&redacted).unwrap();

        assert!(!rendered.contains("/Users/alice"));
        assert!(!rendered.contains("Private"));
        assert!(!rendered.contains("11111111-2222-3333-4444-555555555555"));
        assert!(!rendered.contains("10.0.0.4"));
        assert!(!rendered.contains("abcdefgh12345678"));
        assert!(!rendered.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="));
        assert!(diagnostics_summary_count(&summary, RedactionCategory::HomeDirectory) >= 1);
        assert!(diagnostics_summary_count(&summary, RedactionCategory::UuidLikeId) >= 1);
        assert!(diagnostics_summary_count(&summary, RedactionCategory::WireguardKey) >= 1);
    }
}
