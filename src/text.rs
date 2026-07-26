//! Small dependency-free text utilities shared by the checks.
//!
//! These are deliberately hand-rolled rather than regex-backed: the patterns
//! are few and fixed, and keeping `regex` out of the tree keeps the dependency
//! story short enough to fit in a README paragraph (which is itself one of the
//! things this tool asks projects to be able to do).

/// Truncate a line for use as report evidence, appending an ellipsis marker.
pub fn clip(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push_str("...");
    out
}

/// True when `haystack` (already lowercased) contains any of `needles`.
pub fn contains_any(haystack_lower: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack_lower.contains(n))
}

/// Domains that mean "fill this in", not "mail us here".
const PLACEHOLDER_DOMAINS: [&str; 5] = [
    "example.com",
    "example.org",
    "example.net",
    "domain.com",
    "yourdomain.com",
];

/// A contact address found in a security policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub address: String,
    /// True when the address points at a documentation placeholder domain and
    /// therefore is not a usable reporting channel.
    pub placeholder: bool,
}

/// Find the first plausible email address in `text`.
///
/// Hand-rolled scan: locate `@`, expand over the legal local-part characters to
/// the left and the legal domain characters to the right, then require the
/// domain to have a dot and an alphabetic TLD of at least two characters. That
/// last requirement is what stops workflow-style refs (`actions/checkout@v4`)
/// from ever looking like an address.
pub fn find_email(text: &str) -> Option<Email> {
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b'@' {
            continue;
        }
        let mut start = i;
        while start > 0 && is_local_char(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = i + 1;
        while end < bytes.len() && is_domain_char(bytes[end]) {
            end += 1;
        }
        if start == i || end == i + 1 {
            continue;
        }
        let local = &text[start..i];
        let domain = text[i + 1..end].trim_end_matches('.');
        if local.starts_with('.') || local.ends_with('.') || domain.is_empty() {
            continue;
        }
        let Some((_, tld)) = domain.rsplit_once('.') else {
            continue;
        };
        if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        let domain_lower = domain.to_ascii_lowercase();
        return Some(Email {
            address: format!("{local}@{domain}"),
            placeholder: PLACEHOLDER_DOMAINS.contains(&domain_lower.as_str()),
        });
    }
    None
}

fn is_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

/// Markers of a hosted private-reporting channel (GitHub private vulnerability
/// reporting, or a managed disclosure platform).
const PRIVATE_CHANNEL_MARKERS: [&str; 7] = [
    "security/advisories",
    "private vulnerability reporting",
    "privately report",
    "report a vulnerability",
    "hackerone.com",
    "bugcrowd.com",
    "huntr.",
];

/// Which hosted private-reporting marker, if any, appears in `text_lower`.
pub fn find_private_channel(text_lower: &str) -> Option<&'static str> {
    PRIVATE_CHANNEL_MARKERS
        .iter()
        .find(|m| text_lower.contains(**m))
        .copied()
}

const RESPONSE_KEYWORDS: [&str; 8] = [
    "respond",
    "response",
    "acknowledg",
    "reply",
    "triage",
    "get back to you",
    "initial contact",
    "aim to",
];

const TIME_UNITS: [&str; 6] = [
    "hour",
    "day",
    "week",
    "month",
    "business day",
    "working day",
];

const SPELLED_NUMBERS: [&str; 12] = [
    "one", "two", "three", "four", "five", "six", "seven", "ten", "fourteen", "twenty", "thirty",
    "ninety",
];

/// Find a line that states a response-time expectation, e.g.
/// "We aim to send an initial response within 72 hours."
///
/// Motivated by OpenSSF Best Practices `vulnerability_report_response` (initial
/// response within 14 days) and OSPS-VM-01.01 ("a clear timeframe for
/// response"). Returns the matching line, clipped, as evidence.
pub fn find_response_time(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !contains_any(&lower, &RESPONSE_KEYWORDS) {
            continue;
        }
        if !contains_any(&lower, &TIME_UNITS) {
            continue;
        }
        let has_number =
            lower.chars().any(|c| c.is_ascii_digit()) || contains_any(&lower, &SPELLED_NUMBERS);
        if has_number {
            return Some(clip(line, 120));
        }
    }
    None
}

/// A best-effort SPDX identifier guess, matched on phrases unique to each
/// license text. Deliberately conservative: an unrecognized license is
/// reported as unidentified rather than guessed at, because a wrong SPDX id in
/// a downstream SBOM is worse than a missing one.
///
/// Motivated by OpenSSF Best Practices `floss_license` / `license_location`
/// and OSPS-LE-02.01 / OSPS-LE-03.01.
pub fn guess_spdx(text: &str) -> Option<&'static str> {
    let t = squeeze(&text.to_ascii_lowercase());

    // Order matters: the AGPL/LGPL texts both contain "general public license".
    if t.contains("gnu affero general public license") {
        return Some(if t.contains("version 3") {
            "AGPL-3.0"
        } else {
            "AGPL"
        });
    }
    if t.contains("gnu lesser general public license") {
        return Some(match () {
            _ if t.contains("version 3") => "LGPL-3.0",
            _ if t.contains("version 2.1") => "LGPL-2.1",
            _ => "LGPL",
        });
    }
    if t.contains("gnu general public license") {
        return Some(match () {
            _ if t.contains("version 3") => "GPL-3.0",
            _ if t.contains("version 2") => "GPL-2.0",
            _ => "GPL",
        });
    }
    if t.contains("apache license") && t.contains("version 2.0") {
        return Some("Apache-2.0");
    }
    if t.contains("mozilla public license") && t.contains("2.0") {
        return Some("MPL-2.0");
    }
    if t.contains("permission is hereby granted, free of charge") {
        return Some("MIT");
    }
    if t.contains("permission to use, copy, modify, and/or distribute this software") {
        return Some("ISC");
    }
    if t.contains("redistribution and use in source and binary forms") {
        return Some(if t.contains("neither the name") {
            "BSD-3-Clause"
        } else {
            "BSD-2-Clause"
        });
    }
    if t.contains("boost software license") {
        return Some("BSL-1.0");
    }
    if t.contains("this is free and unencumbered software released into the public domain") {
        return Some("Unlicense");
    }
    if t.contains("cc0 1.0 universal") {
        return Some("CC0-1.0");
    }
    if t.contains("do what the fuck you want to public license") {
        return Some("WTFPL");
    }
    None
}

/// Collapse all runs of whitespace to a single space so phrase matching works
/// across the hard-wrapped license texts everyone ships.
fn squeeze(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            in_ws = true;
            continue;
        }
        if in_ws && !out.is_empty() {
            out.push(' ');
        }
        in_ws = false;
        out.push(c);
    }
    out
}

/// How a workflow step's `uses:` reference is pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// Pinned to a full 40-character commit SHA: immutable.
    CommitSha,
    /// Pinned to a tag or branch, which the upstream owner can move.
    Mutable,
    /// A local action (`./.github/actions/foo`): nothing third-party to pin.
    Local,
    /// A container image reference: outside the scope of this check.
    Docker,
    /// No `@ref` at all, which resolves to the action's default branch.
    NoRef,
}

/// Classify a `uses:` value.
pub fn classify_ref(uses: &str) -> RefKind {
    if uses.starts_with("./") || uses.starts_with("../") {
        return RefKind::Local;
    }
    if uses.starts_with("docker://") {
        return RefKind::Docker;
    }
    let Some((_, git_ref)) = uses.rsplit_once('@') else {
        return RefKind::NoRef;
    };
    if git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit()) {
        RefKind::CommitSha
    } else {
        RefKind::Mutable
    }
}

/// Extract the value of a `uses:` key from a single workflow line.
///
/// A real YAML parser would be more correct, but `uses:` only ever appears as a
/// scalar step key, and staying parser-free keeps the dependency tree small.
/// Anything ambiguous simply yields `None` and is not reported.
pub fn parse_uses(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    if let Some(stripped) = rest.strip_prefix("- ") {
        rest = stripped.trim_start();
    }
    let rest = rest.strip_prefix("uses:")?.trim_start();
    let value = match rest.as_bytes().first() {
        Some(b'"') => rest[1..].split('"').next()?,
        Some(b'\'') => rest[1..].split('\'').next()?,
        _ => rest.split_whitespace().next()?.split('#').next()?,
    };
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_found_and_placeholders_flagged() {
        let found = find_email("contact us at info@printemps.tokyo please").unwrap();
        assert_eq!(found.address, "info@printemps.tokyo");
        assert!(!found.placeholder);

        let ph = find_email("mail security@example.com").unwrap();
        assert!(ph.placeholder);
    }

    #[test]
    fn action_refs_are_not_mistaken_for_emails() {
        assert_eq!(find_email("uses: actions/checkout@v4"), None);
        assert_eq!(find_email("see @maintainer for help"), None);
    }

    #[test]
    fn response_time_lines() {
        assert!(
            find_response_time("We aim to send an initial response within 72 hours.").is_some()
        );
        assert!(find_response_time("Expect a reply in three business days.").is_some());
        assert_eq!(find_response_time("Please report vulnerabilities."), None);
        assert_eq!(find_response_time("We will respond eventually."), None);
    }

    #[test]
    fn spdx_guesses() {
        assert_eq!(
            guess_spdx(
                "MIT License\n\nPermission is hereby granted, free of charge, to any person"
            ),
            Some("MIT")
        );
        assert_eq!(
            guess_spdx("Apache License\nVersion 2.0, January 2004"),
            Some("Apache-2.0")
        );
        assert_eq!(
            guess_spdx("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1, February 1999"),
            Some("LGPL-2.1")
        );
        assert_eq!(guess_spdx("Copyright me. All rights reserved."), None);
    }

    #[test]
    fn ref_classification() {
        assert_eq!(
            classify_ref("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"),
            RefKind::CommitSha
        );
        assert_eq!(classify_ref("actions/checkout@v4"), RefKind::Mutable);
        assert_eq!(classify_ref("actions/checkout@main"), RefKind::Mutable);
        assert_eq!(classify_ref("actions/checkout"), RefKind::NoRef);
        assert_eq!(classify_ref("./.github/actions/setup"), RefKind::Local);
        assert_eq!(classify_ref("docker://alpine:3"), RefKind::Docker);
    }

    #[test]
    fn uses_parsing() {
        assert_eq!(
            parse_uses("      - uses: actions/checkout@v4"),
            Some("actions/checkout@v4")
        );
        assert_eq!(
            parse_uses("        uses: actions/checkout@v4 # comment"),
            Some("actions/checkout@v4")
        );
        assert_eq!(
            parse_uses("        uses: \"actions/checkout@v4\""),
            Some("actions/checkout@v4")
        );
        assert_eq!(
            parse_uses("        uses: 'actions/checkout@v4'"),
            Some("actions/checkout@v4")
        );
        assert_eq!(parse_uses("        name: uses: not-a-step"), None);
        assert_eq!(parse_uses("        uses:"), None);
    }

    #[test]
    fn clip_shortens_long_lines() {
        assert_eq!(clip("  hello  ", 20), "hello");
        assert_eq!(clip("abcdefghij", 5), "abcde...");
    }
}
