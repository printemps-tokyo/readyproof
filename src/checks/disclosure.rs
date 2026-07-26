//! Vulnerability-disclosure checks: is there a published policy, does it name a
//! channel, does it state a response time, and is there a security.txt?

use super::Meta;
use crate::model::{Category, Finding, Severity};
use crate::snapshot::RepoSnapshot;
use crate::text::{find_email, find_private_channel, find_response_time};

/// Locations GitHub itself recognizes for a security policy, plus the plain
/// root spellings.
pub(crate) const SECURITY_CANDIDATES: &[&str] = &[
    "SECURITY.md",
    "SECURITY",
    "SECURITY.txt",
    "SECURITY.rst",
    "SECURITY.markdown",
    ".github/SECURITY.md",
    ".github/SECURITY",
    ".github/SECURITY.txt",
    "docs/SECURITY.md",
    "docs/SECURITY",
];

const SECURITY_TXT_CANDIDATES: &[&str] = &[
    ".well-known/security.txt",
    "security.txt",
    "public/.well-known/security.txt",
    "static/.well-known/security.txt",
    "docs/.well-known/security.txt",
    "www/.well-known/security.txt",
];

fn security_policy(snap: &RepoSnapshot) -> Option<&str> {
    snap.find_first(SECURITY_CANDIDATES)
}

const POLICY_META: Meta = Meta {
    id: "disclosure-policy",
    category: Category::Disclosure,
    why: "Publishing how to report a vulnerability is a passing-level OpenSSF requirement and the \
first thing a downstream security team looks for. Without it, a finder's only options are a public \
issue or silence.",
    source:
        "OpenSSF Best Practices, passing level: vulnerability_report_process; OpenSSF Baseline \
OSPS-VM-01.01 (https://www.bestpractices.dev/en/criteria/0, https://baseline.openssf.org/)",
    fix: "Add SECURITY.md at the repository root (or in .github/), stating how to report a \
vulnerability privately and what happens next.",
};

/// `disclosure-policy` — is a security policy published anywhere GitHub looks?
pub fn policy(snap: &RepoSnapshot) -> Finding {
    let Some(path) = security_policy(snap) else {
        return POLICY_META.finding(Severity::Fail, "No security policy found", Vec::new());
    };
    let title = if path.eq_ignore_ascii_case("SECURITY.md") {
        "Security policy present".to_string()
    } else {
        format!("Security policy present at {path}")
    };
    POLICY_META.finding(Severity::Pass, title, vec![path.to_string()])
}

const CONTACT_META: Meta = Meta {
    id: "disclosure-contact",
    category: Category::Disclosure,
    why: "A policy that does not name a channel is not a reporting process. OpenSSF requires that \
if private reports are supported, the policy says how to send them privately; the Baseline asks \
for security contacts outright.",
    source:
        "OpenSSF Best Practices, passing level: vulnerability_report_private; OpenSSF Baseline \
OSPS-VM-02.01 and OSPS-VM-03.01 (https://www.bestpractices.dev/en/criteria/0, \
https://baseline.openssf.org/)",
    fix: "Name a real channel in SECURITY.md: a monitored email address, or GitHub private \
vulnerability reporting (Settings -> Code security -> Private vulnerability reporting), and link \
to it directly.",
};

/// `disclosure-contact` — does the policy name a usable reporting channel?
pub fn contact(snap: &RepoSnapshot) -> Finding {
    let Some(path) = security_policy(snap) else {
        return CONTACT_META.finding(
            Severity::Fail,
            "No security policy, so no documented reporting channel",
            Vec::new(),
        );
    };
    let Some(text) = snap.text(path) else {
        return CONTACT_META.finding(
            Severity::Warn,
            format!("Security policy {path} could not be read as text"),
            vec![path.to_string()],
        );
    };

    let lower = text.to_ascii_lowercase();
    let email = find_email(text);
    let private = find_private_channel(&lower);

    let mut evidence = Vec::new();
    if let Some(marker) = private {
        evidence.push(format!("{path}: mentions \"{marker}\""));
    }
    if let Some(e) = &email {
        evidence.push(format!("{path}: {}", e.address));
    }

    let usable_email = email.as_ref().is_some_and(|e| !e.placeholder);
    if usable_email || private.is_some() {
        return CONTACT_META.finding(Severity::Pass, "Reporting channel documented", evidence);
    }
    if email.is_some() {
        return CONTACT_META.finding(
            Severity::Warn,
            "Security policy only contains a placeholder address",
            evidence,
        );
    }
    CONTACT_META.finding(
        Severity::Fail,
        "Security policy names no email address or private reporting channel",
        vec![path.to_string()],
    )
}

const RESPONSE_META: Meta = Meta {
    id: "disclosure-response-time",
    category: Category::Disclosure,
    why: "A finder needs to know when to expect a reply and when to escalate. OpenSSF's passing \
criteria measure initial response within 14 days, and the Baseline asks the policy to state a \
timeframe. Stating a modest one you can actually meet is better than stating none.",
    source:
        "OpenSSF Best Practices, passing level: vulnerability_report_response; OpenSSF Baseline \
OSPS-VM-01.01 (https://www.bestpractices.dev/en/criteria/0, https://baseline.openssf.org/)",
    fix: "Add one sentence to SECURITY.md, e.g. \"We aim to send an initial response within 72 \
hours.\"",
};

/// `disclosure-response-time`.
pub fn response_time(snap: &RepoSnapshot) -> Finding {
    let Some(path) = security_policy(snap) else {
        return RESPONSE_META.finding(
            Severity::Warn,
            "No security policy, so no response-time expectation",
            Vec::new(),
        );
    };
    let Some(text) = snap.text(path) else {
        return RESPONSE_META.finding(
            Severity::Warn,
            format!("Security policy {path} could not be read as text"),
            vec![path.to_string()],
        );
    };
    match find_response_time(text) {
        Some(line) => RESPONSE_META.finding(
            Severity::Pass,
            "Response-time expectation stated",
            vec![format!("{path}: {line}")],
        ),
        None => RESPONSE_META.finding(
            Severity::Warn,
            "Security policy states no response-time expectation",
            vec![path.to_string()],
        ),
    }
}

const SECURITY_TXT_META: Meta = Meta {
    id: "disclosure-security-txt",
    category: Category::Disclosure,
    why: "RFC 9116 security.txt is the machine-readable counterpart to SECURITY.md, used by \
scanners and by finders who arrive at a deployed site rather than the repository. It is optional \
and mainly relevant to projects that also operate a web property.",
    source: "RFC 9116, A File Format to Aid in Security Vulnerability Disclosure \
(https://www.rfc-editor.org/rfc/rfc9116)",
    fix: "If the project publishes a website, serve /.well-known/security.txt with Contact and \
Expires fields.",
};

/// `disclosure-security-txt` — informational either way.
pub fn security_txt(snap: &RepoSnapshot) -> Finding {
    match snap.find_first(SECURITY_TXT_CANDIDATES) {
        Some(path) => SECURITY_TXT_META.finding(
            Severity::Info,
            "security.txt present",
            vec![path.to_string()],
        ),
        None => SECURITY_TXT_META.finding(
            Severity::Info,
            "No security.txt found (optional; mainly for projects with a website)",
            Vec::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_POLICY: &str =
        "# Security Policy\n\nReport privately to security@printemps.tokyo.\n\
We aim to send an initial response within 72 hours.\n";

    #[test]
    fn full_policy_passes_every_disclosure_check() {
        let snap = RepoSnapshot::from_entries("x", [("SECURITY.md", Some(GOOD_POLICY))]);
        assert_eq!(policy(&snap).severity, Severity::Pass);
        assert_eq!(contact(&snap).severity, Severity::Pass);
        assert_eq!(response_time(&snap).severity, Severity::Pass);
    }

    #[test]
    fn alternate_github_location_is_honored() {
        let snap = RepoSnapshot::from_entries("x", [(".github/SECURITY.md", Some(GOOD_POLICY))]);
        let f = policy(&snap);
        assert_eq!(f.severity, Severity::Pass);
        assert_eq!(f.evidence, [".github/SECURITY.md"]);
        assert!(f.title.contains(".github/SECURITY.md"));
        assert_eq!(contact(&snap).severity, Severity::Pass);
    }

    #[test]
    fn policy_without_contact_fails_the_contact_check() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [(
                "SECURITY.md",
                Some("# Security\n\nWe take security seriously. Please be responsible.\n"),
            )],
        );
        assert_eq!(policy(&snap).severity, Severity::Pass);
        assert_eq!(contact(&snap).severity, Severity::Fail);
        assert_eq!(response_time(&snap).severity, Severity::Warn);
    }

    #[test]
    fn private_vulnerability_reporting_counts_as_a_channel() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [(
                "SECURITY.md",
                Some("Use GitHub private vulnerability reporting: ../../security/advisories/new\n"),
            )],
        );
        assert_eq!(contact(&snap).severity, Severity::Pass);
    }

    #[test]
    fn placeholder_address_only_warns() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [(
                "SECURITY.md",
                Some("Mail security@example.com to report.\n"),
            )],
        );
        assert_eq!(contact(&snap).severity, Severity::Warn);
    }

    #[test]
    fn missing_policy_fails_policy_and_contact() {
        let snap = RepoSnapshot::from_entries("x", [("README.md", Some("hi"))]);
        assert_eq!(policy(&snap).severity, Severity::Fail);
        assert_eq!(contact(&snap).severity, Severity::Fail);
        assert_eq!(response_time(&snap).severity, Severity::Warn);
        assert_eq!(security_txt(&snap).severity, Severity::Info);
    }
}
