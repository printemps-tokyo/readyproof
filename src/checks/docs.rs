//! Documentation checks: README, support policy, CONTRIBUTING, code of
//! conduct, and the license file.

use super::Meta;
use crate::model::{Category, Finding, Severity};
use crate::snapshot::RepoSnapshot;
use crate::text::{contains_any, guess_spdx};

const README_CANDIDATES: &[&str] = &[
    "README.md",
    "README",
    "README.markdown",
    "README.rst",
    "README.txt",
    "README.adoc",
    "docs/README.md",
    ".github/README.md",
];

const CONTRIBUTING_CANDIDATES: &[&str] = &[
    "CONTRIBUTING.md",
    "CONTRIBUTING",
    "CONTRIBUTING.rst",
    "CONTRIBUTING.txt",
    ".github/CONTRIBUTING.md",
    "docs/CONTRIBUTING.md",
];

const COC_CANDIDATES: &[&str] = &[
    "CODE_OF_CONDUCT.md",
    "CODE_OF_CONDUCT",
    "CODE_OF_CONDUCT.rst",
    ".github/CODE_OF_CONDUCT.md",
    "docs/CODE_OF_CONDUCT.md",
];

const LICENSE_CANDIDATES: &[&str] = &[
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENCE",
    "LICENCE.md",
    "LICENCE.txt",
    "COPYING",
    "COPYING.md",
    "COPYING.txt",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    ".github/LICENSE",
    "docs/LICENSE",
];

const README_META: Meta = Meta {
    id: "doc-readme",
    category: Category::Documentation,
    why: "The README is where every downstream reviewer starts. OpenSSF Best Practices requires \
basic documentation of what the software does and how to use it, and a repository without one \
cannot answer either question.",
    source: "OpenSSF Best Practices, passing level: documentation_basics, description_good \
(https://www.bestpractices.dev/en/criteria/0)",
    fix: "Add README.md at the repository root: what the project does, how to install it, how to \
use it, and where to get help.",
};

/// `doc-readme` — is there a README at all?
pub fn readme(snap: &RepoSnapshot) -> Finding {
    match snap.find_first(README_CANDIDATES) {
        Some(path) => README_META.finding(Severity::Pass, "README present", vec![path.to_string()]),
        None => README_META.finding(Severity::Fail, "No README found", Vec::new()),
    }
}

/// Phrases that indicate a documented support window. `EOL` on its own is
/// deliberately excluded: it matches too much ordinary prose.
const SUPPORT_MARKERS: &[&str] = &[
    "supported versions",
    "supported version",
    "supported releases",
    "support policy",
    "support period",
    "end of life",
    "end-of-life",
    "maintenance policy",
    "security support",
    "security updates for",
    "msrv",
];

const SUPPORT_META: Meta = Meta {
    id: "doc-support-policy",
    category: Category::Documentation,
    why:
        "\"Which versions do you still patch, and for how long?\" is one of the first questions a \
downstream manufacturer asks, because their own support period depends on the answer. This is \
informational only: no OpenSSF passing criterion requires it, and upstream maintainers owe nobody \
a support commitment.",
    source: "Downstream integrator question; OpenSSF CRA guidance on voluntarily publishing \
development and support practices (https://openssf.org/category/policy/cra/)",
    fix:
        "If you are willing to state one, add a short \"Supported versions\" table to SECURITY.md \
or the README. Saying \"only the latest release is supported\" is a complete answer.",
};

/// `doc-support-policy` — informational either way.
pub fn support_policy(snap: &RepoSnapshot) -> Finding {
    let sources = [
        snap.find_first(README_CANDIDATES),
        snap.find_first(super::disclosure::SECURITY_CANDIDATES),
    ];
    for path in sources.into_iter().flatten() {
        let Some(text) = snap.text(path) else {
            continue;
        };
        if contains_any(&text.to_ascii_lowercase(), SUPPORT_MARKERS) {
            return SUPPORT_META.finding(
                Severity::Info,
                "Supported versions / support policy appears to be documented",
                vec![path.to_string()],
            );
        }
    }
    SUPPORT_META.finding(
        Severity::Info,
        "No supported-versions or support-policy statement found",
        Vec::new(),
    )
}

const CONTRIBUTING_META: Meta = Meta {
    id: "doc-contributing",
    category: Category::Documentation,
    why: "OpenSSF Best Practices requires the contribution process to be documented. A separate \
CONTRIBUTING file is the convention GitHub surfaces in the new-PR flow, so contributors actually \
see it.",
    source: "OpenSSF Best Practices, passing level: contribution, contribution_requirements \
(https://www.bestpractices.dev/en/criteria/0)",
    fix: "Add CONTRIBUTING.md covering how to build and test, whether pull requests are used, and \
what makes a change acceptable.",
};

/// `doc-contributing` — a WARN rather than a FAIL, because the criterion can
/// also be satisfied by a section in the README.
pub fn contributing(snap: &RepoSnapshot) -> Finding {
    if let Some(path) = snap.find_first(CONTRIBUTING_CANDIDATES) {
        return CONTRIBUTING_META.finding(
            Severity::Pass,
            "CONTRIBUTING present",
            vec![path.to_string()],
        );
    }
    if let Some(readme_path) = snap.find_first(README_CANDIDATES) {
        if let Some(text) = snap.text(readme_path) {
            if text.to_ascii_lowercase().contains("contributing") {
                return CONTRIBUTING_META.finding(
                    Severity::Warn,
                    "No CONTRIBUTING file; the README mentions contributing",
                    vec![readme_path.to_string()],
                );
            }
        }
    }
    CONTRIBUTING_META.finding(Severity::Warn, "No CONTRIBUTING file found", Vec::new())
}

const COC_META: Meta = Meta {
    id: "doc-code-of-conduct",
    category: Category::Documentation,
    why: "A published code of conduct tells contributors and downstream reviewers how conflicts \
are handled. It is a silver-level OpenSSF criterion, not a passing one, so its absence is reported \
as a warning rather than a failure.",
    source: "OpenSSF Best Practices, silver level: code_of_conduct \
(https://www.bestpractices.dev/en/criteria/1)",
    fix: "Add CODE_OF_CONDUCT.md. Adopting the Contributor Covenant and naming a reporting \
address is enough.",
};

/// `doc-code-of-conduct`.
pub fn code_of_conduct(snap: &RepoSnapshot) -> Finding {
    match snap.find_first(COC_CANDIDATES) {
        Some(path) => COC_META.finding(
            Severity::Pass,
            "Code of conduct present",
            vec![path.to_string()],
        ),
        None => COC_META.finding(Severity::Warn, "No CODE_OF_CONDUCT file found", Vec::new()),
    }
}

const LICENSE_PRESENT_META: Meta = Meta {
    id: "license-present",
    category: Category::Documentation,
    why: "Without a license file in a standard location, downstream consumers cannot legally \
redistribute the code and cannot populate the license field of an SBOM. This is the single most \
common blocker in a downstream review.",
    source: "OpenSSF Best Practices, passing level: license_location; OpenSSF Baseline \
OSPS-LE-03.01 (https://www.bestpractices.dev/en/criteria/0, https://baseline.openssf.org/)",
    fix: "Add a LICENSE (or COPYING) file at the repository root containing the full license text.",
};

/// Locate the license file, including a `LICENSE/` directory.
fn license_path(snap: &RepoSnapshot) -> Option<String> {
    if let Some(path) = snap.find_first(LICENSE_CANDIDATES) {
        return Some(path.to_string());
    }
    // OSPS-LE-03.01 also accepts a LICENSE/ directory.
    snap.paths_under("license/").next().map(str::to_string)
}

/// `license-present`.
pub fn license_present(snap: &RepoSnapshot) -> Finding {
    match license_path(snap) {
        Some(path) => {
            LICENSE_PRESENT_META.finding(Severity::Pass, "License file present", vec![path])
        }
        None => LICENSE_PRESENT_META.finding(
            Severity::Fail,
            "No LICENSE or COPYING file found",
            Vec::new(),
        ),
    }
}

const LICENSE_ID_META: Meta = Meta {
    id: "license-identified",
    category: Category::Documentation,
    why: "An SBOM entry needs an SPDX identifier, and automated license scanners match on the \
canonical text. A modified or unrecognized license text forces every downstream consumer into a \
manual legal review.",
    source: "OpenSSF Best Practices, passing level: floss_license; OpenSSF Baseline OSPS-LE-02.01 \
(https://www.bestpractices.dev/en/criteria/0, https://baseline.openssf.org/)",
    fix: "Use the unmodified text of a standard OSI license, and declare the SPDX id in your \
package manifest (for example Cargo.toml's `license` field).",
};

/// `license-identified` — best-effort SPDX guess from the license text.
pub fn license_identified(snap: &RepoSnapshot) -> Finding {
    let Some(path) = license_path(snap) else {
        return LICENSE_ID_META.finding(
            Severity::Info,
            "Not evaluated: no license file to identify",
            Vec::new(),
        );
    };
    let Some(text) = snap.text(&path) else {
        return LICENSE_ID_META.finding(
            Severity::Warn,
            format!("License file {path} could not be read as text"),
            vec![path],
        );
    };
    match guess_spdx(text) {
        Some(spdx) => LICENSE_ID_META.finding(
            Severity::Pass,
            format!("License text matches {spdx}"),
            vec![format!("{path} ({spdx})")],
        ),
        None => LICENSE_ID_META.finding(
            Severity::Warn,
            "License text does not match a well-known license",
            vec![path],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readme_pass_and_fail() {
        let with = RepoSnapshot::from_entries("x", [("README.md", Some("hi"))]);
        assert_eq!(readme(&with).severity, Severity::Pass);

        let without = RepoSnapshot::from_entries("x", [("src/main.rs", None::<&str>)]);
        assert_eq!(readme(&without).severity, Severity::Fail);
    }

    #[test]
    fn license_directory_is_accepted() {
        let snap = RepoSnapshot::from_entries("x", [("LICENSE/MIT.txt", None::<&str>)]);
        assert_eq!(license_present(&snap).severity, Severity::Pass);
    }

    #[test]
    fn unidentifiable_license_warns() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [("LICENSE", Some("You may use this if you are nice to me."))],
        );
        assert_eq!(license_present(&snap).severity, Severity::Pass);
        assert_eq!(license_identified(&snap).severity, Severity::Warn);
    }

    #[test]
    fn missing_license_makes_identification_informational() {
        let snap = RepoSnapshot::from_entries("x", [("README.md", Some("hi"))]);
        assert_eq!(license_identified(&snap).severity, Severity::Info);
    }

    #[test]
    fn contributing_falls_back_to_the_readme() {
        let snap =
            RepoSnapshot::from_entries("x", [("README.md", Some("## Contributing\nPRs ok"))]);
        let f = contributing(&snap);
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.title.contains("README"));
    }

    #[test]
    fn support_policy_is_always_informational() {
        let documented =
            RepoSnapshot::from_entries("x", [("README.md", Some("## Supported versions\n1.x"))]);
        let f = support_policy(&documented);
        assert_eq!(f.severity, Severity::Info);
        assert!(f.title.contains("documented"));

        let bare = RepoSnapshot::from_entries("x", [("README.md", Some("hi"))]);
        assert_eq!(support_policy(&bare).severity, Severity::Info);
    }
}
