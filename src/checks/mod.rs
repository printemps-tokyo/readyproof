//! The check registry.
//!
//! Every check is a pure function from a [`RepoSnapshot`] to exactly one
//! [`Finding`]. One check produces one finding, always, so the catalog printed
//! in the README is exactly the catalog the tool emits, and `--skip <id>` has
//! an unambiguous target.
//!
//! Each check is anchored on a citable source: the OpenSSF Best Practices
//! "passing" criteria (<https://www.bestpractices.dev/en/criteria/0>), the
//! OpenSSF Baseline controls (<https://baseline.openssf.org/>), OpenSSF's CRA
//! guidance for maintainers (<https://openssf.org/category/policy/cra/>), or a
//! concrete question downstream consumers ask. Where a practice is contested or
//! commonly skipped, the finding says so rather than pretending otherwise.

pub mod ci;
pub mod disclosure;
pub mod docs;
pub mod supply;

use crate::model::{Category, Finding, Report, Severity};
use crate::snapshot::RepoSnapshot;

/// Static description of one check, shared by every finding it can emit.
pub(crate) struct Meta {
    pub id: &'static str,
    pub category: Category,
    /// Why a downstream consumer cares.
    pub why: &'static str,
    /// The primary source that motivates the check.
    pub source: &'static str,
    /// The concrete next step when the check is not clean.
    pub fix: &'static str,
}

impl Meta {
    pub(crate) fn finding(
        &self,
        severity: Severity,
        title: impl Into<String>,
        evidence: Vec<String>,
    ) -> Finding {
        Finding {
            id: self.id,
            category: self.category,
            severity,
            title: title.into(),
            evidence,
            why: self.why,
            source: self.source,
            fix: self.fix,
        }
    }
}

/// One entry in the registry.
pub struct CheckSpec {
    pub id: &'static str,
    pub category: Category,
    pub run: fn(&RepoSnapshot) -> Finding,
}

/// Every check, in registry order. Report ordering is imposed separately by
/// [`Report::new`], so this order only affects which checks exist.
pub const CHECKS: &[CheckSpec] = &[
    CheckSpec {
        id: "doc-readme",
        category: Category::Documentation,
        run: docs::readme,
    },
    CheckSpec {
        id: "doc-support-policy",
        category: Category::Documentation,
        run: docs::support_policy,
    },
    CheckSpec {
        id: "doc-contributing",
        category: Category::Documentation,
        run: docs::contributing,
    },
    CheckSpec {
        id: "doc-code-of-conduct",
        category: Category::Documentation,
        run: docs::code_of_conduct,
    },
    CheckSpec {
        id: "license-present",
        category: Category::Documentation,
        run: docs::license_present,
    },
    CheckSpec {
        id: "license-identified",
        category: Category::Documentation,
        run: docs::license_identified,
    },
    CheckSpec {
        id: "supply-manifest",
        category: Category::SupplyChain,
        run: supply::manifest,
    },
    CheckSpec {
        id: "supply-lockfile",
        category: Category::SupplyChain,
        run: supply::lockfile,
    },
    CheckSpec {
        id: "supply-sbom-basis",
        category: Category::SupplyChain,
        run: supply::sbom_basis,
    },
    CheckSpec {
        id: "supply-updates",
        category: Category::SupplyChain,
        run: supply::updates,
    },
    CheckSpec {
        id: "supply-secrets",
        category: Category::SupplyChain,
        run: supply::secrets,
    },
    CheckSpec {
        id: "ci-present",
        category: Category::Ci,
        run: ci::present,
    },
    CheckSpec {
        id: "ci-tests",
        category: Category::Ci,
        run: ci::tests,
    },
    CheckSpec {
        id: "ci-action-pinning",
        category: Category::Ci,
        run: ci::action_pinning,
    },
    CheckSpec {
        id: "ci-release-integrity",
        category: Category::Ci,
        run: ci::release_integrity,
    },
    CheckSpec {
        id: "disclosure-policy",
        category: Category::Disclosure,
        run: disclosure::policy,
    },
    CheckSpec {
        id: "disclosure-contact",
        category: Category::Disclosure,
        run: disclosure::contact,
    },
    CheckSpec {
        id: "disclosure-response-time",
        category: Category::Disclosure,
        run: disclosure::response_time,
    },
    CheckSpec {
        id: "disclosure-security-txt",
        category: Category::Disclosure,
        run: disclosure::security_txt,
    },
];

/// Which checks to run.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// When non-empty, run only checks in these categories.
    pub only: Vec<Category>,
    /// Check ids to suppress entirely.
    pub skip: Vec<String>,
}

impl Options {
    fn selected(&self, spec: &CheckSpec) -> bool {
        if !self.only.is_empty() && !self.only.contains(&spec.category) {
            return false;
        }
        !self.skip.iter().any(|s| s == spec.id)
    }
}

/// Run the selected checks against `snapshot` and aggregate the report.
pub fn audit(snapshot: &RepoSnapshot, opts: &Options) -> Report {
    let mut findings = Vec::with_capacity(CHECKS.len());
    let mut skipped = 0;
    for spec in CHECKS {
        if opts.selected(spec) {
            findings.push((spec.run)(snapshot));
        } else {
            skipped += 1;
        }
    }
    Report::new(snapshot.root_name().to_string(), findings, skipped)
}

/// Every known check id, for `--skip` validation and `--help` text.
pub fn check_ids() -> Vec<&'static str> {
    CHECKS.iter().map(|c| c.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_id_is_unique_and_matches_its_finding() {
        let snap = RepoSnapshot::from_entries("x", [("README.md", Some("hi"))]);
        let mut seen = std::collections::BTreeSet::new();
        for spec in CHECKS {
            assert!(seen.insert(spec.id), "duplicate check id {}", spec.id);
            let f = (spec.run)(&snap);
            assert_eq!(f.id, spec.id);
            assert_eq!(
                f.category, spec.category,
                "category mismatch for {}",
                spec.id
            );
            assert!(!f.title.is_empty(), "{} has an empty title", spec.id);
            assert!(!f.why.is_empty(), "{} has no rationale", spec.id);
            assert!(!f.source.is_empty(), "{} has no source", spec.id);
            assert!(!f.fix.is_empty(), "{} has no fix", spec.id);
        }
    }

    #[test]
    fn only_and_skip_filter_the_registry() {
        let snap = RepoSnapshot::from_entries("x", [("README.md", Some("hi"))]);

        let only_docs = audit(
            &snap,
            &Options {
                only: vec![Category::Documentation],
                skip: Vec::new(),
            },
        );
        assert!(only_docs
            .findings
            .iter()
            .all(|f| f.category == Category::Documentation));
        assert_eq!(only_docs.categories.len(), 1);

        let skipped = audit(
            &snap,
            &Options {
                only: Vec::new(),
                skip: vec!["doc-readme".into()],
            },
        );
        assert!(!skipped.findings.iter().any(|f| f.id == "doc-readme"));
        assert_eq!(skipped.skipped, 1);
    }
}
