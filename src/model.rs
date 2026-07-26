//! Core data model: severities, categories, findings and the aggregated report.
//!
//! Nothing in this module touches the filesystem; it is pure data plus the
//! scoring rollup, so it is trivially testable.

use std::fmt;

/// Outcome of a single check.
///
/// `Info` is deliberately unscored: it carries context a downstream reviewer
/// asks about (e.g. "what would an SBOM be generated from?") without implying
/// the repository did anything wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The practice is in place.
    Pass,
    /// Context only; never affects the score or the exit code.
    Info,
    /// Worth fixing, but reasonable projects disagree or the practice is
    /// commonly skipped. Only fails the run under `--strict`.
    Warn,
    /// A practice downstream consumers routinely ask for is absent.
    Fail,
}

impl Severity {
    /// Lowercase machine token used in JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Pass => "pass",
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Fail => "fail",
        }
    }

    /// Fixed-width uppercase label used in the human report.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Pass => "PASS",
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        }
    }

    /// Fraction of a check's weight earned by this outcome.
    fn credit(self) -> f64 {
        match self {
            Severity::Pass => 1.0,
            Severity::Warn => 0.5,
            Severity::Fail => 0.0,
            // Info is excluded from scoring entirely (see `Finding::weight`).
            Severity::Info => 1.0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rollup bucket a check belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    /// README / CONTRIBUTING / CODE_OF_CONDUCT / LICENSE.
    Documentation,
    /// Dependency manifests, lockfiles, SBOM basis, update process, secrets.
    SupplyChain,
    /// Workflows: presence, tests, action pinning, release integrity.
    Ci,
    /// Vulnerability reporting policy, contact, response time, security.txt.
    Disclosure,
}

impl Category {
    /// Every category, in the order they are rendered. Rendering order is part
    /// of the deterministic-output contract.
    pub const ALL: [Category; 4] = [
        Category::Documentation,
        Category::SupplyChain,
        Category::Ci,
        Category::Disclosure,
    ];

    /// Machine token, also the accepted `--only` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Documentation => "documentation",
            Category::SupplyChain => "supply-chain",
            Category::Ci => "ci",
            Category::Disclosure => "disclosure",
        }
    }

    /// Human title used as the section heading.
    pub fn title(self) -> &'static str {
        match self {
            Category::Documentation => "Documentation",
            Category::SupplyChain => "Supply chain",
            Category::Ci => "CI",
            Category::Disclosure => "Disclosure",
        }
    }

    /// Parse a `--only` value. A few obvious aliases are accepted so the flag
    /// is forgiving without being magic.
    pub fn parse(s: &str) -> Option<Category> {
        match s.trim().to_ascii_lowercase().as_str() {
            "documentation" | "docs" | "doc" => Some(Category::Documentation),
            "supply-chain" | "supply_chain" | "supplychain" | "supply" => {
                Some(Category::SupplyChain)
            }
            "ci" | "workflows" => Some(Category::Ci),
            "disclosure" | "security" | "vuln" => Some(Category::Disclosure),
            _ => None,
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable identifier, also the `--skip` value (e.g. `doc-readme`).
    pub id: &'static str,
    /// Rollup bucket.
    pub category: Category,
    /// Outcome.
    pub severity: Severity,
    /// One-line human summary of what was (or was not) found.
    pub title: String,
    /// Concrete evidence: repository-relative paths, or `path:line` for
    /// workflow findings. Always sorted by the check that produced it.
    ///
    /// Evidence never contains file contents for the secret-hygiene check;
    /// see `checks::supply::secrets`.
    pub evidence: Vec<String>,
    /// Why a downstream consumer cares.
    pub why: &'static str,
    /// The primary source that motivates the check.
    pub source: &'static str,
    /// A concrete next step.
    pub fix: &'static str,
}

impl Finding {
    /// Scoring weight. `Info` findings are unscored, and the two checks that
    /// map onto the strongest downstream questions (a vulnerability reporting
    /// process, and no secrets in the tree) count double.
    pub fn weight(&self) -> f64 {
        if self.severity == Severity::Info {
            return 0.0;
        }
        match self.id {
            "disclosure-policy" | "disclosure-contact" | "supply-secrets" | "license-present" => {
                2.0
            }
            _ => 1.0,
        }
    }
}

/// Per-severity tallies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub info: usize,
}

impl Counts {
    fn add(&mut self, severity: Severity) {
        match severity {
            Severity::Pass => self.pass += 1,
            Severity::Warn => self.warn += 1,
            Severity::Fail => self.fail += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// Rollup for one category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryScore {
    pub category: Category,
    /// 0-100, or `None` when every finding in the category was informational
    /// (or the category was filtered out).
    pub score: Option<u32>,
    pub counts: Counts,
}

/// The aggregated audit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Display name of the audited repository (its directory name).
    pub root_name: String,
    /// Findings, already in deterministic order.
    pub findings: Vec<Finding>,
    /// Per-category rollups, in `Category::ALL` order, skipping empty ones.
    pub categories: Vec<CategoryScore>,
    pub counts: Counts,
    /// Overall 0-100 score, or `None` when nothing scoreable ran.
    pub score: Option<u32>,
    /// Number of checks suppressed by `--skip` / `--only`.
    pub skipped: usize,
}

/// The one-line framing that must accompany every report, in both output modes.
pub const DISCLAIMER: &str = "readyproof grades practice readiness only. It is not legal advice, \
not a certification, and not a CRA conformity assessment: CRA obligations fall on manufacturers \
placing products on the EU market, and open source stewards have a lighter regime.";

impl Report {
    /// Build a report from findings, computing the rollups. `findings` is
    /// sorted here so callers cannot accidentally emit unstable output.
    pub fn new(root_name: String, mut findings: Vec<Finding>, skipped: usize) -> Report {
        // Deterministic ordering: category order first, then check id. Severity
        // is deliberately not part of the key so that adding a finding never
        // reshuffles unrelated lines.
        findings.sort_by(|a, b| {
            category_rank(a.category)
                .cmp(&category_rank(b.category))
                .then_with(|| a.id.cmp(b.id))
        });

        let mut counts = Counts::default();
        for f in &findings {
            counts.add(f.severity);
        }

        let mut categories = Vec::new();
        for category in Category::ALL {
            let in_cat: Vec<&Finding> =
                findings.iter().filter(|f| f.category == category).collect();
            if in_cat.is_empty() {
                continue;
            }
            let mut cat_counts = Counts::default();
            for f in &in_cat {
                cat_counts.add(f.severity);
            }
            categories.push(CategoryScore {
                category,
                score: score_of(in_cat.into_iter()),
                counts: cat_counts,
            });
        }

        let score = score_of(findings.iter());

        Report {
            root_name,
            findings,
            categories,
            counts,
            score,
            skipped,
        }
    }

    /// Letter grade derived from the overall score.
    pub fn grade(&self) -> &'static str {
        match self.score {
            None => "n/a",
            Some(s) if s >= 90 => "A",
            Some(s) if s >= 75 => "B",
            Some(s) if s >= 60 => "C",
            Some(s) if s >= 40 => "D",
            Some(_) => "F",
        }
    }

    /// True when at least one check failed.
    pub fn has_fail(&self) -> bool {
        self.counts.fail > 0
    }

    /// True when at least one check warned.
    pub fn has_warn(&self) -> bool {
        self.counts.warn > 0
    }

    /// Process exit code: 0 clean, 1 when a FAIL (or, under `--strict`, a WARN)
    /// is present. Usage and I/O errors exit 2 from `main`.
    pub fn exit_code(&self, strict: bool) -> i32 {
        if self.has_fail() || (strict && self.has_warn()) {
            1
        } else {
            0
        }
    }
}

fn category_rank(c: Category) -> usize {
    Category::ALL
        .iter()
        .position(|x| *x == c)
        .unwrap_or(usize::MAX)
}

/// Weighted score over an iterator of findings, rounded to the nearest integer.
fn score_of<'a>(findings: impl Iterator<Item = &'a Finding>) -> Option<u32> {
    let mut earned = 0.0;
    let mut total = 0.0;
    for f in findings {
        let w = f.weight();
        total += w;
        earned += w * f.severity.credit();
    }
    if total <= 0.0 {
        return None;
    }
    Some((earned / total * 100.0).round() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &'static str, category: Category, severity: Severity) -> Finding {
        Finding {
            id,
            category,
            severity,
            title: String::new(),
            evidence: Vec::new(),
            why: "",
            source: "",
            fix: "",
        }
    }

    #[test]
    fn info_findings_do_not_move_the_score() {
        let all_pass = Report::new(
            "x".into(),
            vec![finding("a-x", Category::Ci, Severity::Pass)],
            0,
        );
        let with_info = Report::new(
            "x".into(),
            vec![
                finding("a-x", Category::Ci, Severity::Pass),
                finding("a-y", Category::Ci, Severity::Info),
            ],
            0,
        );
        assert_eq!(all_pass.score, Some(100));
        assert_eq!(with_info.score, Some(100));
    }

    #[test]
    fn warn_is_half_credit() {
        let r = Report::new(
            "x".into(),
            vec![
                finding("a-x", Category::Ci, Severity::Pass),
                finding("a-y", Category::Ci, Severity::Warn),
            ],
            0,
        );
        assert_eq!(r.score, Some(75));
        assert_eq!(r.grade(), "B");
    }

    #[test]
    fn exit_codes_follow_the_contract() {
        let warn = Report::new(
            "x".into(),
            vec![finding("a-x", Category::Ci, Severity::Warn)],
            0,
        );
        assert_eq!(warn.exit_code(false), 0);
        assert_eq!(warn.exit_code(true), 1);

        let fail = Report::new(
            "x".into(),
            vec![finding("a-x", Category::Ci, Severity::Fail)],
            0,
        );
        assert_eq!(fail.exit_code(false), 1);
        assert_eq!(fail.exit_code(true), 1);
    }

    #[test]
    fn findings_sort_by_category_then_id() {
        let r = Report::new(
            "x".into(),
            vec![
                finding("z-last", Category::Disclosure, Severity::Pass),
                finding("b-two", Category::Documentation, Severity::Pass),
                finding("a-one", Category::Documentation, Severity::Pass),
                finding("m-mid", Category::Ci, Severity::Pass),
            ],
            0,
        );
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id).collect();
        assert_eq!(ids, ["a-one", "b-two", "m-mid", "z-last"]);
    }

    #[test]
    fn category_parse_accepts_aliases() {
        assert_eq!(Category::parse("DOCS"), Some(Category::Documentation));
        assert_eq!(
            Category::parse(" supply-chain "),
            Some(Category::SupplyChain)
        );
        assert_eq!(Category::parse("nope"), None);
    }
}
