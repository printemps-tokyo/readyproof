//! Integration tests over real fixture repositories built in tempdirs.
//!
//! These exercise the actual gitignore-aware walk, not an in-memory snapshot,
//! so they cover the seam between `RepoSnapshot::scan` and the check engine.

use std::fs;
use std::path::Path;

use readyproof::checks::{audit, Options};
use readyproof::model::{Category, Severity};
use readyproof::report::{render_json, render_text, RenderOptions};
use readyproof::snapshot::RepoSnapshot;

const MIT: &str = "MIT License\n\nCopyright (c) 2026 Example\n\nPermission is hereby granted, \
free of charge, to any person obtaining a copy of this software and associated documentation \
files (the \"Software\"), to deal in the Software without restriction.\n";

const SHA: &str = "11bd71901bbe5b1630ceea73d27597364c9af683";

fn write(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn scan(root: &Path) -> RepoSnapshot {
    RepoSnapshot::scan(root, "fixture").unwrap()
}

fn run(root: &Path) -> readyproof::Report {
    audit(&scan(root), &Options::default())
}

fn severity_of(report: &readyproof::Report, id: &str) -> Severity {
    report
        .findings
        .iter()
        .find(|f| f.id == id)
        .unwrap_or_else(|| panic!("no finding with id {id}"))
        .severity
}

/// A repository that has every practice readyproof looks for.
fn good_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write(
        root,
        "README.md",
        "# fixture\n\nDoes a thing.\n\n## Supported versions\n\nOnly the latest release.\n",
    );
    write(root, "LICENSE", MIT);
    write(
        root,
        "CONTRIBUTING.md",
        "# Contributing\n\nOpen a pull request.\n",
    );
    write(
        root,
        "CODE_OF_CONDUCT.md",
        "# Code of Conduct\n\nContributor Covenant v2.1.\n",
    );
    write(
        root,
        "SECURITY.md",
        "# Security Policy\n\nReport privately to security@fixture.example.org or via GitHub \
private vulnerability reporting.\n\nWe aim to send an initial response within 72 hours.\n",
    );
    write(root, "Cargo.toml", "[package]\nname = \"fixture\"\n");
    write(root, "Cargo.lock", "version = 4\n");
    write(root, ".github/dependabot.yml", "version: 2\nupdates: []\n");
    write(
        root,
        ".github/workflows/ci.yml",
        &format!(
            "name: CI\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@{SHA} # v4\n\
      - run: cargo test --all\n"
        ),
    );
    write(
        root,
        ".github/workflows/release.yml",
        &format!(
            "name: Release\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@{SHA} # v4\n\
      - run: shasum -a 256 dist/* > SHA256SUMS\n      - run: gh release upload\n"
        ),
    );
    write(root, "src/main.rs", "fn main() {}\n");
    dir
}

/// A repository with nothing but source.
fn bare_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "src/main.rs", "fn main() {}\n");
    dir
}

#[test]
fn good_repo_grades_clean_under_strict() {
    let dir = good_repo();
    let report = run(dir.path());

    assert_eq!(report.counts.fail, 0, "unexpected FAIL findings");
    let warnings: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .map(|f| f.id)
        .collect();
    assert!(
        warnings.is_empty(),
        "unexpected WARN findings: {warnings:?}"
    );

    assert_eq!(report.score, Some(100));
    assert_eq!(report.grade(), "A");
    assert_eq!(report.exit_code(false), 0);
    assert_eq!(report.exit_code(true), 0);
    assert_eq!(report.categories.len(), 4);
}

#[test]
fn bare_repo_produces_the_expected_failures() {
    let dir = bare_repo();
    let report = run(dir.path());

    let failures: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Fail)
        .map(|f| f.id)
        .collect();
    assert_eq!(
        failures,
        [
            "doc-readme",
            "license-present",
            "disclosure-contact",
            "disclosure-policy"
        ]
    );

    assert_eq!(report.exit_code(false), 1);
    assert_eq!(report.exit_code(true), 1);
    assert!(report.score.unwrap() < 40);
    assert_eq!(report.grade(), "F");
}

#[test]
fn security_policy_without_a_contact_fails_the_contact_check() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "SECURITY.md",
        "# Security\n\nWe care about security. Please be careful.\n",
    );
    let report = run(dir.path());

    assert_eq!(severity_of(&report, "disclosure-policy"), Severity::Pass);
    assert_eq!(severity_of(&report, "disclosure-contact"), Severity::Fail);
    assert_eq!(
        severity_of(&report, "disclosure-response-time"),
        Severity::Warn
    );
}

#[test]
fn security_policy_in_the_github_directory_is_found() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".github/SECURITY.md",
        "Report to security@fixture.example.org. Initial response within 5 days.\n",
    );
    let report = run(dir.path());

    let policy = report
        .findings
        .iter()
        .find(|f| f.id == "disclosure-policy")
        .unwrap();
    assert_eq!(policy.severity, Severity::Pass);
    assert_eq!(policy.evidence, [".github/SECURITY.md"]);
    assert_eq!(severity_of(&report, "disclosure-contact"), Severity::Pass);
    assert_eq!(
        severity_of(&report, "disclosure-response-time"),
        Severity::Pass
    );
}

#[test]
fn unidentifiable_license_warns_but_still_counts_as_present() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "LICENSE",
        "You may use this software if you say something nice about it.\n",
    );
    let report = run(dir.path());

    assert_eq!(severity_of(&report, "license-present"), Severity::Pass);
    assert_eq!(severity_of(&report, "license-identified"), Severity::Warn);
}

#[test]
fn mutable_action_tag_warns_and_a_commit_sha_passes() {
    let tagged = tempfile::tempdir().unwrap();
    write(
        tagged.path(),
        ".github/workflows/ci.yml",
        "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n",
    );
    let report = run(tagged.path());
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "ci-action-pinning")
        .unwrap();
    assert_eq!(finding.severity, Severity::Warn);
    assert_eq!(
        finding.evidence,
        [".github/workflows/ci.yml:4: actions/checkout@v4"]
    );

    let pinned = tempfile::tempdir().unwrap();
    write(
        pinned.path(),
        ".github/workflows/ci.yml",
        &format!("jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{SHA}\n"),
    );
    assert_eq!(
        severity_of(&run(pinned.path()), "ci-action-pinning"),
        Severity::Pass
    );
}

#[test]
fn missing_lockfile_warns() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "Cargo.toml", "[package]\nname = \"x\"\n");
    let report = run(dir.path());

    assert_eq!(severity_of(&report, "supply-manifest"), Severity::Pass);
    let lock = report
        .findings
        .iter()
        .find(|f| f.id == "supply-lockfile")
        .unwrap();
    assert_eq!(lock.severity, Severity::Warn);
    assert_eq!(lock.evidence, ["Cargo.toml (Rust (Cargo)) -> no lockfile"]);
}

#[test]
fn committed_dotenv_is_reported_by_path_and_never_by_content() {
    const CANARY: &str = "CANARY-VALUE-MUST-NEVER-APPEAR";
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "README.md", "# x\n");
    write(
        dir.path(),
        ".env",
        &format!("AWS_SECRET_ACCESS_KEY={CANARY}\n"),
    );
    write(dir.path(), "deploy/id_rsa", &format!("PRIVATE {CANARY}\n"));

    let snapshot = scan(dir.path());
    // The bytes are never loaded in the first place.
    assert!(snapshot.text(".env").is_none());
    assert!(snapshot.text("deploy/id_rsa").is_none());

    let report = audit(&snapshot, &Options::default());
    let secrets = report
        .findings
        .iter()
        .find(|f| f.id == "supply-secrets")
        .unwrap();
    assert_eq!(secrets.severity, Severity::Fail);
    assert_eq!(
        secrets.evidence,
        [".env (environment file)", "deploy/id_rsa (SSH private key)"]
    );

    let text = render_text(&report, RenderOptions { color: false });
    let json = render_json(&report);
    assert!(
        !text.contains(CANARY),
        "secret value leaked into the text report"
    );
    assert!(
        !json.contains(CANARY),
        "secret value leaked into the JSON report"
    );
    assert!(text.contains(".env (environment file)"));
}

#[test]
fn gitignored_files_are_not_treated_as_committed() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".gitignore", ".env\n");
    write(dir.path(), ".env", "SECRET=1\n");
    let report = run(dir.path());

    assert_eq!(severity_of(&report, "supply-secrets"), Severity::Pass);
}

#[test]
fn only_and_skip_filter_the_run() {
    let dir = good_repo();
    let snapshot = scan(dir.path());

    let only_ci = audit(
        &snapshot,
        &Options {
            only: vec![Category::Ci],
            skip: Vec::new(),
        },
    );
    assert!(only_ci.findings.iter().all(|f| f.category == Category::Ci));
    assert_eq!(only_ci.findings.len(), 4);
    assert_eq!(only_ci.skipped, 15);

    let skipped = audit(
        &snapshot,
        &Options {
            only: vec![Category::Ci],
            skip: vec!["ci-tests".into(), "ci-present".into()],
        },
    );
    assert_eq!(skipped.findings.len(), 2);
    assert_eq!(skipped.skipped, 17);
    assert!(!skipped.findings.iter().any(|f| f.id == "ci-tests"));
}

#[test]
fn ordering_is_deterministic_across_runs() {
    let dir = good_repo();
    let first: Vec<&str> = run(dir.path()).findings.iter().map(|f| f.id).collect();
    for _ in 0..5 {
        let again: Vec<&str> = run(dir.path()).findings.iter().map(|f| f.id).collect();
        assert_eq!(first, again);
    }

    // Categories come out in their declared order, ids sorted within each.
    assert_eq!(
        first,
        [
            "doc-code-of-conduct",
            "doc-contributing",
            "doc-readme",
            "doc-support-policy",
            "license-identified",
            "license-present",
            "supply-lockfile",
            "supply-manifest",
            "supply-sbom-basis",
            "supply-secrets",
            "supply-updates",
            "ci-action-pinning",
            "ci-present",
            "ci-release-integrity",
            "ci-tests",
            "disclosure-contact",
            "disclosure-policy",
            "disclosure-response-time",
            "disclosure-security-txt",
        ]
    );
}

#[test]
fn json_shape_is_stable() {
    let dir = good_repo();
    let report = run(dir.path());
    let json = render_json(&report);

    assert_eq!(json, render_json(&run(dir.path())));
    for key in [
        "\"tool\":",
        "\"version\":",
        "\"repository\":",
        "\"grade\":",
        "\"score\":",
        "\"counts\":",
        "\"skipped\":",
        "\"categories\":",
        "\"findings\":",
        "\"disclaimer\":",
    ] {
        assert!(json.contains(key), "missing top-level key {key}");
    }
    for key in [
        "\"id\":",
        "\"category\":",
        "\"severity\":",
        "\"title\":",
        "\"evidence\":",
        "\"why\":",
        "\"source\":",
        "\"fix\":",
    ] {
        assert!(json.contains(key), "missing finding key {key}");
    }
    assert!(json.contains("\"grade\": \"A\""));
    assert!(json.contains("\"score\": 100"));
}

#[test]
fn every_report_carries_the_disclaimer() {
    let dir = bare_repo();
    let report = run(dir.path());
    let text = render_text(&report, RenderOptions { color: false });
    let json = render_json(&report);

    // The text report wraps at a fixed width, so compare on collapsed
    // whitespace rather than on the literal bytes.
    for out in [&text, &json] {
        let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("not legal advice"));
        assert!(flat.contains("not a certification"));
        assert!(flat.contains("manufacturers placing products on the EU market"));
        assert!(flat.contains("open source stewards have a lighter regime"));
    }
    // The tool must never assert compliance.
    assert!(!text.to_lowercase().contains("cra compliant"));
    assert!(!json.to_lowercase().contains("cra compliant"));
}

#[test]
fn empty_directory_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let report = run(dir.path());
    assert!(report.score.is_some());
    assert!(report.has_fail());
}
