//! End-to-end tests of the binary: exit codes, flags, and output plumbing.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_readyproof");
const SHA: &str = "11bd71901bbe5b1630ceea73d27597364c9af683";

fn write(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn readyproof(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run readyproof")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

/// A repo with one WARN (a mutable action tag) and no FAILs.
fn warn_only_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "README.md", "# x\n");
    write(
        root,
        "LICENSE",
        "MIT License\n\nPermission is hereby granted, free of charge, to any person\n",
    );
    write(root, "CONTRIBUTING.md", "# Contributing\n");
    write(root, "CODE_OF_CONDUCT.md", "# Code of Conduct\n");
    write(
        root,
        "SECURITY.md",
        "Report to security@fixture.example.org. Initial response within 72 hours.\n",
    );
    write(root, "Cargo.toml", "[package]\n");
    write(root, "Cargo.lock", "version = 4\n");
    write(root, ".github/dependabot.yml", "version: 2\n");
    write(
        root,
        ".github/workflows/ci.yml",
        "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n      - run: cargo test\n",
    );
    dir
}

#[test]
fn clean_repo_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "README.md", "# x\n");
    write(
        root,
        "LICENSE",
        "MIT License\n\nPermission is hereby granted, free of charge, to any person\n",
    );
    write(root, "CONTRIBUTING.md", "# Contributing\n");
    write(root, "CODE_OF_CONDUCT.md", "# Code of Conduct\n");
    write(
        root,
        "SECURITY.md",
        "Report to security@fixture.example.org. Initial response within 72 hours.\n",
    );
    write(root, "Cargo.toml", "[package]\n");
    write(root, "Cargo.lock", "version = 4\n");
    write(root, ".github/dependabot.yml", "version: 2\n");
    write(
        root,
        ".github/workflows/ci.yml",
        &format!(
            "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{SHA}\n      - run: cargo test\n"
        ),
    );

    let out = readyproof(&[root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("grade A"));
}

#[test]
fn failures_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "src/main.rs", "fn main() {}\n");
    let out = readyproof(&[dir.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn strict_turns_warnings_into_a_nonzero_exit() {
    let dir = warn_only_repo();
    let path = dir.path().to_str().unwrap();

    let lenient = readyproof(&[path]);
    assert_eq!(lenient.status.code(), Some(0));

    let strict = readyproof(&[path, "--strict"]);
    assert_eq!(strict.status.code(), Some(1));
}

#[test]
fn skipping_the_warning_check_makes_strict_pass() {
    let dir = warn_only_repo();
    let path = dir.path().to_str().unwrap();

    let out = readyproof(&[path, "--strict", "--skip", "ci-action-pinning"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!stdout(&out).contains("ci-action-pinning"));
    assert!(stdout(&out).contains("1 skipped"));
}

#[test]
fn only_restricts_the_report_to_one_category() {
    let dir = warn_only_repo();
    let out = readyproof(&[dir.path().to_str().unwrap(), "--only", "disclosure"]);
    let text = stdout(&out);

    assert!(text.contains("Disclosure"));
    assert!(!text.contains("Documentation"));
    assert!(text.contains("4 check(s) run, 15 skipped"));
}

#[test]
fn unknown_check_id_and_category_exit_two() {
    let dir = warn_only_repo();
    let path = dir.path().to_str().unwrap();

    let bad_skip = readyproof(&[path, "--skip", "no-such-check"]);
    assert_eq!(bad_skip.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_skip.stderr).contains("unknown check id"));

    let bad_category = readyproof(&[path, "--only", "nonsense"]);
    assert_eq!(bad_category.status.code(), Some(2));

    let missing_path = readyproof(&["/this/path/does/not/exist"]);
    assert_eq!(missing_path.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_path.stderr).contains("not a directory"));
}

#[test]
fn json_mode_is_uncolored_and_parses_as_one_object() {
    let dir = warn_only_repo();
    let out = readyproof(&[dir.path().to_str().unwrap(), "--json"]);
    let text = stdout(&out);

    assert!(!text.contains('\x1b'));
    assert!(text.starts_with('{'));
    assert!(text.trim_end().ends_with('}'));
    assert_eq!(text.matches("\"tool\"").count(), 1);
    assert!(text.contains("\"severity\": \"warn\""));
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn quiet_prints_exactly_one_stdout_line_and_frames_on_stderr() {
    let dir = warn_only_repo();
    let out = readyproof(&[dir.path().to_str().unwrap(), "--quiet"]);
    let text = stdout(&out);

    assert_eq!(text.lines().count(), 1);
    assert!(text.starts_with("readyproof: "));
    assert!(text.contains("grade "));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not legal advice"));
}

#[test]
fn output_is_byte_identical_across_runs() {
    let dir = warn_only_repo();
    let path = dir.path().to_str().unwrap();

    let a = readyproof(&[path]);
    let b = readyproof(&[path]);
    assert_eq!(a.stdout, b.stdout);

    let ja = readyproof(&[path, "--json"]);
    let jb = readyproof(&[path, "--json"]);
    assert_eq!(ja.stdout, jb.stdout);
}

#[test]
fn no_color_flag_and_env_both_suppress_escapes() {
    let dir = warn_only_repo();
    let out = readyproof(&[dir.path().to_str().unwrap(), "--no-color"]);
    assert!(!stdout(&out).contains('\x1b'));
}

#[test]
fn help_and_version_work() {
    let help = readyproof(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    let text = stdout(&help);
    assert!(text.contains("--strict"));
    assert!(text.contains("EXIT CODES"));
    assert!(text.contains("not legal advice"));

    let version = readyproof(&["--version"]);
    assert_eq!(version.status.code(), Some(0));
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn secret_values_never_reach_stdout_or_stderr() {
    const CANARY: &str = "CANARY-VALUE-MUST-NEVER-APPEAR";
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "README.md", "# x\n");
    write(dir.path(), ".env.production", &format!("TOKEN={CANARY}\n"));
    let path = dir.path().to_str().unwrap();

    for args in [vec![path], vec![path, "--json"], vec![path, "--quiet"]] {
        let out = readyproof(&args);
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !combined.contains(CANARY),
            "secret leaked with args {args:?}"
        );
    }

    let report = readyproof(&[path]);
    assert!(stdout(&report).contains(".env.production (environment file)"));
    assert_eq!(report.status.code(), Some(1));
}

#[test]
fn map_prints_the_scorecard_and_slsa_table() {
    let out = Command::new(BIN).arg("--map").output().expect("run");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("disclosure-policy"));
    assert!(text.contains("Security-Policy (same)"));
    assert!(text.contains("Build L1-L2"));
    assert!(text.contains("Branch-Protection"));

    let json = Command::new(BIN)
        .args(["--map", "--json"])
        .output()
        .expect("run");
    let doc = String::from_utf8(json.stdout).unwrap();
    assert!(doc.contains("\"scorecard_not_covered\""));
    assert!(doc.contains("\"relation\": \"partial\""));
}

#[test]
fn fix_creates_starter_files_without_overwriting() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    fs::write(dir.path().join("CONTRIBUTING.md"), "# mine\n").unwrap();

    let dry = Command::new(BIN)
        .arg(dir.path())
        .args(["--fix", "--dry-run", "--quiet"])
        .output()
        .expect("run");
    let log = String::from_utf8(dry.stderr).unwrap();
    assert!(log.contains("would create SECURITY.md"), "{log}");
    assert!(!dir.path().join("SECURITY.md").exists());

    let out = Command::new(BIN)
        .arg(dir.path())
        .args(["--fix", "--json"])
        .output()
        .expect("run");
    let log = String::from_utf8(out.stderr).unwrap();
    assert!(log.contains("created SECURITY.md"), "{log}");
    assert!(log.contains("left license-present to you"), "{log}");
    assert_eq!(
        fs::read_to_string(dir.path().join("CONTRIBUTING.md")).unwrap(),
        "# mine\n"
    );
    let dependabot = fs::read_to_string(dir.path().join(".github/dependabot.yml")).unwrap();
    assert!(dependabot.contains("package-ecosystem: \"cargo\""));
    assert!(dir.path().join("CODE_OF_CONDUCT.md").exists());
    // The report is the audit after the fix: the policy now exists, but its
    // placeholder address is still flagged.
    let doc = String::from_utf8(out.stdout).unwrap();
    assert!(doc.contains("Security policy present"), "{doc}");
    assert!(doc.contains("placeholder"), "{doc}");
}
