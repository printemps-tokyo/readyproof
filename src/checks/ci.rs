//! CI checks: is there continuous integration, does it run tests, are
//! third-party actions pinned, and does the release path publish integrity
//! material.

use super::Meta;
use crate::model::{Category, Finding, Severity};
use crate::snapshot::RepoSnapshot;
use crate::text::{classify_ref, parse_uses, RefKind};

const MAX_EVIDENCE: usize = 12;

/// GitHub Actions workflow files, sorted by path.
fn workflows(snap: &RepoSnapshot) -> Vec<(&str, &str)> {
    snap.texts()
        .filter(|(path, _)| {
            let lower = path.to_ascii_lowercase();
            lower.starts_with(".github/workflows/")
                && (lower.ends_with(".yml") || lower.ends_with(".yaml"))
        })
        .collect()
}

/// Config files for CI systems readyproof does not parse. Their presence still
/// answers "does this project have CI?".
const OTHER_CI_CONFIGS: &[&str] = &[
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    "Jenkinsfile",
    ".travis.yml",
    ".woodpecker.yml",
    ".drone.yml",
    "bitbucket-pipelines.yml",
    ".builds/build.yml",
];

fn cap(mut items: Vec<String>) -> Vec<String> {
    if items.len() > MAX_EVIDENCE {
        let extra = items.len() - MAX_EVIDENCE;
        items.truncate(MAX_EVIDENCE);
        items.push(format!("... and {extra} more"));
    }
    items
}

const PRESENT_META: Meta = Meta {
    id: "ci-present",
    category: Category::Ci,
    why: "Continuous integration is what turns a test suite into evidence that the code still \
works. OpenSSF lists it as suggested rather than required at the passing level, so its absence is \
a warning.",
    source: "OpenSSF Best Practices, passing level: test_continuous_integration (SUGGESTED) \
(https://www.bestpractices.dev/en/criteria/0)",
    fix: "Add a .github/workflows/ci.yml that builds and tests the project on every push and pull \
request.",
};

/// `ci-present`.
pub fn present(snap: &RepoSnapshot) -> Finding {
    let wfs = workflows(snap);
    if !wfs.is_empty() {
        let evidence = cap(wfs.iter().map(|(p, _)| p.to_string()).collect());
        return PRESENT_META.finding(
            Severity::Pass,
            format!("{} GitHub Actions workflow(s) present", wfs.len()),
            evidence,
        );
    }
    if let Some(path) = snap.find_first(OTHER_CI_CONFIGS) {
        return PRESENT_META.finding(
            Severity::Pass,
            "Non-GitHub CI configuration present (not analyzed further)",
            vec![path.to_string()],
        );
    }
    PRESENT_META.finding(Severity::Warn, "No CI configuration found", Vec::new())
}

/// Commands that indicate a workflow actually runs the test suite.
const TEST_MARKERS: &[&str] = &[
    "cargo test",
    "cargo nextest",
    "npm test",
    "npm run test",
    "yarn test",
    "pnpm test",
    "pnpm run test",
    "bun test",
    "pytest",
    "python -m unittest",
    "tox",
    "go test",
    "mvn test",
    "mvn verify",
    "gradle test",
    "gradlew test",
    "rspec",
    "phpunit",
    "dotnet test",
    "make test",
    "make check",
    "ctest",
    "deno test",
    "swift test",
];

const TESTS_META: Meta = Meta {
    id: "ci-tests",
    category: Category::Ci,
    why: "OpenSSF requires an automated test suite at the passing level, and a suite nobody runs \
automatically decays. A downstream reviewer checks whether CI actually invokes the tests, not just \
whether tests exist.",
    source: "OpenSSF Best Practices, passing level: test, test_invocation, \
test_continuous_integration (https://www.bestpractices.dev/en/criteria/0)",
    fix:
        "Add a `cargo test` (or equivalent) step to the CI workflow so every push and pull request \
runs the suite.",
};

/// `ci-tests`.
pub fn tests(snap: &RepoSnapshot) -> Finding {
    let wfs = workflows(snap);
    if wfs.is_empty() {
        return TESTS_META.finding(
            Severity::Info,
            "Not evaluated: no GitHub Actions workflows to inspect",
            Vec::new(),
        );
    }
    for (path, text) in &wfs {
        for (n, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let Some(marker) = TEST_MARKERS.iter().find(|m| lower.contains(**m)) else {
                continue;
            };
            return TESTS_META.finding(
                Severity::Pass,
                "CI runs the test suite",
                vec![format!("{path}:{}: {marker}", n + 1)],
            );
        }
    }
    TESTS_META.finding(
        Severity::Warn,
        "No test command found in any workflow",
        cap(wfs.iter().map(|(p, _)| p.to_string()).collect()),
    )
}

const PINNING_META: Meta = Meta {
    id: "ci-action-pinning",
    category: Category::Ci,
    why: "A tag or branch reference resolves at run time, so whoever controls the upstream action \
can change what executes inside your workflow, with whatever token that job holds. Pinning to a \
full commit SHA removes that. The honest tradeoff: tag pinning is extremely common (including \
across this organization's own repositories), major-version tags from well-known publishers are a \
reasonable risk position, and SHA pinning costs you automatic patch updates unless Dependabot \
keeps the pins fresh. That is why this is a warning, not a failure.",
    source: "OpenSSF supply-chain hardening guidance and OpenSSF Baseline build-release controls; \
GitHub's own security hardening guide for Actions \
(https://baseline.openssf.org/, https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)",
    fix: "Replace `uses: owner/action@v4` with `uses: owner/action@<40-char-sha> # v4`, and enable \
Dependabot for the github-actions ecosystem so the pins keep moving.",
};

/// `ci-action-pinning`.
pub fn action_pinning(snap: &RepoSnapshot) -> Finding {
    let wfs = workflows(snap);
    if wfs.is_empty() {
        return PINNING_META.finding(
            Severity::Info,
            "Not evaluated: no GitHub Actions workflows to inspect",
            Vec::new(),
        );
    }

    let mut mutable = Vec::new();
    let mut pinned = 0usize;
    for (path, text) in &wfs {
        for (n, line) in text.lines().enumerate() {
            let Some(uses) = parse_uses(line) else {
                continue;
            };
            match classify_ref(uses) {
                RefKind::CommitSha => pinned += 1,
                RefKind::Mutable => mutable.push(format!("{path}:{}: {uses}", n + 1)),
                RefKind::NoRef => {
                    mutable.push(format!("{path}:{}: {uses} (no ref: default branch)", n + 1))
                }
                RefKind::Local | RefKind::Docker => {}
            }
        }
    }

    if mutable.is_empty() {
        if pinned == 0 {
            return PINNING_META.finding(
                Severity::Info,
                "No third-party actions referenced",
                Vec::new(),
            );
        }
        return PINNING_META.finding(
            Severity::Pass,
            format!("All {pinned} action reference(s) pinned to a commit SHA"),
            Vec::new(),
        );
    }
    PINNING_META.finding(
        Severity::Warn,
        format!(
            "{} action reference(s) pinned to a mutable tag or branch",
            mutable.len()
        ),
        cap(mutable),
    )
}

/// Signals that a workflow is on the release path.
const RELEASE_MARKERS: &[&str] = &[
    "gh release",
    "action-gh-release",
    "upload-release-asset",
    "release-please",
    "goreleaser",
    "cargo publish",
    "npm publish",
    "twine upload",
    "pypi",
];

/// Signals that a release publishes checksums, signatures or attestations.
const INTEGRITY_MARKERS: &[&str] = &[
    "sha256sum",
    "shasum -a 256",
    "sha256sums",
    "certutil -hashfile",
    "cosign",
    "sigstore",
    "gpg --detach-sig",
    "gpg -b ",
    "minisign",
    "attest-build-provenance",
    "gh attestation",
    "slsa-github-generator",
    "checksums",
];

const RELEASE_META: Meta = Meta {
    id: "ci-release-integrity",
    category: Category::Ci,
    why: "A downloaded binary is only as trustworthy as the thing that lets you verify it. \
Publishing SHA256SUMS, a signature, or a build attestation alongside release artifacts lets \
consumers detect tampering between your CI and their disk. Note that signed releases are an \
OpenSSF silver/gold criterion, not a passing one, so this is a warning at most.",
    source: "OpenSSF Baseline OSPS-BR-06.01 (releases signed or covered by a signed manifest of \
cryptographic hashes); OpenSSF CRA guidance on release integrity \
(https://baseline.openssf.org/, https://openssf.org/category/policy/cra/)",
    fix:
        "In the release workflow, run `shasum -a 256 <artifacts> > SHA256SUMS` and upload it with \
the artifacts, or add build provenance with actions/attest-build-provenance.",
};

/// `ci-release-integrity`.
pub fn release_integrity(snap: &RepoSnapshot) -> Finding {
    let wfs = workflows(snap);
    if wfs.is_empty() {
        return RELEASE_META.finding(
            Severity::Info,
            "Not evaluated: no GitHub Actions workflows to inspect",
            Vec::new(),
        );
    }

    let mut release_workflows = Vec::new();
    for (path, text) in &wfs {
        let lower = text.to_ascii_lowercase();
        let name_hints_release = {
            let stem = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
            stem.contains("release") || stem.contains("publish")
        };
        if name_hints_release || RELEASE_MARKERS.iter().any(|m| lower.contains(m)) {
            release_workflows.push((*path, lower));
        }
    }

    if release_workflows.is_empty() {
        return RELEASE_META.finding(
            Severity::Info,
            "No release workflow detected; release integrity not evaluated",
            Vec::new(),
        );
    }

    let mut evidence = Vec::new();
    for (path, lower) in &release_workflows {
        if let Some(marker) = INTEGRITY_MARKERS.iter().find(|m| lower.contains(**m)) {
            evidence.push(format!("{path}: {}", marker.trim()));
        }
    }
    if !evidence.is_empty() {
        return RELEASE_META.finding(
            Severity::Pass,
            "Release workflow publishes checksums, signatures or attestations",
            cap(evidence),
        );
    }
    RELEASE_META.finding(
        Severity::Warn,
        "Release workflow publishes no checksums or signatures",
        cap(release_workflows
            .iter()
            .map(|(p, _)| p.to_string())
            .collect()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "11bd71901bbe5b1630ceea73d27597364c9af683";

    #[test]
    fn mutable_tag_warns_and_sha_passes() {
        let tagged = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/ci.yml",
                Some("jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"),
            )],
        );
        let f = action_pinning(&tagged);
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(
            f.evidence,
            [".github/workflows/ci.yml:4: actions/checkout@v4"]
        );

        let pinned = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/ci.yml",
                Some(format!(
                    "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{SHA} # v4\n"
                )),
            )],
        );
        assert_eq!(action_pinning(&pinned).severity, Severity::Pass);
    }

    #[test]
    fn local_actions_do_not_count() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/ci.yml",
                Some("steps:\n  - uses: ./.github/actions/setup\n"),
            )],
        );
        let f = action_pinning(&snap);
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn tests_check_finds_the_command() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/ci.yml",
                Some("steps:\n  - run: cargo test --all\n"),
            )],
        );
        let f = tests(&snap);
        assert_eq!(f.severity, Severity::Pass);
        assert_eq!(f.evidence, [".github/workflows/ci.yml:2: cargo test"]);
    }

    #[test]
    fn workflow_without_tests_warns() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/ci.yml",
                Some("steps:\n  - run: cargo build\n"),
            )],
        );
        assert_eq!(tests(&snap).severity, Severity::Warn);
    }

    #[test]
    fn release_integrity_states() {
        let none = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/ci.yml",
                Some("steps:\n  - run: cargo test\n"),
            )],
        );
        assert_eq!(release_integrity(&none).severity, Severity::Info);

        let unsigned = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/release.yml",
                Some("steps:\n  - uses: softprops/action-gh-release@v2\n"),
            )],
        );
        assert_eq!(release_integrity(&unsigned).severity, Severity::Warn);

        let signed = RepoSnapshot::from_entries(
            "x",
            [(
                ".github/workflows/release.yml",
                Some("steps:\n  - run: shasum -a 256 dist/* > SHA256SUMS\n"),
            )],
        );
        assert_eq!(release_integrity(&signed).severity, Severity::Pass);
    }

    #[test]
    fn non_github_ci_still_counts_as_present() {
        let snap = RepoSnapshot::from_entries("x", [(".gitlab-ci.yml", None::<&str>)]);
        assert_eq!(present(&snap).severity, Severity::Pass);
        assert_eq!(tests(&snap).severity, Severity::Info);
        assert_eq!(action_pinning(&snap).severity, Severity::Info);
    }
}
