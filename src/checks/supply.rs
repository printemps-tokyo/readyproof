//! Supply-chain checks: dependency manifests, lockfiles, the basis an SBOM
//! would be generated from, the dependency-update process, and a path-only
//! secret-hygiene smoke test.

use super::Meta;
use crate::model::{Category, Finding, Severity};
use crate::snapshot::RepoSnapshot;
use crate::text::contains_any;

/// How many evidence lines a single finding will print before summarizing.
const MAX_EVIDENCE: usize = 12;

/// A dependency ecosystem: the manifest that declares dependencies, and the
/// lockfiles that pin them.
struct Ecosystem {
    /// Lowercased manifest basename.
    manifest: &'static str,
    /// Human name used in evidence lines.
    name: &'static str,
    /// Lockfile basenames, checked as siblings of the manifest. An empty list
    /// means the ecosystem has no standard lockfile, so its absence is not
    /// held against the project.
    locks: &'static [&'static str],
}

/// Ecosystems recognized by the manifest and lockfile checks. Not exhaustive;
/// an unrecognized manifest simply is not counted, never counted against.
const ECOSYSTEMS: &[Ecosystem] = &[
    Ecosystem {
        manifest: "cargo.toml",
        name: "Rust (Cargo)",
        locks: &["Cargo.lock"],
    },
    Ecosystem {
        manifest: "package.json",
        name: "JavaScript (npm/yarn/pnpm/bun)",
        locks: &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lockb",
            "bun.lock",
        ],
    },
    Ecosystem {
        manifest: "go.mod",
        name: "Go (modules)",
        locks: &["go.sum"],
    },
    Ecosystem {
        manifest: "pyproject.toml",
        name: "Python (pyproject)",
        locks: &["poetry.lock", "pdm.lock", "uv.lock", "requirements.lock"],
    },
    Ecosystem {
        // Handled specially: the file is both the manifest and, when every
        // requirement is pinned, the lock.
        manifest: "requirements.txt",
        name: "Python (requirements)",
        locks: &[],
    },
    Ecosystem {
        manifest: "gemfile",
        name: "Ruby (Bundler)",
        locks: &["Gemfile.lock"],
    },
    Ecosystem {
        manifest: "composer.json",
        name: "PHP (Composer)",
        locks: &["composer.lock"],
    },
    Ecosystem {
        manifest: "pom.xml",
        name: "Java (Maven)",
        locks: &[],
    },
    Ecosystem {
        manifest: "build.gradle",
        name: "Java (Gradle)",
        locks: &["gradle.lockfile"],
    },
    Ecosystem {
        manifest: "build.gradle.kts",
        name: "Kotlin (Gradle)",
        locks: &["gradle.lockfile"],
    },
    Ecosystem {
        manifest: "pubspec.yaml",
        name: "Dart (pub)",
        locks: &["pubspec.lock"],
    },
    Ecosystem {
        manifest: "mix.exs",
        name: "Elixir (Mix)",
        locks: &["mix.lock"],
    },
    Ecosystem {
        manifest: "package.swift",
        name: "Swift (SwiftPM)",
        locks: &["Package.resolved"],
    },
    Ecosystem {
        manifest: "podfile",
        name: "CocoaPods",
        locks: &["Podfile.lock"],
    },
];

/// Whether a manifest's dependencies are pinned by a committed lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockStatus {
    Found,
    Missing,
    /// The ecosystem has no standard lockfile (e.g. Maven).
    NotApplicable,
}

struct Detected {
    path: String,
    ecosystem: &'static str,
    lock: Option<String>,
    status: LockStatus,
}

impl Detected {
    fn describe(&self) -> String {
        match (&self.lock, self.status) {
            (Some(lock), _) => format!("{} ({}) -> {}", self.path, self.ecosystem, lock),
            (None, LockStatus::NotApplicable) => {
                format!("{} ({}) -> no standard lockfile", self.path, self.ecosystem)
            }
            (None, _) => format!("{} ({}) -> no lockfile", self.path, self.ecosystem),
        }
    }
}

/// Find every recognized dependency manifest and its sibling lockfile.
fn detect(snap: &RepoSnapshot) -> Vec<Detected> {
    let mut out = Vec::new();
    for path in snap.paths() {
        let (dir, base) = split_path(path);
        let base_lower = base.to_ascii_lowercase();

        let eco = ECOSYSTEMS.iter().find(|e| e.manifest == base_lower);
        let Some(eco) = eco else {
            // .NET projects are matched by extension rather than by name.
            if base_lower.ends_with(".csproj") || base_lower.ends_with(".fsproj") {
                let lock = snap
                    .find(&format!("{dir}packages.lock.json"))
                    .map(str::to_string);
                let status = if lock.is_some() {
                    LockStatus::Found
                } else {
                    LockStatus::Missing
                };
                out.push(Detected {
                    path: path.clone(),
                    ecosystem: ".NET (NuGet)",
                    lock,
                    status,
                });
            }
            continue;
        };

        if eco.manifest == "requirements.txt" {
            let pinned = snap.text(path).is_some_and(is_pinned_requirements);
            out.push(Detected {
                path: path.clone(),
                ecosystem: eco.name,
                lock: pinned.then(|| format!("{path} (fully pinned)")),
                status: if pinned {
                    LockStatus::Found
                } else {
                    LockStatus::Missing
                },
            });
            continue;
        }

        let lock = eco
            .locks
            .iter()
            .find_map(|l| snap.find(&format!("{dir}{l}")))
            .map(str::to_string);
        let status = match (&lock, eco.locks.is_empty()) {
            (Some(_), _) => LockStatus::Found,
            (None, true) => LockStatus::NotApplicable,
            (None, false) => LockStatus::Missing,
        };
        out.push(Detected {
            path: path.clone(),
            ecosystem: eco.name,
            lock,
            status,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Split a repo-relative path into (`dir/` including the trailing slash, basename).
fn split_path(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    }
}

/// A requirements.txt counts as its own lock when every requirement carries an
/// exact `==` pin, or when hashes are present (pip-compile --generate-hashes).
fn is_pinned_requirements(text: &str) -> bool {
    if text.contains("--hash=") {
        return true;
    }
    let mut requirements = 0usize;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        requirements += 1;
        if !line.contains("==") {
            return false;
        }
    }
    requirements > 0
}

/// Cap evidence to keep monorepo output readable.
fn cap(mut items: Vec<String>) -> Vec<String> {
    if items.len() > MAX_EVIDENCE {
        let extra = items.len() - MAX_EVIDENCE;
        items.truncate(MAX_EVIDENCE);
        items.push(format!("... and {extra} more"));
    }
    items
}

const MANIFEST_META: Meta = Meta {
    id: "supply-manifest",
    category: Category::SupplyChain,
    why: "An SBOM and any vulnerability scan start from a declared dependency list committed to \
the repository. Without one, downstream consumers have to reverse-engineer what the project \
depends on.",
    source:
        "OpenSSF Baseline OSPS-QA-02.01 (a dependency list accounting for direct dependencies) \
(https://baseline.openssf.org/)",
    fix: "Commit the dependency manifest for your ecosystem (Cargo.toml, package.json, go.mod, \
pyproject.toml, ...). If the project genuinely has no dependencies, say so in the README.",
};

/// `supply-manifest`.
pub fn manifest(snap: &RepoSnapshot) -> Finding {
    let detected = detect(snap);
    if detected.is_empty() {
        return MANIFEST_META.finding(
            Severity::Warn,
            "No recognized dependency manifest found",
            Vec::new(),
        );
    }
    let evidence = cap(detected
        .iter()
        .map(|d| format!("{} ({})", d.path, d.ecosystem))
        .collect());
    MANIFEST_META.finding(
        Severity::Pass,
        format!("{} dependency manifest(s) detected", detected.len()),
        evidence,
    )
}

const LOCKFILE_META: Meta = Meta {
    id: "supply-lockfile",
    category: Category::SupplyChain,
    why:
        "A committed lockfile is what makes a build reproducible and makes \"which exact versions \
shipped\" answerable after the fact. Libraries are the honest exception: a library's lockfile does \
not constrain its consumers, but it still pins CI and makes an audit repeatable.",
    source: "OpenSSF Baseline OSPS-QA-02.01; OpenSSF Best Practices build/test reproducibility \
themes (https://baseline.openssf.org/, https://www.bestpractices.dev/en/criteria/0)",
    fix: "Commit the lockfile next to each manifest (Cargo.lock, package-lock.json, go.sum, \
poetry.lock, ...). For Python requirements, pin exact versions with pip-compile.",
};

/// `supply-lockfile`.
pub fn lockfile(snap: &RepoSnapshot) -> Finding {
    let detected = detect(snap);
    if detected.is_empty() {
        return LOCKFILE_META.finding(
            Severity::Info,
            "Not evaluated: no dependency manifest found",
            Vec::new(),
        );
    }
    let missing: Vec<&Detected> = detected
        .iter()
        .filter(|d| d.status == LockStatus::Missing)
        .collect();
    if missing.is_empty() {
        let evidence = cap(detected.iter().map(Detected::describe).collect());
        return LOCKFILE_META.finding(
            Severity::Pass,
            "Every manifest has a committed lockfile",
            evidence,
        );
    }
    let evidence = cap(missing.iter().map(|d| d.describe()).collect());
    LOCKFILE_META.finding(
        Severity::Warn,
        format!("{} manifest(s) without a committed lockfile", missing.len()),
        evidence,
    )
}

const SBOM_META: Meta = Meta {
    id: "supply-sbom-basis",
    category: Category::SupplyChain,
    why: "Downstream manufacturers have to draw up an SBOM for the products they place on the \
market, and they build it from what upstream declares. Upstream maintainers are not obliged to \
publish one; this finding simply shows what a generator would read.",
    source: "OpenSSF Baseline OSPS-QA-02.02; OpenSSF SBOM guidance under its CRA materials \
(https://baseline.openssf.org/, https://openssf.org/category/policy/cra/)",
    fix: "Optional. If you want to publish an SBOM, generate CycloneDX or SPDX from these \
manifests (cargo-cyclonedx, syft, cdxgen) and attach it to each release.",
};

/// `supply-sbom-basis` — informational either way.
pub fn sbom_basis(snap: &RepoSnapshot) -> Finding {
    let detected = detect(snap);
    if detected.is_empty() {
        return SBOM_META.finding(
            Severity::Info,
            "No dependency manifest for an SBOM to be generated from",
            Vec::new(),
        );
    }
    let evidence = cap(detected.iter().map(Detected::describe).collect());
    SBOM_META.finding(
        Severity::Info,
        format!(
            "An SBOM would be generated from {} manifest(s)",
            detected.len()
        ),
        evidence,
    )
}

pub(crate) const UPDATE_CONFIGS: &[&str] = &[
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
    ".github/renovate.json",
    ".github/renovate.json5",
    ".gitlab/renovate.json",
];

/// CI steps that automatically evaluate dependencies against known
/// vulnerabilities (OSPS-VM-05.03).
const SCANNER_MARKERS: &[&str] = &[
    "dependency-review-action",
    "cargo audit",
    "cargo-audit",
    "cargo deny",
    "cargo-deny",
    "osv-scanner",
    "npm audit",
    "pip-audit",
    "govulncheck",
    "trivy",
    "snyk",
];

const UPDATE_DOC_MARKERS: &[&str] = &[
    "dependabot",
    "renovate",
    "dependency update",
    "update dependencies",
    "updating dependencies",
    "dependency policy",
    "cargo update",
    "cargo audit",
];

const UPDATES_META: Meta = Meta {
    id: "supply-updates",
    category: Category::SupplyChain,
    why: "Downstream consumers want to know that a vulnerable transitive dependency will be \
noticed. Either automation or a documented, followed process answers that; neither answers it \
badly.",
    source: "OpenSSF Baseline OSPS-DO-06.01 (document how dependencies are selected, obtained and \
tracked) and OSPS-VM-05.03 (automatic evaluation of changes against known vulnerabilities) \
(https://baseline.openssf.org/)",
    fix: "Add .github/dependabot.yml (or a Renovate config) covering your package ecosystem and \
github-actions, or document your update cadence in CONTRIBUTING.md.",
};

/// `supply-updates`.
pub fn updates(snap: &RepoSnapshot) -> Finding {
    if let Some(path) = snap.find_first(UPDATE_CONFIGS) {
        return UPDATES_META.finding(
            Severity::Pass,
            "Automated dependency updates configured",
            vec![path.to_string()],
        );
    }

    for (path, text) in snap.texts() {
        if !path.to_ascii_lowercase().starts_with(".github/workflows/") {
            continue;
        }
        let lower = text.to_ascii_lowercase();
        if let Some(marker) = SCANNER_MARKERS.iter().find(|m| lower.contains(**m)) {
            return UPDATES_META.finding(
                Severity::Pass,
                "CI evaluates dependencies against known vulnerabilities",
                vec![format!("{path}: {marker}")],
            );
        }
    }

    let doc_candidates = [
        snap.find_first(&["CONTRIBUTING.md", ".github/CONTRIBUTING.md", "CONTRIBUTING"]),
        snap.find_first(super::disclosure::SECURITY_CANDIDATES),
        snap.find_first(&["README.md", "README"]),
    ];
    for path in doc_candidates.into_iter().flatten() {
        let Some(text) = snap.text(path) else {
            continue;
        };
        if contains_any(&text.to_ascii_lowercase(), UPDATE_DOC_MARKERS) {
            return UPDATES_META.finding(
                Severity::Pass,
                "Dependency-update process documented",
                vec![path.to_string()],
            );
        }
    }

    UPDATES_META.finding(
        Severity::Warn,
        "No dependency-update automation or documented process found",
        Vec::new(),
    )
}

/// `.env.<suffix>` spellings that are templates, not secrets.
const ENV_TEMPLATE_SUFFIXES: &[&str] = &[
    "example", "sample", "template", "dist", "tpl", "defaults", "schema", "test",
];

/// Extensions that are almost always private key material or credentials.
const HIGH_CONFIDENCE_EXTENSIONS: &[(&str, &str)] = &[
    (".p12", "PKCS#12 keystore"),
    (".pfx", "PKCS#12 keystore"),
    (".jks", "Java keystore"),
    (".ppk", "PuTTY private key"),
    (".p8", "PKCS#8 private key"),
];

/// Extensions that frequently hold key material but also legitimately hold
/// public certificates, so they are reported at a lower confidence.
const LOW_CONFIDENCE_EXTENSIONS: &[(&str, &str)] = &[
    (".pem", "PEM file (may be a public certificate)"),
    (".key", "key file"),
    (".keystore", "keystore"),
];

const HIGH_CONFIDENCE_NAMES: &[(&str, &str)] = &[
    ("id_rsa", "SSH private key"),
    ("id_dsa", "SSH private key"),
    ("id_ecdsa", "SSH private key"),
    ("id_ed25519", "SSH private key"),
    (".netrc", "netrc credentials"),
    ("_netrc", "netrc credentials"),
    (".pgpass", "PostgreSQL password file"),
    (".htpasswd", "htpasswd file"),
    ("credentials.json", "credentials file"),
];

/// Confidence with which a path looks like it holds a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confidence {
    High,
    Low,
}

/// Classify a path by name alone.
///
/// This function never opens the file. The snapshot does not retain the bytes
/// of any path this can match (see `snapshot::is_readable_doc`), so it is
/// structurally impossible for a secret value to reach a finding.
fn secret_kind(path: &str) -> Option<(Confidence, &'static str)> {
    let (_, base) = split_path(path);
    let base = base.to_ascii_lowercase();

    // Public halves of key pairs are not secrets.
    if base.ends_with(".pub") {
        return None;
    }

    if base == ".env" {
        return Some((Confidence::High, "environment file"));
    }
    if let Some(suffix) = base.strip_prefix(".env.") {
        return if ENV_TEMPLATE_SUFFIXES.contains(&suffix) {
            None
        } else {
            Some((Confidence::High, "environment file"))
        };
    }
    if let Some(stem) = base.strip_suffix(".env") {
        return if ENV_TEMPLATE_SUFFIXES.contains(&stem) {
            None
        } else {
            Some((Confidence::High, "environment file"))
        };
    }

    if let Some((_, kind)) = HIGH_CONFIDENCE_NAMES.iter().find(|(n, _)| *n == base) {
        return Some((Confidence::High, kind));
    }
    if base.ends_with(".json")
        && contains_any(
            &base,
            &[
                "service-account",
                "service_account",
                "serviceaccount",
                "client_secret",
            ],
        )
    {
        return Some((Confidence::High, "service account credentials"));
    }
    if let Some((_, kind)) = HIGH_CONFIDENCE_EXTENSIONS
        .iter()
        .find(|(ext, _)| base.ends_with(*ext))
    {
        return Some((Confidence::High, kind));
    }
    if let Some((_, kind)) = LOW_CONFIDENCE_EXTENSIONS
        .iter()
        .find(|(ext, _)| base.ends_with(*ext))
    {
        return Some((Confidence::Low, kind));
    }
    None
}

const SECRETS_META: Meta = Meta {
    id: "supply-secrets",
    category: Category::SupplyChain,
    why: "A credential committed to history stays reachable after it is deleted, so a downstream \
reviewer treats any hit as a live incident until proven otherwise. This is a filename-only smoke \
test: readyproof never opens these files and never prints their contents, so it detects the shape \
of a mistake, not the secret itself.",
    source: "Downstream security-review question; OpenSSF Baseline access-control controls on \
credential management (https://baseline.openssf.org/)",
    fix: "Remove the file, rotate the credential (assume it is burned), add the pattern to \
.gitignore, and purge it from history with git-filter-repo. For content-level scanning of logs and \
diffs, use the companion tool `redact`.",
};

/// `supply-secrets` — path-based only, contents never read.
pub fn secrets(snap: &RepoSnapshot) -> Finding {
    let mut high = Vec::new();
    let mut low = Vec::new();
    for path in snap.paths() {
        let Some((confidence, kind)) = secret_kind(path) else {
            continue;
        };
        let line = format!("{path} ({kind})");
        match confidence {
            Confidence::High => high.push(line),
            Confidence::Low => low.push(line),
        }
    }

    if !high.is_empty() {
        let n = high.len() + low.len();
        high.extend(low);
        return SECRETS_META.finding(
            Severity::Fail,
            format!("{n} committed file(s) match secret-bearing filename patterns"),
            cap(high),
        );
    }
    if !low.is_empty() {
        return SECRETS_META.finding(
            Severity::Warn,
            format!(
                "{} committed file(s) may hold key material; review each",
                low.len()
            ),
            cap(low),
        );
    }
    SECRETS_META.finding(
        Severity::Pass,
        "No committed files match secret-bearing filename patterns",
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_detection_is_per_directory() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [
                ("Cargo.toml", None::<&str>),
                ("Cargo.lock", None),
                ("web/package.json", None),
            ],
        );
        let f = lockfile(&snap);
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(f.evidence.len(), 1);
        assert!(f.evidence[0].starts_with("web/package.json"));
    }

    #[test]
    fn maven_has_no_standard_lockfile() {
        let snap = RepoSnapshot::from_entries("x", [("pom.xml", None::<&str>)]);
        assert_eq!(lockfile(&snap).severity, Severity::Pass);
    }

    #[test]
    fn pinned_requirements_count_as_a_lock() {
        let pinned =
            RepoSnapshot::from_entries("x", [("requirements.txt", Some("flask==3.0.0\n# note\n"))]);
        assert_eq!(lockfile(&pinned).severity, Severity::Pass);

        let loose = RepoSnapshot::from_entries("x", [("requirements.txt", Some("flask\n"))]);
        assert_eq!(lockfile(&loose).severity, Severity::Warn);
    }

    #[test]
    fn secret_paths_are_classified_by_confidence() {
        assert_eq!(secret_kind(".env").map(|k| k.0), Some(Confidence::High));
        assert_eq!(
            secret_kind(".env.local").map(|k| k.0),
            Some(Confidence::High)
        );
        assert_eq!(secret_kind(".env.example"), None);
        assert_eq!(secret_kind("prod.env").map(|k| k.0), Some(Confidence::High));
        assert_eq!(
            secret_kind("deploy/id_rsa").map(|k| k.0),
            Some(Confidence::High)
        );
        assert_eq!(secret_kind("deploy/id_rsa.pub"), None);
        assert_eq!(
            secret_kind("gcp-service-account.json").map(|k| k.0),
            Some(Confidence::High)
        );
        assert_eq!(
            secret_kind("certs/ca.pem").map(|k| k.0),
            Some(Confidence::Low)
        );
        assert_eq!(secret_kind("src/main.rs"), None);
    }

    #[test]
    fn secrets_check_never_reads_contents() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [(".env", Some("AWS_SECRET_ACCESS_KEY=TOPSECRETVALUE"))],
        );
        let f = secrets(&snap);
        assert_eq!(f.severity, Severity::Fail);
        assert_eq!(f.evidence, [".env (environment file)"]);
        let rendered = format!("{f:?}");
        assert!(!rendered.contains("TOPSECRETVALUE"));
    }

    #[test]
    fn dependabot_config_passes_updates() {
        let snap = RepoSnapshot::from_entries("x", [(".github/dependabot.yml", None::<&str>)]);
        assert_eq!(updates(&snap).severity, Severity::Pass);

        let bare = RepoSnapshot::from_entries("x", [("Cargo.toml", None::<&str>)]);
        assert_eq!(updates(&bare).severity, Severity::Warn);
    }

    #[test]
    fn sbom_basis_is_informational() {
        let snap =
            RepoSnapshot::from_entries("x", [("Cargo.toml", None::<&str>), ("Cargo.lock", None)]);
        let f = sbom_basis(&snap);
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.evidence, ["Cargo.toml (Rust (Cargo)) -> Cargo.lock"]);
    }

    #[test]
    fn evidence_is_capped() {
        let items: Vec<String> = (0..30).map(|i| format!("item {i}")).collect();
        let capped = cap(items);
        assert_eq!(capped.len(), MAX_EVIDENCE + 1);
        assert_eq!(capped[MAX_EVIDENCE], "... and 18 more");
    }
}
