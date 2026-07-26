//! A read-once, in-memory view of a repository.
//!
//! Every check runs against a `RepoSnapshot` rather than the filesystem, which
//! keeps the check engine pure (and lets tests build a repository literally, in
//! memory, without a tempdir). The walk itself is `ignore::WalkBuilder`, the
//! same gitignore-aware walker repotome uses, so ignored build output never
//! shows up as "committed" evidence.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use ignore::WalkBuilder;

/// Largest file we will read into the snapshot. Only documentation and
/// workflow files are ever read, and none of them are legitimately larger.
const MAX_READ_BYTES: u64 = 256 * 1024;

/// An immutable view of the repository: every tracked path, plus the text of
/// the small set of files the checks actually need to read.
#[derive(Debug, Clone, Default)]
pub struct RepoSnapshot {
    root_name: String,
    /// Repository-relative paths with forward slashes, sorted, deduplicated.
    paths: Vec<String>,
    /// Lowercased path -> index into `paths`, for case-insensitive lookup
    /// (`LICENSE`, `license`, `License.md` all occur in the wild).
    lower: BTreeMap<String, usize>,
    /// Contents of files matching `is_readable_doc`. Keyed by the real path.
    texts: BTreeMap<String, String>,
}

impl RepoSnapshot {
    /// Build a snapshot directly from `(path, contents)` pairs.
    ///
    /// `contents` is `None` for files whose bytes are irrelevant to any check.
    /// Only paths that `is_readable_doc` accepts retain their text, mirroring
    /// what `scan` does, so in-memory tests cannot accidentally give a check
    /// access to bytes the real walker would never have read.
    pub fn from_entries<I, P, C>(root_name: impl Into<String>, entries: I) -> RepoSnapshot
    where
        I: IntoIterator<Item = (P, Option<C>)>,
        P: Into<String>,
        C: Into<String>,
    {
        let mut snap = RepoSnapshot {
            root_name: root_name.into(),
            ..RepoSnapshot::default()
        };
        for (path, contents) in entries {
            let path = normalize(&path.into());
            if let Some(text) = contents {
                if is_readable_doc(&path.to_ascii_lowercase()) {
                    snap.texts.insert(path.clone(), text.into());
                }
            }
            snap.paths.push(path);
        }
        snap.finish();
        snap
    }

    /// Walk `root`, honoring .gitignore/.ignore and skipping `.git`.
    ///
    /// Hidden files are included on purpose: `.github/`, `.well-known/` and
    /// `.env` are all load-bearing for this audit.
    pub fn scan(root: &Path, root_name: impl Into<String>) -> io::Result<RepoSnapshot> {
        let mut snap = RepoSnapshot {
            root_name: root_name.into(),
            ..RepoSnapshot::default()
        };

        let mut walker = WalkBuilder::new(root);
        walker
            // .github/, .well-known/ and .env are all load-bearing here.
            .hidden(false)
            // Honor the audited repository's own ignore files...
            .git_ignore(true)
            .ignore(true)
            // ...but nothing outside it. Parent-directory .gitignore files, the
            // user's global gitignore and .git/info/exclude are all state that
            // lives outside the repository being audited: honoring them would
            // make the same repository grade differently depending on where it
            // sits on disk and whose machine ran the audit.
            .parents(false)
            .git_global(false)
            .git_exclude(false)
            // Honor .gitignore even when the target is not inside a git repo.
            .require_git(false)
            .filter_entry(|e| e.file_name() != ".git");

        for entry in walker.build() {
            let Ok(dent) = entry else { continue };
            if !dent.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let Ok(rel) = dent.path().strip_prefix(root) else {
                continue;
            };
            let rel = normalize(&rel.to_string_lossy());
            if rel.is_empty() {
                continue;
            }

            if is_readable_doc(&rel.to_ascii_lowercase()) {
                let small = dent
                    .metadata()
                    .map(|m| m.len() <= MAX_READ_BYTES)
                    .unwrap_or(false);
                if small {
                    if let Ok(text) = std::fs::read_to_string(dent.path()) {
                        snap.texts.insert(rel.clone(), text);
                    }
                }
            }
            snap.paths.push(rel);
        }

        snap.finish();
        Ok(snap)
    }

    fn finish(&mut self) {
        self.paths.sort();
        self.paths.dedup();
        self.lower.clear();
        for (i, p) in self.paths.iter().enumerate() {
            // First writer wins so the lookup is stable when a case-insensitive
            // filesystem surfaces two spellings of the same path.
            self.lower.entry(p.to_ascii_lowercase()).or_insert(i);
        }
    }

    /// Directory name of the audited repository, used as the report title.
    pub fn root_name(&self) -> &str {
        &self.root_name
    }

    /// Every path in the snapshot, sorted.
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Number of files in the snapshot.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// True when the walk found no files at all.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Case-insensitive lookup; returns the path as it is actually spelled.
    pub fn find(&self, path: &str) -> Option<&str> {
        let key = normalize(path).to_ascii_lowercase();
        self.lower.get(&key).map(|i| self.paths[*i].as_str())
    }

    /// First existing path among `candidates`, in the order given.
    pub fn find_first(&self, candidates: &[&str]) -> Option<&str> {
        candidates.iter().find_map(|c| self.find(c))
    }

    /// Contents of `path`, if it was one of the files worth reading.
    pub fn text(&self, path: &str) -> Option<&str> {
        self.texts.get(path).map(String::as_str)
    }

    /// Paths whose lowercased form starts with `prefix` (a directory prefix
    /// ending in `/`), sorted.
    pub fn paths_under<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        let prefix = prefix.to_ascii_lowercase();
        self.paths
            .iter()
            .filter(move |p| p.to_ascii_lowercase().starts_with(&prefix))
            .map(String::as_str)
    }

    /// Every readable file whose text the snapshot retained, sorted by path.
    /// Used by the workflow checks.
    pub fn texts(&self) -> impl Iterator<Item = (&str, &str)> {
        self.texts.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// Normalize a path for the snapshot: forward slashes, no `./` prefix.
fn normalize(path: &str) -> String {
    let p = path.replace('\\', "/");
    p.strip_prefix("./")
        .unwrap_or(&p)
        .trim_matches('/')
        .to_string()
}

/// Whether a file's text is needed by any check.
///
/// This is the allowlist that makes the secret-hygiene check structurally safe:
/// `.env`, `*.pem`, key material and similar files are never matched here, so
/// their bytes are never loaded into the process, let alone into a finding.
pub fn is_readable_doc(lower_path: &str) -> bool {
    // GitHub workflow definitions.
    if lower_path.starts_with(".github/workflows/")
        && (lower_path.ends_with(".yml") || lower_path.ends_with(".yaml"))
    {
        return true;
    }

    let base = lower_path.rsplit('/').next().unwrap_or(lower_path);
    let dir = match lower_path.rfind('/') {
        Some(i) => &lower_path[..i],
        None => "",
    };

    // Community health files, at the root or in the locations GitHub also
    // honors (`.github/`, `docs/`).
    let community_dir = matches!(dir, "" | ".github" | "docs" | ".github/docs");
    if community_dir {
        let stem = base.split('.').next().unwrap_or(base);
        if matches!(
            stem,
            "readme"
                | "license"
                | "licence"
                | "copying"
                | "security"
                | "contributing"
                | "code_of_conduct"
        ) {
            return true;
        }
    }

    // requirements.txt is read to tell a pinned dependency list from a loose one.
    if base == "requirements.txt" {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive() {
        let snap = RepoSnapshot::from_entries("x", [("License.md", Some("MIT License"))]);
        assert_eq!(snap.find("LICENSE.md"), Some("License.md"));
        assert_eq!(snap.find("license.md"), Some("License.md"));
        assert_eq!(snap.find("nope"), None);
    }

    #[test]
    fn only_allowlisted_files_keep_their_text() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [
                ("README.md", Some("hello")),
                (".env", Some("API_KEY=do-not-leak")),
                ("id_rsa", Some("-----BEGIN OPENSSH PRIVATE KEY-----")),
            ],
        );
        assert_eq!(snap.text("README.md"), Some("hello"));
        assert_eq!(snap.text(".env"), None);
        assert_eq!(snap.text("id_rsa"), None);
        // The paths are still known, which is all the secret check needs.
        assert!(snap.find(".env").is_some());
    }

    #[test]
    fn readable_doc_allowlist() {
        assert!(is_readable_doc(".github/workflows/ci.yml"));
        assert!(is_readable_doc(".github/security.md"));
        assert!(is_readable_doc("security.md"));
        assert!(is_readable_doc("requirements.txt"));
        assert!(!is_readable_doc(".env"));
        assert!(!is_readable_doc("secrets/id_rsa"));
        assert!(!is_readable_doc("src/main.rs"));
        assert!(!is_readable_doc("vendor/security.md"));
    }

    #[test]
    fn paths_are_normalized_and_sorted() {
        let snap = RepoSnapshot::from_entries(
            "x",
            [
                ("./b.txt", None::<&str>),
                ("a\\c.txt", None),
                ("a.txt", None),
            ],
        );
        assert_eq!(snap.paths(), ["a.txt", "a/c.txt", "b.txt"]);
    }
}
