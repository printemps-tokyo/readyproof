# Contributing

Thanks for your interest in contributing to readyproof.

## Development

1. Fork / clone the repository
2. Install a stable Rust toolchain (https://rustup.rs)
3. Create a branch: `git switch -c feat/your-change`
4. Make your change and verify locally:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all
   ```
5. Commit and open a pull request

## Adding or changing a check

Every check must be anchored on a citable source: an OpenSSF Best Practices
criterion, an OpenSSF Baseline control, an RFC, or a concrete question that
downstream consumers actually ask. Pull requests that add a check should:

- put the source URL in the check's `source` field, not just in the PR
  description
- say honestly when a practice is contested or commonly skipped, and grade it
  WARN rather than FAIL in that case
- never claim regulatory compliance, and never read the contents of files the
  secret-hygiene check can match
- add tests covering the pass, warn/fail, and not-applicable outcomes

## Dependencies

readyproof depends on `anyhow`, `clap` and `ignore`, and that is meant to stay
short. A pull request adding a dependency needs to explain why the alternative
of a few dozen lines of local code is worse. Dependency updates are handled by
Dependabot (see `.github/dependabot.yml`).

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are preferred
(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).

## Pull requests

- Keep one PR focused on a single purpose
- CI (fmt / clippy / test / build) must be green
- Update the README and tests when behavior changes

## Bug reports and requests

Please open an [issue](../../issues) using the templates.
