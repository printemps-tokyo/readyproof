# readyproof

Audit a local git repository for open-source security and compliance
readiness, offline, in milliseconds.

readyproof walks a repository (respecting `.gitignore`), looks at the files and
CI workflows that are actually there, and reports on the practices downstream
consumers keep asking maintainers about: is there a way to report a
vulnerability, is the license identifiable, is there a lockfile, does CI run the
tests, are third-party actions pinned, are release artifacts verifiable, and is
anything credential-shaped committed.

Every check names the source that motivates it, the evidence it found, and a
concrete fix.

```
$ readyproof
readyproof: readyproof
grade A  score 98/100  |  pass 15  warn 1  fail 0  info 3
```

## This is a preparation aid, not legal advice

Read this part before you read the score.

- readyproof is not legal advice and not a certification. It is a
  checklist runner.
- It never claims a repository is "CRA compliant", and neither should you.
  There is no such thing as a repository being CRA compliant.
- Under the EU Cyber Resilience Act, the obligations fall on manufacturers
  placing products with digital elements on the EU market. Upstream open
  source maintainers are not that party. The Act also defines a lighter regime
  for open source software stewards — entities that support the development
  of FOSS intended for commercial activities — and OpenSSF's own guidance is
  explicit that responsibility "remains exclusively with manufacturers placing
  products on the market". See
  [OpenSSF's CRA materials](https://openssf.org/category/policy/cra/).
- Publishing information about your practices is voluntary and, per that same
  guidance, "does not create legal obligations, warranties, or liability".
  readyproof grades the *readiness* of practices. It does not grade you, and it
  does not create a duty you did not already have.

What readyproof is actually useful for: answering the security questionnaire a
downstream integrator sends you, without spending an afternoon on it.

## Install

From source (requires a stable Rust toolchain):

```bash
git clone https://github.com/printemps-tokyo/readyproof
cd readyproof
cargo build --release
./target/release/readyproof --help
```

Prebuilt binaries for Linux and macOS are attached to each tagged release,
alongside a `.sha256` checksum file. Verify before use:

```bash
shasum -a 256 -c readyproof-aarch64-apple-darwin.tar.gz.sha256
```

## Quickstart

```bash
readyproof                      # audit the current directory
readyproof ../some-repo         # audit another checkout
readyproof --json               # machine-readable report
readyproof --strict             # exit non-zero on warnings too
readyproof --only disclosure    # just the vulnerability-disclosure checks
readyproof --skip ci-action-pinning
readyproof --quiet              # one summary line on stdout
readyproof --map                # how each check lines up with Scorecard and SLSA
readyproof --fix --dry-run      # which starter files --fix would create
readyproof --fix                # create them, then audit the result
```

Nothing touches the network, at any point. Files are read only from the
directory you point at, and written only by `--fix`.

### Flags

| Flag | Meaning |
| --- | --- |
| `PATH` | Repository directory to audit (default `.`) |
| `--json` | Emit the JSON report instead of the human report |
| `--strict` | Also exit non-zero when any check warns |
| `--only <CATEGORY>` | Run only one category; repeatable. `documentation`, `supply-chain`, `ci`, `disclosure` |
| `--skip <CHECK_ID>` | Suppress a check by id; repeatable |
| `--no-color` | Never emit ANSI color (also honors `NO_COLOR` and a non-tty stdout) |
| `-q`, `--quiet` | Print only the one-line summary to stdout |
| `--map` | Print the OpenSSF Scorecard / SLSA correspondence table and exit (`--json` for JSON) |
| `--fix` | Create starter files for what is missing, then audit the result |
| `--dry-run` | With `--fix`: list what would be created and create nothing |
| `-h`, `--help` / `-V`, `--version` | Usage / version |

## Check catalog

Nineteen checks in four categories. Each emits exactly one finding, so
`--skip <id>` always has an unambiguous target.

Severity meanings: FAIL = a practice downstream consumers routinely ask for
is absent. WARN = worth fixing, but reasonable projects disagree or the
practice is commonly skipped. INFO = context only, never scored, never
affects the exit code. PASS = the practice is in place.

### Documentation

| Check id | Outcome | What it looks at | Source |
| --- | --- | --- | --- |
| `doc-readme` | PASS / FAIL | A README at the root, in `docs/`, or in `.github/` | OpenSSF Best Practices passing: [`documentation_basics`, `description_good`](https://www.bestpractices.dev/en/criteria/0) |
| `doc-support-policy` | INFO | Whether the README or SECURITY.md states supported versions, a support period, or an EOL policy | Downstream integrator question; [OpenSSF CRA guidance](https://openssf.org/category/policy/cra/) on voluntarily publishing support practices |
| `doc-contributing` | PASS / WARN | A CONTRIBUTING file; falls back to noting a README section | OpenSSF Best Practices passing: [`contribution`, `contribution_requirements`](https://www.bestpractices.dev/en/criteria/0) |
| `doc-code-of-conduct` | PASS / WARN | A CODE_OF_CONDUCT file | OpenSSF Best Practices [silver: `code_of_conduct`](https://www.bestpractices.dev/en/criteria/1) — silver, hence WARN not FAIL |
| `license-present` | PASS / FAIL | LICENSE / LICENCE / COPYING, or a `LICENSE/` directory | OpenSSF Best Practices passing: [`license_location`](https://www.bestpractices.dev/en/criteria/0); [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-LE-03.01 |
| `license-identified` | PASS / WARN / INFO | Guesses the SPDX id from the license text; conservative, an unknown text is reported as unknown rather than guessed | OpenSSF Best Practices passing: [`floss_license`](https://www.bestpractices.dev/en/criteria/0); [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-LE-02.01 |

### Supply chain

| Check id | Outcome | What it looks at | Source |
| --- | --- | --- | --- |
| `supply-manifest` | PASS / WARN | Dependency manifests anywhere in the tree: `Cargo.toml`, `package.json`, `go.mod`, `pyproject.toml`, `requirements.txt`, `Gemfile`, `composer.json`, `pom.xml`, Gradle, `pubspec.yaml`, `mix.exs`, `Package.swift`, `Podfile`, `*.csproj` | [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-QA-02.01 |
| `supply-lockfile` | PASS / WARN / INFO | A lockfile committed beside each manifest. Ecosystems with no standard lockfile (Maven) are not counted against. A `requirements.txt` counts as its own lock when fully `==`-pinned or hash-pinned | [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-QA-02.01; reproducibility themes in [OpenSSF Best Practices](https://www.bestpractices.dev/en/criteria/0) |
| `supply-sbom-basis` | INFO | Lists the manifest/lock pairs an SBOM generator would read | [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-QA-02.02; [OpenSSF CRA / SBOM materials](https://openssf.org/category/policy/cra/) |
| `supply-updates` | PASS / WARN | Dependabot or Renovate config, a vulnerability scanner step in CI, or a documented update process | [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-DO-06.01 and OSPS-VM-05.03 |
| `supply-secrets` | PASS / WARN / FAIL | Committed files whose *names* match secret-bearing patterns: `.env` and variants, `id_rsa`/`id_ed25519`, `*.p12`/`*.pfx`/`*.jks`/`*.ppk`/`*.p8`, service-account and `client_secret` JSON, `.netrc`, `.pgpass`, `.htpasswd`. `*.pem`/`*.key`/`*.keystore` are reported at lower confidence (WARN) because they legitimately hold public certificates | Downstream security-review question; [OpenSSF Baseline](https://baseline.openssf.org/) credential-management controls |

### CI

| Check id | Outcome | What it looks at | Source |
| --- | --- | --- | --- |
| `ci-present` | PASS / WARN | `.github/workflows/*.yml`, or a config for another CI system (GitLab, CircleCI, Jenkins, ...) | OpenSSF Best Practices passing: [`test_continuous_integration`](https://www.bestpractices.dev/en/criteria/0) (SUGGESTED, hence WARN) |
| `ci-tests` | PASS / WARN / INFO | Whether any workflow runs a recognized test command | OpenSSF Best Practices passing: [`test`, `test_invocation`](https://www.bestpractices.dev/en/criteria/0) |
| `ci-action-pinning` | PASS / WARN / INFO | Every `uses:` reference; a full 40-character commit SHA passes, a tag or branch warns | [GitHub Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions); [OpenSSF Baseline](https://baseline.openssf.org/) build/release controls |
| `ci-release-integrity` | PASS / WARN / INFO | Whether a release workflow publishes checksums (`SHA256SUMS`, `shasum -a 256`), signatures (cosign, gpg, minisign) or attestations | [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-BR-06.01; [OpenSSF CRA guidance](https://openssf.org/category/policy/cra/) on release integrity |

### Disclosure

| Check id | Outcome | What it looks at | Source |
| --- | --- | --- | --- |
| `disclosure-policy` | PASS / FAIL | SECURITY.md at the root, in `.github/`, or in `docs/` | OpenSSF Best Practices passing: [`vulnerability_report_process`](https://www.bestpractices.dev/en/criteria/0); [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-VM-01.01 |
| `disclosure-contact` | PASS / WARN / FAIL | Whether the policy names an email address or a private reporting channel (GitHub private vulnerability reporting, HackerOne, Bugcrowd, huntr). A placeholder address such as `security@example.com` warns rather than passes | OpenSSF Best Practices passing: [`vulnerability_report_private`](https://www.bestpractices.dev/en/criteria/0); [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-VM-02.01, OSPS-VM-03.01 |
| `disclosure-response-time` | PASS / WARN | Whether the policy states an initial-response expectation | OpenSSF Best Practices passing: [`vulnerability_report_response`](https://www.bestpractices.dev/en/criteria/0) (14 days); [OpenSSF Baseline](https://baseline.openssf.org/) OSPS-VM-01.01 |
| `disclosure-security-txt` | INFO | Whether a `security.txt` exists | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) |

### On action pinning, honestly

`ci-action-pinning` is a WARN and will stay a WARN.

Pinning `uses:` to a tag means the upstream action owner can move that tag and
change what runs inside your workflow, with whatever token the job holds.
Pinning to a full commit SHA removes that. That is a real hardening step.

It is also true that tag pinning is extremely common, including in every
repository this organization publishes and in this one. Major-version tags from
well-known publishers are a defensible risk position, and SHA pins go stale
unless something (Dependabot for the `github-actions` ecosystem) keeps moving
them. A tool that failed your build over this would be wrong more often than it
was right. So readyproof tells you, explains the tradeoff, and lets you decide.

readyproof warns about its own workflows for exactly this reason. That is not an
oversight.

## Example report

```
readyproof: repotome
grade A  score 93/100  |  pass 13  warn 3  fail 0  info 3

Documentation (score 100)
  [PASS] doc-code-of-conduct       Code of conduct present
         - CODE_OF_CONDUCT.md
  [PASS] doc-contributing          CONTRIBUTING present
         - CONTRIBUTING.md
  [PASS] doc-readme                README present
         - README.md
  [INFO] doc-support-policy        No supported-versions or support-policy statement found
         why    "Which versions do you still patch, and for how long?" is one of the first
                questions a downstream manufacturer asks, because their own support period
                depends on the answer. This is informational only: no OpenSSF passing
                criterion requires it, and upstream maintainers owe nobody a support
                commitment.
  [PASS] license-identified        License text matches MIT
         - LICENSE (MIT)
  [PASS] license-present           License file present
         - LICENSE

...

CI (score 75)
  [WARN] ci-action-pinning         7 action reference(s) pinned to a mutable tag or branch
         - .github/workflows/ci.yml:22: actions/checkout@v4
         - .github/workflows/ci.yml:23: dtolnay/rust-toolchain@stable
         - .github/workflows/ci.yml:26: Swatinem/rust-cache@v2
         - .github/workflows/release.yml:29: actions/checkout@v4
         ...
         why    A tag or branch reference resolves at run time, so whoever controls the
                upstream action can change what executes inside your workflow, with whatever
                token that job holds. Pinning to a full commit SHA removes that. ...
         source OpenSSF supply-chain hardening guidance and OpenSSF Baseline build-release
                controls; GitHub's own security hardening guide for Actions
         fix    Replace `uses: owner/action@v4` with `uses: owner/action@<40-char-sha> #
                v4`, and enable Dependabot for the github-actions ecosystem so the pins keep
                moving.

Disclosure (score 100)
  [PASS] disclosure-contact        Reporting channel documented
         - SECURITY.md: mentions "security/advisories"
         - SECURITY.md: info@printemps.tokyo
  [PASS] disclosure-policy         Security policy present
         - SECURITY.md
  [PASS] disclosure-response-time  Response-time expectation stated
         - SECURITY.md: We aim to send an initial response within 72 hours.
  [INFO] disclosure-security-txt   No security.txt found (optional; mainly for projects with a website)

19 check(s) run, 0 skipped.
readyproof grades practice readiness only. It is not legal advice, not a certification, and
not a CRA conformity assessment: CRA obligations fall on manufacturers placing products on
the EU market, and open source stewards have a lighter regime.
```

PASS lines stay terse. Anything actionable carries its rationale, source and fix
inline, so there is no separate `--explain` mode to remember.

## Scoring

Each non-INFO check contributes to a weighted score. PASS earns full credit,
WARN earns half, FAIL earns none. The four checks that map onto the strongest
downstream questions — `disclosure-policy`, `disclosure-contact`,
`license-present`, `supply-secrets` — count double. INFO findings are excluded
entirely.

| Grade | Score |
| --- | --- |
| A | 90-100 |
| B | 75-89 |
| C | 60-74 |
| D | 40-59 |
| F | below 40 |

The score is a prioritization aid. It is not a rating, a badge, or a claim
about anyone's legal position.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No FAIL findings. With `--strict`, also no WARN findings |
| 1 | At least one FAIL finding. With `--strict`, also any WARN finding |
| 2 | Usage error (unknown check id or category, path is not a directory) or I/O error |

INFO findings never affect the exit code. Suppressing a check with `--skip`
removes it from the exit-code calculation too, which is the intended way to
adopt `--strict` in CI while you work through a backlog.

## JSON output

`--json` writes a single object to stdout. The shape is stable; new keys may be
added, existing keys will not change meaning.

```json
{
  "tool": "readyproof",
  "version": "0.1.0",
  "repository": "readyproof",
  "grade": "A",
  "score": 98,
  "counts": { "pass": 15, "warn": 1, "fail": 0, "info": 3 },
  "skipped": 0,
  "categories": [
    {
      "id": "documentation",
      "title": "Documentation",
      "score": 100,
      "counts": { "pass": 5, "warn": 0, "fail": 0, "info": 1 }
    }
  ],
  "findings": [
    {
      "id": "disclosure-policy",
      "category": "disclosure",
      "severity": "pass",
      "title": "Security policy present",
      "evidence": ["SECURITY.md"],
      "why": "Publishing how to report a vulnerability is ...",
      "source": "OpenSSF Best Practices, passing level: vulnerability_report_process; ...",
      "fix": "Add SECURITY.md at the repository root ..."
    }
  ],
  "disclaimer": "readyproof grades practice readiness only. It is not legal advice, ..."
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `tool` | string | Always `"readyproof"` |
| `version` | string | The readyproof version that produced the report |
| `repository` | string | Directory name of the audited repository |
| `grade` | string | `A`-`F`, or `n/a` when nothing scoreable ran |
| `score` | integer or null | 0-100; null when nothing scoreable ran |
| `counts` | object | `pass`, `warn`, `fail`, `info` totals |
| `skipped` | integer | Checks suppressed by `--skip` / `--only` |
| `categories[]` | array | One entry per non-empty category, in report order |
| `categories[].score` | integer or null | Per-category rollup |
| `findings[]` | array | Sorted by category order, then check id |
| `findings[].severity` | string | `pass`, `warn`, `fail`, `info` |
| `findings[].evidence` | array of strings | Repository-relative paths, or `path:line` for workflow findings |
| `disclaimer` | string | The framing above; always present |

Output is byte-for-byte reproducible: findings sort by category order then check
id, evidence is sorted by the check that produced it, and text wraps at a fixed
width rather than the terminal width.

## Secret hygiene: what this does and does not do

`supply-secrets` is a filename-based smoke test. readyproof never opens the
files it flags: the snapshot only retains the text of documentation and workflow
files, so the bytes of a `.env` or a private key are never loaded into the
process, let alone into a report. What you get is a path and a category, which
is enough to act on and impossible to leak through.

It will not find an API key pasted into a source file, a config, or a log. For
content-level scanning use the companion tool
[`redact`](https://github.com/printemps-tokyo/redact), which is built for
exactly that.

Two more honest limits:

- readyproof reads the working tree, not git history. A credential that was
  committed and later deleted is still in your history and still burned;
  readyproof will not see it.
- readyproof respects `.gitignore`. A file that is both ignored and tracked
  (possible, if it was added before the ignore rule) will not be reported.

## Scorecard and SLSA

`readyproof --map` prints, for every readyproof check, the
[OpenSSF Scorecard](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
checks it corresponds to and how closely (`same`: the same thing in the same
place; `partial`: the same practice observed differently or only in part),
the SLSA level its evidence bears on, and a one-line note on the difference.
It then lists the Scorecard checks readyproof does not cover and why.

| readyproof | Scorecard | SLSA |
| --- | --- | --- |
| `license-present` / `license-identified` | License (same / partial) | |
| `supply-lockfile` | Pinned-Dependencies (partial: Scorecard looks at Dockerfiles, scripts and workflows, not lockfiles) | |
| `supply-sbom-basis` | SBOM (partial) | |
| `supply-updates` | Dependency-Update-Tool (same; readyproof also accepts a CI scan or a documented process) | |
| `ci-tests` | CI-Tests (partial: Scorecard reads CI results through the API) | |
| `ci-action-pinning` | Pinned-Dependencies (same, for GitHub Actions) | |
| `ci-release-integrity` | Signed-Releases (partial: Scorecard reads release assets) | Build L1-L2 |
| `disclosure-policy` | Security-Policy (same) | |
| `disclosure-contact` / `disclosure-response-time` | Security-Policy (partial: its linking and timeline points) | |

Not covered: Binary-Artifacts, Dangerous-Workflow and Token-Permissions
(readable offline, not checked yet), Fuzzing, Packaging, and the checks that
need the hosting platform's API, history or an online database
(Branch-Protection, CII-Best-Practices, Code-Review, Contributors, Maintained,
SAST, Vulnerabilities, Webhooks).

The SLSA column uses the v1.1 Build track: L1 "provenance showing how the
package was built", L2 "signed provenance, generated by a hosted build
platform". readyproof sees a provenance step in the release workflow
(`actions/attest-build-provenance`, `slsa-github-generator`), not the
attestation itself, so it is evidence toward those levels, not a claim to them.
A passing readyproof check is likewise not a Scorecard score. Sources:
Scorecard `docs/checks.md` at commit `4ddc782` and slsa.dev/spec/v1.1/levels,
both read 2026-11-12.

## Starter files with `--fix`

`--fix` creates, at the repository root, whichever of these is missing:

| File | For | What it leaves to you |
| --- | --- | --- |
| `SECURITY.md` | `disclosure-policy` | a reporting address (`security@example.com` until you change it, which `disclosure-contact` keeps flagging), a response time, and supported versions |
| `CONTRIBUTING.md` | `doc-contributing` | the build and test commands |
| `CODE_OF_CONDUCT.md` | `doc-code-of-conduct` | adopts the Contributor Covenant 2.1 by link; who receives reports |
| `.github/dependabot.yml` | `supply-updates` | one weekly entry per ecosystem found at the root (`cargo`, `npm`, `gomod`, `pip`, `bundler`, `composer`, `docker`) plus `github-actions` when there are workflows |

The places that would be a promise are `<!-- readyproof: ... -->` comments, not
made-up answers. `--fix` never overwrites a file (it creates each one only if it
still does not exist) and never writes a LICENSE: which license to use is your
decision. The log goes to stderr; stdout is the audit of the result.

## What readyproof does not check

Deliberately out of scope, because file-and-CI evidence cannot answer them
honestly: whether your tests are any good, whether your maintainers have 2FA
enabled, whether your dependencies currently have known vulnerabilities
(that needs a network and a vulnerability database), whether your release
artifacts actually match your source, and anything about your legal position.

## Design

- `src/snapshot.rs` — the only code that touches the filesystem. Walks with
  [`ignore`](https://crates.io/crates/ignore) and builds a read-once view.
- `src/checks/` — pure functions from a snapshot to findings. One check, one
  finding, always.
- `src/model.rs` — severities, categories, scoring rollup.
- `src/report.rs` — text and JSON rendering, both pure.
- `src/main.rs` — argument parsing and printing, nothing else.

Three direct dependencies, each load-bearing: `anyhow` for error context in the
binary, `clap` for argument parsing, `ignore` for the gitignore-aware walk. JSON
is hand-rolled rather than pulled in via `serde`, because the document has a
fixed shape with no user-controlled keys and 40 lines of local code is cheaper
than a derive-macro dependency tree. A tool that lectures people about their
supply chain should keep its own short.

## Sources

The check catalog is anchored on:

- [OpenSSF Best Practices, passing-level criteria](https://www.bestpractices.dev/en/criteria/0)
- [OpenSSF Best Practices, silver-level criteria](https://www.bestpractices.dev/en/criteria/1)
- [OpenSSF Baseline (OSPS)](https://baseline.openssf.org/)
- [OpenSSF Cyber Resilience Act materials](https://openssf.org/category/policy/cra/)
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [RFC 9116, security.txt](https://www.rfc-editor.org/rfc/rfc9116)
- [OpenSSF Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md) and [SLSA v1.1 levels](https://slsa.dev/spec/v1.1/levels), for `--map`
- [Dependabot options reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference), for the ecosystem names `--fix` writes

Where a source treats something as suggested, optional, or above the passing
level, readyproof grades it as WARN or INFO rather than FAIL. Where no source
supports a check, the check does not exist.

## License

MIT. See [LICENSE](LICENSE).
