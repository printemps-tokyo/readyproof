//! Command-line entry point for readyproof.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;

use readyproof::checks::{check_ids, Options};
use readyproof::model::Category;
use readyproof::report::{render_json, render_text, summary_line, RenderOptions};
use readyproof::snapshot::RepoSnapshot;
use readyproof::DISCLAIMER;

const AFTER_HELP: &str = "\
CATEGORIES:
  documentation, supply-chain, ci, disclosure

EXIT CODES:
  0  no FAIL findings (and, with --strict, no WARN findings)
  1  at least one FAIL finding (with --strict, also any WARN)
  2  usage or I/O error

readyproof is a preparation aid, not legal advice and not a certification. It
grades the readiness of practices downstream consumers ask about. CRA
obligations fall on manufacturers placing products on the EU market; open
source stewards have a lighter regime.";

/// Audit a git repository for open-source security and compliance readiness.
#[derive(Parser, Debug)]
#[command(
    name = "readyproof",
    version,
    about,
    long_about = None,
    after_help = AFTER_HELP
)]
struct Cli {
    /// Repository directory to audit.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Emit the machine-readable JSON report instead of the human report.
    #[arg(long)]
    json: bool,

    /// Also exit non-zero when any check warns.
    #[arg(long)]
    strict: bool,

    /// Run only checks in this category (repeatable).
    #[arg(long, value_name = "CATEGORY", value_parser = parse_category)]
    only: Vec<Category>,

    /// Skip a check by id (repeatable).
    #[arg(long, value_name = "CHECK_ID")]
    skip: Vec<String>,

    /// Print how each check corresponds to OpenSSF Scorecard and SLSA, and
    /// exit (with --json, as JSON).
    #[arg(long, conflicts_with_all = ["fix", "strict", "quiet"])]
    map: bool,

    /// Create starter files for what is missing (SECURITY.md, CONTRIBUTING.md,
    /// CODE_OF_CONDUCT.md, .github/dependabot.yml), then audit the result.
    /// Never overwrites a file and never writes a LICENSE.
    #[arg(long)]
    fix: bool,

    /// With --fix, print what would be created and create nothing.
    #[arg(long, requires = "fix")]
    dry_run: bool,

    /// Never emit ANSI color codes.
    #[arg(long)]
    no_color: bool,

    /// Print only the one-line summary.
    #[arg(short, long)]
    quiet: bool,
}

fn parse_category(s: &str) -> Result<Category, String> {
    Category::parse(s).ok_or_else(|| {
        let names: Vec<&str> = Category::ALL.iter().map(|c| c.as_str()).collect();
        format!(
            "unknown category '{s}' (expected one of: {})",
            names.join(", ")
        )
    })
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("readyproof: {err:#}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    if cli.map {
        let doc = if cli.json {
            readyproof::report::render_map_json()
        } else {
            readyproof::report::render_map_text()
        };
        std::io::stdout().write_all(doc.as_bytes())?;
        return Ok(0);
    }

    for id in &cli.skip {
        if !check_ids().contains(&id.as_str()) {
            anyhow::bail!(
                "unknown check id '{id}'\nknown ids: {}",
                check_ids().join(", ")
            );
        }
    }

    if !cli.path.is_dir() {
        anyhow::bail!("not a directory: {}", cli.path.display());
    }
    let root_name = cli
        .path
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| cli.path.display().to_string());

    let mut snapshot = RepoSnapshot::scan(&cli.path, root_name.clone())
        .with_context(|| format!("failed to walk {}", cli.path.display()))?;

    if cli.fix {
        let plan = readyproof::fix::plan(&snapshot);
        let created = apply_fix(&cli.path, &plan, cli.dry_run)?;
        if created {
            snapshot = RepoSnapshot::scan(&cli.path, root_name)
                .with_context(|| format!("failed to walk {}", cli.path.display()))?;
        }
    }

    let report = readyproof::audit(
        &snapshot,
        &Options {
            only: cli.only,
            skip: cli.skip,
        },
    );

    // Color is opt-out via the flag, the NO_COLOR convention, or a non-tty
    // stdout; JSON is never colored.
    let color = !cli.no_color
        && !cli.json
        && std::env::var_os("NO_COLOR").is_none()
        && std::io::stdout().is_terminal();
    let opts = RenderOptions { color };

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if cli.json {
        out.write_all(render_json(&report).as_bytes())?;
    } else if cli.quiet {
        // stdout stays a single pipeable line; the framing goes to stderr so it
        // is still shown without polluting the summary.
        writeln!(
            out,
            "readyproof: {}  {}",
            report.root_name,
            summary_line(&report, opts)
        )?;
        eprintln!("{DISCLAIMER}");
    } else {
        out.write_all(render_text(&report, opts).as_bytes())?;
    }
    out.flush()?;

    Ok(report.exit_code(cli.strict))
}

/// Create the planned files (or describe them, with `dry_run`). The log goes to
/// stderr so stdout stays the report. Returns whether anything was written.
fn apply_fix(root: &Path, plan: &readyproof::fix::FixPlan, dry_run: bool) -> Result<bool> {
    let mut wrote = false;
    for file in &plan.create {
        let path = root.join(file.path);
        if dry_run {
            eprintln!(
                "readyproof: --fix: would create {}  (for {})",
                file.path, file.check
            );
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        // create_new: a file that appeared since the scan is left alone.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(file.contents.as_bytes())
                    .with_context(|| format!("cannot write {}", path.display()))?;
                wrote = true;
                eprintln!(
                    "readyproof: --fix: created {}  (for {})",
                    file.path, file.check
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                eprintln!(
                    "readyproof: --fix: skipped {}: it already exists",
                    file.path
                );
            }
            Err(e) => {
                return Err(e).with_context(|| format!("cannot create {}", path.display()));
            }
        }
    }
    for skip in &plan.skipped {
        eprintln!(
            "readyproof: --fix: left {} to you: {}",
            skip.check, skip.reason
        );
    }
    if plan.create.is_empty() && plan.skipped.is_empty() {
        eprintln!("readyproof: --fix: nothing to create");
    } else if !dry_run && wrote {
        eprintln!(
            "readyproof: --fix: the new files hold <!-- readyproof: ... --> placeholders; \
             fill them in, then delete the comments"
        );
    }
    Ok(wrote)
}
