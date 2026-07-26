//! Command-line entry point for readyproof.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

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

    let snapshot = RepoSnapshot::scan(&cli.path, root_name)
        .with_context(|| format!("failed to walk {}", cli.path.display()))?;

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
