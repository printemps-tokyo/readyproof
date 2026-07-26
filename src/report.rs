//! Rendering: the human report and the JSON document.
//!
//! Both renderers are pure functions of a [`Report`], and both wrap at a fixed
//! width rather than the terminal width, so output is byte-for-byte
//! reproducible across machines and CI runs.

use crate::model::{Report, Severity, DISCLAIMER};

/// Fixed wrap width. Not terminal-derived, on purpose: identical input must
/// produce identical bytes.
const WRAP: usize = 92;

/// Column width the check id is padded to in the human report.
const ID_WIDTH: usize = 25;

/// Rendering options for the human report.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderOptions {
    /// Emit ANSI color codes.
    pub color: bool,
}

/// Render the full human-readable report, including the trailing disclaimer.
pub fn render_text(report: &Report, opts: RenderOptions) -> String {
    let mut out = String::new();
    let c = |code: &str, s: &str| -> String {
        if opts.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };

    out.push_str(&format!("readyproof: {}\n", report.root_name));
    out.push_str(&summary_line(report, opts));
    out.push_str("\n\n");

    for cat in &report.categories {
        let score = match cat.score {
            Some(s) => format!(" (score {s})"),
            None => String::new(),
        };
        out.push_str(&format!("{}{}\n", c("1", cat.category.title()), score));

        for f in report
            .findings
            .iter()
            .filter(|f| f.category == cat.category)
        {
            let label = c(severity_color(f.severity), f.severity.label());
            out.push_str(&format!(
                "  [{}] {:<width$} {}\n",
                label,
                f.id,
                f.title,
                width = ID_WIDTH
            ));
            for e in &f.evidence {
                out.push_str(&format!("         - {e}\n"));
            }
            // PASS lines stay terse; anything actionable carries its rationale.
            if f.severity != Severity::Pass {
                push_field(&mut out, "why", f.why);
                if f.severity != Severity::Info {
                    push_field(&mut out, "source", f.source);
                    push_field(&mut out, "fix", f.fix);
                }
            }
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "{} check(s) run, {} skipped.\n",
        report.findings.len(),
        report.skipped
    ));
    for line in wrap(DISCLAIMER, WRAP) {
        out.push_str(&c("2", &line));
        out.push('\n');
    }
    out
}

/// The one-line summary used as the `--quiet` output and as the report header.
pub fn summary_line(report: &Report, opts: RenderOptions) -> String {
    let c = |code: &str, s: &str| -> String {
        if opts.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let score = match report.score {
        Some(s) => format!("score {s}/100"),
        None => "score n/a".to_string(),
    };
    format!(
        "grade {}  {}  |  pass {}  warn {}  fail {}  info {}",
        c(grade_color(report.grade()), report.grade()),
        score,
        report.counts.pass,
        report.counts.warn,
        report.counts.fail,
        report.counts.info,
    )
}

fn push_field(out: &mut String, name: &str, text: &str) {
    let indent = "         ";
    let head = format!("{indent}{name:<7}");
    let body_indent = format!("{indent}{}", " ".repeat(7));
    for (i, line) in wrap(text, WRAP.saturating_sub(head.len()))
        .into_iter()
        .enumerate()
    {
        if i == 0 {
            out.push_str(&head);
        } else {
            out.push_str(&body_indent);
        }
        out.push_str(&line);
        out.push('\n');
    }
}

fn severity_color(s: Severity) -> &'static str {
    match s {
        Severity::Pass => "32",
        Severity::Info => "36",
        Severity::Warn => "33",
        Severity::Fail => "31",
    }
}

fn grade_color(grade: &str) -> &'static str {
    match grade {
        "A" | "B" => "32",
        "C" => "33",
        "n/a" => "36",
        _ => "31",
    }
}

/// Greedy word wrap. Words longer than `width` are emitted on their own line
/// rather than being split, which keeps URLs intact and clickable.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Render the machine-readable report.
///
/// JSON is hand-rolled rather than pulled in via serde: the document has a
/// fixed shape with no user-controlled keys, and skipping serde keeps the
/// dependency tree to three direct crates.
pub fn render_json(report: &Report) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("{\n");
    out.push_str("  \"tool\": \"readyproof\",\n");
    out.push_str(&format!(
        "  \"version\": \"{}\",\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str(&format!(
        "  \"repository\": {},\n",
        quote(&report.root_name)
    ));
    out.push_str(&format!("  \"grade\": {},\n", quote(report.grade())));
    out.push_str(&format!("  \"score\": {},\n", num(report.score)));
    out.push_str(&format!(
        "  \"counts\": {{\"pass\": {}, \"warn\": {}, \"fail\": {}, \"info\": {}}},\n",
        report.counts.pass, report.counts.warn, report.counts.fail, report.counts.info
    ));
    out.push_str(&format!("  \"skipped\": {},\n", report.skipped));

    out.push_str("  \"categories\": [\n");
    for (i, cat) in report.categories.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"id\": {}, \"title\": {}, \"score\": {}, \
\"counts\": {{\"pass\": {}, \"warn\": {}, \"fail\": {}, \"info\": {}}}}}",
            quote(cat.category.as_str()),
            quote(cat.category.title()),
            num(cat.score),
            cat.counts.pass,
            cat.counts.warn,
            cat.counts.fail,
            cat.counts.info
        ));
        out.push_str(if i + 1 == report.categories.len() {
            "\n"
        } else {
            ",\n"
        });
    }
    out.push_str("  ],\n");

    out.push_str("  \"findings\": [\n");
    for (i, f) in report.findings.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"id\": {},\n", quote(f.id)));
        out.push_str(&format!(
            "      \"category\": {},\n",
            quote(f.category.as_str())
        ));
        out.push_str(&format!(
            "      \"severity\": {},\n",
            quote(f.severity.as_str())
        ));
        out.push_str(&format!("      \"title\": {},\n", quote(&f.title)));
        let evidence: Vec<String> = f.evidence.iter().map(|e| quote(e)).collect();
        out.push_str(&format!("      \"evidence\": [{}],\n", evidence.join(", ")));
        out.push_str(&format!("      \"why\": {},\n", quote(f.why)));
        out.push_str(&format!("      \"source\": {},\n", quote(f.source)));
        out.push_str(&format!("      \"fix\": {}\n", quote(f.fix)));
        out.push_str("    }");
        out.push_str(if i + 1 == report.findings.len() {
            "\n"
        } else {
            ",\n"
        });
    }
    out.push_str("  ],\n");

    out.push_str(&format!("  \"disclaimer\": {}\n", quote(DISCLAIMER)));
    out.push_str("}\n");
    out
}

fn num(v: Option<u32>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

/// Quote and escape a string as a JSON scalar.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{audit, Options};
    use crate::snapshot::RepoSnapshot;

    fn sample() -> Report {
        let snap = RepoSnapshot::from_entries(
            "sample",
            [
                ("README.md", Some("hello")),
                (".env", Some("SECRET=leak-me")),
            ],
        );
        audit(&snap, &Options::default())
    }

    #[test]
    fn text_report_is_deterministic_and_carries_the_disclaimer() {
        let r = sample();
        let a = render_text(&r, RenderOptions { color: false });
        let b = render_text(&r, RenderOptions { color: false });
        assert_eq!(a, b);
        assert!(a.contains("not legal advice"));
        assert!(a.contains("open source stewards have a lighter regime"));
        assert!(!a.contains("leak-me"));
    }

    #[test]
    fn no_color_output_has_no_escape_codes() {
        let r = sample();
        let plain = render_text(&r, RenderOptions { color: false });
        assert!(!plain.contains('\x1b'));
        let colored = render_text(&r, RenderOptions { color: true });
        assert!(colored.contains('\x1b'));
    }

    #[test]
    fn json_is_stable_and_escaped() {
        let r = sample();
        let a = render_json(&r);
        assert_eq!(a, render_json(&r));
        assert!(a.starts_with("{\n  \"tool\": \"readyproof\","));
        assert!(a.contains("\"disclaimer\":"));
        assert!(!a.contains("leak-me"));
        // Every quoted string is balanced: an odd count would mean a bad escape.
        assert_eq!(a.matches('"').count() % 2, 0);
    }

    #[test]
    fn quote_escapes_control_characters() {
        assert_eq!(quote("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(quote("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn wrap_keeps_long_urls_intact() {
        let long = "https://example.com/".to_string() + &"a".repeat(200);
        let lines = wrap(&format!("see {long} now"), 40);
        assert!(lines.iter().any(|l| l == &long));
    }
}
