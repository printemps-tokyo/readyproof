//! readyproof — audit a local git repository for open-source security and
//! compliance readiness.
//!
//! # Framing
//!
//! readyproof is a preparation aid. It is not legal advice, not a
//! certification, and not a conformity assessment under the EU Cyber
//! Resilience Act. Under the CRA, obligations fall on manufacturers placing
//! products on the EU market; "open source software stewards" are subject to a
//! lighter regime, and individual upstream maintainers releasing code without
//! monetization are not the regulated party. See OpenSSF's CRA materials:
//! <https://openssf.org/category/policy/cra/>.
//!
//! What the tool actually does is grade the *readiness of practices* that
//! downstream consumers ask about, each anchored on a citable source: the
//! OpenSSF Best Practices passing criteria
//! (<https://www.bestpractices.dev/en/criteria/0>) and the OpenSSF Baseline
//! (<https://baseline.openssf.org/>). It never claims a repository is
//! "CRA compliant".
//!
//! # Shape
//!
//! - [`snapshot::RepoSnapshot`] is a read-once view of the repository. Building
//!   one is the only step that touches the filesystem.
//! - [`checks::audit`] is pure: snapshot in, [`model::Report`] out.
//! - [`report`] renders that report as text or JSON.
//!
//! No network access happens at any point.
//!
//! ```no_run
//! use readyproof::{checks, report, snapshot::RepoSnapshot};
//!
//! let snap = RepoSnapshot::scan(std::path::Path::new("."), "my-repo")?;
//! let audit = checks::audit(&snap, &checks::Options::default());
//! print!("{}", report::render_text(&audit, report::RenderOptions { color: false }));
//! # Ok::<(), std::io::Error>(())
//! ```

pub mod checks;
pub mod model;
pub mod report;
pub mod snapshot;
pub mod text;

pub use checks::{audit, Options};
pub use model::{Category, Counts, Finding, Report, Severity, DISCLAIMER};
pub use report::{render_json, render_text, RenderOptions};
pub use snapshot::RepoSnapshot;
