//! Print the capability tables as Markdown.
//!
//! `docs/capabilities.md` is this program's output; the test in
//! `tests/capability_report.rs` compares the committed file against a fresh render, so the
//! documentation cannot silently fall behind the code.

fn main() {
    print!("{}", jose_rs::capability::markdown());
}
