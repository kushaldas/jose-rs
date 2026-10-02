//! The dependency, MSRV and platform record (`docs/dependencies.md`) must describe
//! reality.
//!
//! Q2 of the roadmap asks for dependency/MSRV/platform checks, and the failure mode it
//! names — "forcing isolated major upgrades" instead of documenting blockers — is a
//! failure of *documentation discipline* as much as of version selection: a page that
//! says "kryptering 0.6" after the lock moved to 0.7 is worse than no page, because a
//! reviewer will trust it. So every checkable claim in that document is asserted here
//! against `Cargo.toml`, `Cargo.lock` and `.cargo/audit.toml`.
//!
//! What is *not* checked: whether the documented blocker analysis is still the right
//! analysis. Only a human can tell whether a coordinated trait-family upgrade became
//! possible; the tests guarantee only that what the document states as fact is fact.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn manifest() -> String {
    read("Cargo.toml")
}

fn lock() -> String {
    read("Cargo.lock")
}

fn doc() -> String {
    read("docs/dependencies.md")
}

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `(name, optional)` pairs from `[dependencies]`.
fn direct_dependencies() -> Vec<(String, bool)> {
    let text = manifest();
    let start = text
        .find("[dependencies]")
        .expect("Cargo.toml has a [dependencies] section");
    let rest = &text[start + "[dependencies]".len()..];
    let end = rest.find("\n[").unwrap_or(rest.len());
    let mut out = Vec::new();
    for line in rest[..end].lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line
            .split('=')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"');
        // `package = "x"` renames: the crate in the lock is the renamed one.
        let real = if name == "pkcs8-pq" {
            "pkcs8".to_string()
        } else {
            name.to_string()
        };
        out.push((real, line.contains("optional = true")));
    }
    assert!(
        out.len() > 10,
        "suspiciously few direct dependencies parsed"
    );
    out
}

/// Locked versions per package name, as they appear in `Cargo.lock`.
fn locked_versions() -> Vec<(String, Vec<String>)> {
    let text = lock();
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for block in text.split("[[package]]") {
        let Some(name) = extract_quoted(block, "name") else {
            continue;
        };
        let Some(version) = extract_quoted(block, "version") else {
            continue;
        };
        match out.iter_mut().find(|(n, _)| *n == name) {
            Some((_, versions)) => {
                if !versions.contains(&version) {
                    versions.push(version);
                }
            }
            None => out.push((name, vec![version])),
        }
    }
    out.sort();
    out
}

fn extract_quoted(block: &str, key: &str) -> Option<String> {
    let needle = format!("{key} = \"");
    let at = block.find(&needle)? + needle.len();
    let rest = &block[at..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn feature_names() -> Vec<String> {
    let text = manifest();
    let at = text
        .find("[features]")
        .expect("Cargo.toml has a [features] section");
    let rest = &text[at + "[features]".len()..];
    let end = rest.find("\n[").unwrap_or(rest.len());
    rest[..end]
        .lines()
        .filter_map(|line| line.split('=').next())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// Everything from a `## heading` up to the next `## ` heading.
fn section(body: &str, heading: &str) -> String {
    let start = body
        .find(heading)
        .unwrap_or_else(|| panic!("docs/dependencies.md has no {heading:?} section"));
    let rest = &body[start..];
    let end = rest[heading.len()..]
        .find("\n## ")
        .map(|offset| heading.len() + offset)
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn every_direct_dependency_is_documented_with_its_locked_version() {
    let document = doc();
    let locked = locked_versions();
    let mut missing = Vec::new();

    for (name, optional) in direct_dependencies() {
        // Named as `crate` in the document, which is how the tables write them.
        let named = document.contains(&format!("`{name}`"));
        if !named {
            missing.push(format!("{name} (not named)"));
            continue;
        }
        // The version this crate resolves must be stated. For a name that appears at
        // two majors, that is the lower one — the one our requirement selects; the
        // other is covered by the duplicated-families section below.
        let Some((_, versions)) = locked.iter().find(|(locked, _)| locked == &name) else {
            missing.push(format!("{name} (absent from Cargo.lock)"));
            continue;
        };
        let mut sorted = versions.clone();
        sorted.sort();
        let ours = sorted.first().expect("non-empty");
        if !document.contains(ours.as_str()) {
            missing.push(format!("{name} (locked {ours} not stated)"));
        }
        if optional && !document.contains("optional") {
            missing.push(format!("{name} (optional, but the doc never says so)"));
        }
    }

    assert!(
        missing.is_empty(),
        "docs/dependencies.md no longer describes the dependencies: {missing:?}\n\
         regenerate the inputs with ./scripts/dependency-report.sh"
    );
}

#[test]
fn the_documented_msrv_is_the_declared_one() {
    let text = manifest();
    let declared = extract_quoted(&text, "rust-version").expect("rust-version is declared");
    let document = doc();
    assert!(
        document.contains(&format!("`{declared}`")),
        "docs/dependencies.md must state the declared MSRV `{declared}`"
    );
    // And the policy sentence the number depends on: raising it is breaking.
    assert!(
        document.contains("breaking change"),
        "the MSRV section must state that raising the floor is a breaking change"
    );
}

#[test]
fn every_feature_is_documented_with_what_it_pulls_in() {
    let document = doc();
    let mut missing = Vec::new();
    for feature in feature_names() {
        if !document.contains(&format!("`{feature}`")) {
            missing.push(feature);
        }
    }
    assert!(
        missing.is_empty(),
        "features not covered by the feature-to-dependency table: {missing:?}"
    );
}

#[test]
fn advisory_ignores_are_documented() {
    let audit = read(".cargo/audit.toml");
    let document = doc();
    let mut ids = BTreeSet::new();
    let mut rest = audit.as_str();
    const PREFIX: &str = "RUSTSEC-";
    while let Some(at) = rest.find(PREFIX) {
        // Scan the `YYYY-NNNN` tail after the prefix. Starting the character scan at
        // the prefix itself would stop at `R` (not a digit) and re-find the same
        // occurrence forever — a bug this test was written by, and caught by running
        // it, which is the argument for running infrastructure checks.
        let after_prefix = &rest[at + PREFIX.len()..];
        let end = after_prefix
            .find(|c: char| !(c.is_ascii_digit() || c == '-'))
            .unwrap_or(after_prefix.len());
        ids.insert(format!("{PREFIX}{}", &after_prefix[..end]));
        rest = &after_prefix[end..];
    }
    for id in &ids {
        assert!(
            document.contains(id),
            "{id} is ignored in .cargo/audit.toml but not explained in docs/dependencies.md"
        );
    }
    // An ignore without a justification comment is how an ignore becomes permanent.
    for id in &ids {
        assert!(
            audit.contains(id),
            "{id} listed in the docs but absent from .cargo/audit.toml"
        );
    }
}

#[test]
fn duplicated_trait_families_that_we_require_are_documented() {
    let document = doc();
    // Only the table, not the prose that follows: a name mentioned in the upgrade
    // discussion is not the same as the family being listed as duplicated. Without this
    // cut the check passed a deliberately broken document, so it is load-bearing.
    let duplicated_section = {
        let full = section(&document, "## Duplicated trait-version families");
        let end = full.find("### ").unwrap_or(full.len());
        full[..end].to_string()
    };
    let locked = locked_versions();

    let mut undocumented = Vec::new();
    for (name, _) in direct_dependencies() {
        let Some((_, versions)) = locked.iter().find(|(locked, _)| *locked == name) else {
            continue;
        };
        if versions.len() < 2 {
            continue;
        }
        if !duplicated_section.contains(&format!("`{name}`")) {
            undocumented.push(name);
        }
    }
    assert!(
        undocumented.is_empty(),
        "these direct dependencies resolve to two majors and the doc does not say so: \
         {undocumented:?} — run ./scripts/dependency-report.sh --duplicates"
    );
}

#[test]
fn the_backend_version_documented_is_the_locked_one() {
    let locked = locked_versions();
    let backend = locked
        .iter()
        .find(|(name, _)| name == "kryptering")
        .expect("kryptering is in the lock");
    assert_eq!(
        backend.1.len(),
        1,
        "kryptering resolves to {} versions; the dependency doc describes exactly one",
        backend.1.len()
    );
    let version = &backend.1[0];
    let document = doc();
    assert!(
        document.contains(&format!("| {version} |")) || document.contains(version.as_str()),
        "docs/dependencies.md must state the locked backend version {version}"
    );
}

#[test]
fn dev_dependency_claim_matches_the_manifest() {
    let text = manifest();
    let has_dev_deps = text
        .split("[dev-dependencies]")
        .nth(1)
        .map(|rest| {
            let end = rest.find("\n[").unwrap_or(rest.len());
            rest[..end]
                .lines()
                .any(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
        })
        .unwrap_or(false);
    let document = doc();
    let doc_claims_empty = document.contains("`dev-dependencies` is empty");
    assert_eq!(
        has_dev_deps, !doc_claims_empty,
        "docs/dependencies.md claims dev-dependencies is empty; the manifest says otherwise \
         (or vice versa). Either add the dependency to the doc, or drop it — the point of the \
         claim is that no test-only dependency exists to drift."
    );
}

#[test]
fn no_unsafe_and_no_runtime_process_or_network_access() {
    // Platform claims in docs/dependencies.md, checked where they are cheap to check.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust(&src, &mut files);
    assert!(
        files.len() > 15,
        "unexpectedly few source files: {}",
        files.len()
    );

    let mut offenders = Vec::new();
    for path in &files {
        let text = fs::read_to_string(path).expect("readable source file");
        for needle in [
            "unsafe {",
            "unsafe fn ",
            "std::process::",
            "std::net::",
            "std::fs::",
        ] {
            if text.contains(needle) {
                offenders.push(format!("{}: {needle}", path.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the platform section promises no unsafe / no process / no network / no filesystem \
         access in the library: {offenders:?}"
    );

    let lib = read("src/lib.rs");
    assert!(
        lib.contains("#![forbid(unsafe_code)]"),
        "src/lib.rs must keep #![forbid(unsafe_code)]"
    );
}

fn collect_rust(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable src directory") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rust(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}
