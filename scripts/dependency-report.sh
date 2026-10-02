#!/usr/bin/env bash
# Print the facts behind docs/dependencies.md, straight from Cargo.toml / Cargo.lock.
#
#   ./scripts/dependency-report.sh            # markdown table of locked versions
#   ./scripts/dependency-report.sh --duplicates   # only the duplicated major families
#
# Why a script and not a copy-paste: `docs/dependencies.md` states exact locked
# versions, and a document that states versions has to be re-derivable or it becomes
# folklore. `tests/dependency_policy.rs` enforces the doc against the manifest and the
# lock on every commit; this script is what a human runs to *update* the doc, or to see
# what changed when that test fails.
#
# Nothing here resolves or updates anything: it reads the lock as checked in, which is
# the whole point (a dependency change must be an explicit, reviewed change of its own).

set -u -o pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." || exit 1

MODE="${1:-table}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to parse Cargo.lock" >&2
    exit 1
fi

python3 - "$MODE" << 'PY'
import re
import sys
import pathlib

mode = sys.argv[1]
lock = pathlib.Path("Cargo.lock").read_text()
manifest = pathlib.Path("Cargo.toml").read_text()

versions: dict[str, list[str]] = {}
for block in re.findall(r"\[\[package\]\]\n(.*?)(?=\n\[|\Z)", lock, re.S):
    name = re.search(r'name = "([^"]+)"', block)
    version = re.search(r'version = "([^"]+)"', block)
    if not name or not version:
        continue
    versions.setdefault(name.group(1), []).append(version.group(1))
for values in versions.values():
    values.sort(key=lambda v: tuple(int(part) for part in re.findall(r"\d+", v)[:3]))

section = re.search(r"\[dependencies\]\n(.*?)\n\n", manifest, re.S)
if not section:
    print("could not find [dependencies] in Cargo.toml", file=sys.stderr)
    raise SystemExit(2)

direct: list[tuple[str, bool]] = []
for line in section.group(1).splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    name = line.split("=", 1)[0].strip().strip('"')
    real, optional = name, False
    if real.startswith("pkcs8-pq"):
        real = "pkcs8"
    if "optional = true" in line:
        optional = True
    direct.append((real, optional))

duplicates = {name: values for name, values in versions.items() if len(values) > 1}

if mode == "--duplicates":
    print(f"{len(duplicates)} names resolve to more than one major in Cargo.lock:\n")
    for name in sorted(duplicates):
        marker = " (direct)" if name in {real for real, _ in direct} else ""
        print(f"  {name}: {', '.join(duplicates[name])}{marker}")
    print(
        "\nThe actionable set is the ones marked (direct): those are the majors this "
        "crate\nrequires, and the ones docs/dependencies.md must document."
    )
    raise SystemExit(0)

if mode not in ("table", "facts"):
    print(f"unknown mode: {mode}", file=sys.stderr)
    raise SystemExit(2)

rust_version = re.search(r'rust-version = "([^"]+)"', manifest)
if mode == "facts":
    print(f"declared MSRV: {rust_version.group(1) if rust_version else 'undeclared'}")
    print(f"locked packages: {len(versions)}")
    print(f"duplicated majors: {len(duplicates)}")
    features = re.search(r"\[features\]\n(.*?)\n\n", manifest, re.S)
    if features:
        names = [line.split("=", 1)[0].strip() for line in features.group(1).splitlines() if "=" in line]
        print(f"features: {', '.join(names)}")
    print()

print("| Crate | Locked | Direct requirement |")
print("|---|---|---|")
for real, optional in direct:
    values = ", ".join(versions.get(real, ["not in lock"]))
    tag = " *(optional)*" if optional else ""
    print(f"| `{real}`{tag} | {values} | see Cargo.toml |")

ignored = re.findall(r'"(RUSTSEC-[0-9]{4}-[0-9]{4})"', pathlib.Path(".cargo/audit.toml").read_text())
print(f"\nAdvisory ignores in `.cargo/audit.toml`: {', '.join(ignored) if ignored else 'none'}")
PY
