#!/usr/bin/env python3
"""Checks that every file carrying the version agrees with CMakeLists.txt.

project(openiec61850 VERSION x.y.z) in the top-level CMakeLists.txt is the single source of truth:
the C++ library and the Python package derive their versions from it at build time. vcpkg
manifests need a literal version, so they are checked here instead.

Usage: check_version.py [--tag vX.Y.Z]   (with --tag, also the tag and the CHANGELOG entry)
"""

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def cmake_version() -> str:
    text = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    m = re.search(r"project\(openiec61850\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)", text)
    if not m:
        sys.exit("CMakeLists.txt: no project(openiec61850 VERSION x.y.z)")
    return m.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="release tag to check, e.g. v0.1.0")
    args = parser.parse_args()

    version = cmake_version()
    errors = []
    for manifest in ("vcpkg.json", "packaging/vcpkg/openiec61850/vcpkg.json"):
        found = json.loads((ROOT / manifest).read_text(encoding="utf-8")).get("version")
        if found is not None and found != version:
            errors.append(f"{manifest}: version {found}, CMakeLists.txt has {version}")
    if args.tag is not None:
        if args.tag != f"v{version}":
            errors.append(f"tag {args.tag} does not match CMakeLists.txt version {version}")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        if not re.search(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.M):
            errors.append(f"CHANGELOG.md has no '## [{version}] - YYYY-MM-DD' section")

    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if not errors:
        print(version)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
