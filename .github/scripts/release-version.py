# Does:  Selects a release version from the manifests on either side of a merge.
# Holds: Equal package versions produce no output and a decrease in precedence fails.

import subprocess
import sys
import tomllib


def version_at(commit):
    manifest = subprocess.check_output(["git", "show", f"{commit}:Cargo.toml"], text=True)
    return tomllib.loads(manifest)["package"]["version"]


def precedence(version):
    # Why: SemVer excludes build metadata from version precedence.
    core, _, prerelease = version.split("+", 1)[0].partition("-")
    identifiers = tuple(
        (0, int(part)) if part.isdecimal() else (1, part)
        for part in prerelease.split(".")
    )
    return tuple(map(int, core.split("."))), not prerelease, identifiers


previous, current = map(version_at, sys.argv[1:])
if current != previous:
    if precedence(current) <= precedence(previous):
        sys.exit(f"Release version must increase: {previous} -> {current}")
    print(current)
