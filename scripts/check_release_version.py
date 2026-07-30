#!/usr/bin/env python3
from __future__ import annotations

import argparse
import tomllib
from pathlib import Path

from private_dav_mcp import __version__


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a release tag matches package versions.")
    parser.add_argument("tag", help="Release tag in vMAJOR.MINOR.PATCH form")
    args = parser.parse_args()

    tag = args.tag
    if not tag.startswith("v") or tag.count(".") != 2:
        raise SystemExit(f"release tag must use vMAJOR.MINOR.PATCH format, got {tag!r}")
    tag_version = tag[1:]
    project = tomllib.loads(Path("pyproject.toml").read_text())
    package_version = project["project"]["version"]
    versions = {
        "release tag": tag_version,
        "pyproject.toml": package_version,
        "private_dav_mcp.__version__": __version__,
    }
    if len(set(versions.values())) != 1:
        details = ", ".join(f"{name}={version}" for name, version in versions.items())
        raise SystemExit(f"release versions do not match: {details}")
    print(f"release version verified: {tag_version}")


if __name__ == "__main__":
    main()
