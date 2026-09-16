#!/usr/bin/env python3
"""Fail if any relative Markdown link in the repo points at a path that doesn't exist.

This repo is mostly documents that cross-reference each other (detection ->
lab -> playbook -> validation), and it was assembled from five separate
repositories, so links are the thing most likely to rot. External http(s)
links are not checked: that would make CI depend on other people's servers.
"""

import re
import subprocess
import sys
from pathlib import Path

LINK = re.compile(r"\]\(([^)#\s]+)")


def main():
    root = Path(__file__).resolve().parent.parent
    tracked = subprocess.run(["git", "ls-files", "*.md"], cwd=root,
                             capture_output=True, text=True, check=True).stdout.split()
    files = tracked or [str(p.relative_to(root)) for p in root.rglob("*.md")]

    broken = []
    for rel in files:
        path = root / rel
        for target in LINK.findall(path.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (path.parent / target).resolve().exists():
                broken.append(f"{rel}: {target}")

    print(f"Checked {len(files)} Markdown files.")
    for b in broken:
        print(f"  broken: {b}")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
