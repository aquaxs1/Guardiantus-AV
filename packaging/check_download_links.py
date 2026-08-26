#!/usr/bin/env python3
"""Verify the website's download links point at files that actually exist.

The site hardcodes release asset names into
``.../releases/latest/download/<name>``. Two things can go wrong there, and
only one of them is visible in a diff:

*offline* (always checked)
    The name on the site is not one the release workflow builds -- a typo, or
    a rename applied to one file and not the other.

*online* (``--online``)
    The name is right, but no published release carries it yet. That is what
    happens after renaming an asset and before cutting the release, and it is
    invisible in CI until someone clicks the button. Run against ``main`` so
    a broken live download page is reported rather than discovered.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Set

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

#: Matches the asset URLs the site links to, capturing the file name.
_LINK = re.compile(r"releases/latest/download/([A-Za-z0-9._-]+)")

#: download.js builds its URLs from a table of bare file names, so the
#: pattern above never sees them. Match the names themselves as well.
_ASSET = re.compile(r"\b(guardiantus-av-[A-Za-z0-9._-]+)")

#: The ``include:`` list under ``strategy.matrix`` in the release workflow.
#: Parsed by hand rather than with a YAML library so this check stays
#: dependency-free, the way the rest of the project is.
_INCLUDE = re.compile(r"^(\s*)include:\s*$", re.M)
_ENTRY = re.compile(r"^\s*-\s")
_KEY = re.compile(r"^\s*-?\s*([a-z_]+):\s*(\S+)\s*$")


def site_links() -> Dict[str, List[str]]:
    """Every release asset the site references, mapped to where it appears."""
    found: Dict[str, List[str]] = {}
    for path in sorted(SITE.rglob("*")):
        if path.suffix not in (".html", ".js") or not path.is_file():
            continue
        body = path.read_text(encoding="utf-8")
        for name in _LINK.findall(body) + _ASSET.findall(body):
            where = str(path.relative_to(ROOT))
            places = found.setdefault(name, [])
            if where not in places:
                places.append(where)
    return found


def workflow_assets() -> Set[str]:
    """Every asset name the release workflow uploads."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()

    start = next((i for i, line in enumerate(lines) if _INCLUDE.match(line)), None)
    if start is None:
        raise SystemExit(
            f"{WORKFLOW.name}: no matrix 'include:' block found -- the workflow "
            "shape changed, update this check"
        )

    indent = len(lines[start]) - len(lines[start].lstrip())
    entries: List[Dict[str, str]] = []
    for line in lines[start + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= indent:
            break  # dedented back out of the include list
        if _ENTRY.match(line):
            entries.append({})
        key = _KEY.match(line)
        if key and entries:
            entries[-1][key.group(1)] = key.group(2)

    assets = set()
    for entry in entries:
        try:
            assets.add(f"guardiantus-av-{entry['name']}.{entry['asset_ext']}")
        except KeyError as exc:
            raise SystemExit(
                f"{WORKFLOW.name}: matrix entry {entry} has no {exc} -- the "
                "matrix shape changed, update this check"
            ) from None
    if not assets:
        raise SystemExit(
            f"{WORKFLOW.name}: the matrix builds nothing -- update this check"
        )
    assets.add("SHA256SUMS.txt")  # added by the release job, not the matrix
    return assets


def check_offline() -> List[str]:
    """Does every link name something the workflow builds?"""
    built = workflow_assets()
    problems = []
    for name, places in sorted(site_links().items()):
        if name not in built:
            problems.append(
                f"{name} is linked from {', '.join(places)} but the release "
                f"workflow does not build it (it builds: {', '.join(sorted(built))})"
            )
    return problems


def check_online(repo: str) -> List[str]:
    """Does every link resolve against the published latest release?"""
    problems = []
    for name, places in sorted(site_links().items()):
        url = f"https://github.com/{repo}/releases/latest/download/{name}"
        request = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except OSError as exc:
            problems.append(f"{name}: could not be checked ({exc})")
            continue
        if status >= 400:
            problems.append(
                f"{name} -> HTTP {status}. Linked from {', '.join(places)}, but "
                "no published release carries it. Cut a release, or point the "
                "site at an asset that exists."
            )
        else:
            print(f"  ok   {name} -> HTTP {status}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--online",
        action="store_true",
        help="also check each link against the published latest release",
    )
    parser.add_argument("--repo", default="aquaxs1/Guardiantus-AV")
    args = parser.parse_args()

    links = site_links()
    if not links:
        print("No release download links found on the site -- nothing to check.")
        return 0
    print(f"Checking {len(links)} download link(s) referenced by the site.")

    problems = check_offline()
    if args.online and not problems:
        # Only worth asking GitHub once the names themselves are sane.
        problems += check_online(args.repo)

    if problems:
        print("\nBroken download links:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("Every download link checks out.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
