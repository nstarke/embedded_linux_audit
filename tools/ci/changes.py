#!/usr/bin/env python3
"""Select jobs conservatively; unknown paths and unavailable diffs run all checks."""
import json
import os
from pathlib import Path
import subprocess


def classify(paths):
    selected = dict(agent=False, javascript=False, kmod=False)
    for path in paths:
        if path.startswith(("docs/", "screenshots/")) or path in {
            "README.md", "LICENSE", "LICENSE.md", "CHANGELOG.md",
        }:
            continue
        if path.startswith(("api/", "tests/api/", "tests/unit/api/")) or path in {
            "package.json", "package-lock.json",
        }:
            selected["javascript"] = True
        elif path.startswith(("kmod/", "tests/builder/")):
            selected["kmod"] = True
            selected["javascript"] = True
        else:
            # Includes agent/, shared tests, build tools, dependency gitlinks,
            # compatibility headers, workflow changes and newly added paths.
            return dict.fromkeys(selected, True)
    return selected


def select(event, event_name, force=False):
    if force or event_name not in {"push", "pull_request"}:
        return dict(agent=True, javascript=True, kmod=True)
    base = (event["pull_request"]["base"]["sha"] if event_name == "pull_request"
            else event.get("before", ""))
    if not base or set(base) == {"0"}:
        return dict(agent=True, javascript=True, kmod=True)
    try:
        subprocess.run(["git", "fetch", "--no-tags", "--depth=1", "origin", base], check=True)
        paths = subprocess.check_output(
            ["git", "diff", "--name-only", "--no-renames", "-z", base, "HEAD"]
        ).decode().rstrip("\0").split("\0")
        return classify([p for p in paths if p])
    except subprocess.CalledProcessError:
        return dict(agent=True, javascript=True, kmod=True)


if __name__ == "__main__":
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    selected = select(event, os.environ["GITHUB_EVENT_NAME"], os.getenv("FORCE_FULL") == "true")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for name, value in selected.items():
            print(f"{name}={str(value).lower()}", file=output)
    print(json.dumps(selected))
