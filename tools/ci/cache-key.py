#!/usr/bin/env python3
"""Exact dependency recipe identity, independent of application-only changes."""
import hashlib
import os
from pathlib import Path
import subprocess


def dependency_key(targets):
    digest = hashlib.sha256()
    # gitlinks, not .gitmodules alone: pinning a new revision must invalidate.
    digest.update(subprocess.check_output(["git", "ls-tree", "HEAD", "third_party"]))
    files = [Path("Makefile"), Path(".gitmodules")]
    for directory in ("compat", "build_support", "tools/ci", ".github/actions/setup-cross"):
        files.extend(p for p in Path(directory).rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts)
    files.append(Path("tools/libssh_cc_launcher.py"))
    for path in sorted(files):
        digest.update(str(path).encode() + b"\0" + path.read_bytes() + b"\0")
    # Build directories contain absolute compiler/include paths. Keep caches
    # separate if the checkout location, runner image or compiler changes.
    for value in (targets, str(Path.cwd()), os.getenv("ImageOS", ""),
                  os.getenv("ImageVersion", ""),
                  subprocess.check_output(["zig", "version"]).decode(),
                  subprocess.check_output(["cc", "--version"]).decode()):
        digest.update(value.encode() + b"\0")
    return digest.hexdigest()


if __name__ == "__main__":
    print("key=" + dependency_key(os.environ["ZIG_TARGETS"]))
