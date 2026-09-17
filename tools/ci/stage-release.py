#!/usr/bin/env python3
"""Reject incomplete/mismatched reuse before preparing publication artifacts."""
import json
import os
from pathlib import Path
import shutil


def stage(source, destination, expected_sha, isas):
    manifest = json.loads((source / "tested-commit" / "commit.json").read_text())
    if manifest != {"schema": 1, "sha": expected_sha}:
        raise ValueError("Artifacts were not fully tested at the release commit")
    binaries = [(isa, source / f"ela-{isa}" / f"ela-{isa}") for isa in isas]
    for _, binary in binaries:
        if not binary.is_file() or binary.stat().st_size == 0:
            raise ValueError(f"Missing release binary: {binary}")
    for isa, binary in binaries:
        target = destination / isa
        target.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(binary, target / binary.name)
        if isa == "powerpc-le":
            shutil.copyfile(binary, target / "ela-powerpc64-le")


if __name__ == "__main__":
    isas = [t["isa"] for t in json.loads(Path("tools/ci/targets.json").read_text())]
    stage(Path("tested-artifacts"), Path("release-assets"), os.environ["RELEASE_SHA"], isas)
