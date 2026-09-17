#!/usr/bin/env python3
"""A stable required check that distinguishes intentional skips from missing tests."""
import json
import os


def check(results):
    if results["changes"]["result"] != "success":
        raise ValueError("Job selection failed")
    selected = results["changes"]["outputs"]
    groups = {
        "agent": ["agent-unit-c", "agent-c-coverage", "architectures"],
        "javascript": ["agent-api-jest", "gdb-api-jest", "terminal-api-jest"],
        "kmod": ["kmod-build"],
    }
    required = {"changes", "qemu-summary", "pipeline-tests"}
    for group, jobs in groups.items():
        if selected[group] == "true":
            required.update(jobs)
    for name, job in results.items():
        acceptable = {"success"} if name in required else {"success", "skipped"}
        if job["result"] not in acceptable:
            raise ValueError(f"{name}: {job['result']}")
    if required - results.keys():
        raise ValueError(f"Missing results: {required - results.keys()}")


if __name__ == "__main__":
    check(json.loads(os.environ["RESULTS"]))
