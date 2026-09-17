#!/usr/bin/env python3
"""Regression checks for CI selection, dependency identity and release reuse."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/ci" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


changes = load("changes")
cache = load("cache-key")
release = load("stage-release")
gate = load("check-required")


class GateTests(unittest.TestCase):
    def results(self):
        results = {name: {"result": "skipped"} for name in ["agent-unit-c", "agent-c-coverage",
            "architectures", "agent-api-jest", "gdb-api-jest", "terminal-api-jest", "kmod-build"]}
        results.update({name: {"result": "success"} for name in ["changes", "qemu-summary", "pipeline-tests"]})
        results["changes"]["outputs"] = dict(agent="false", javascript="false", kmod="false")
        return results

    def test_docs_skip_is_success(self):
        gate.check(self.results())

    def test_selected_checks_cannot_be_skipped(self):
        results = self.results()
        results["changes"]["outputs"]["javascript"] = "true"
        with self.assertRaises(ValueError):
            gate.check(results)
        for name in ["agent-api-jest", "gdb-api-jest", "terminal-api-jest"]:
            results[name]["result"] = "success"
        gate.check(results)

    def test_failures_and_cancellation_cannot_pass(self):
        for result in ["failure", "cancelled", "skipped"]:
            results = self.results()
            results["pipeline-tests"]["result"] = result
            with self.assertRaises(ValueError):
                gate.check(results)


class SelectionTests(unittest.TestCase):
    def test_docs_only(self):
        self.assertFalse(any(changes.classify(["README.md", "docs/agent/build.md"]).values()))

    def test_api_only_skips_cross_builds(self):
        self.assertEqual(changes.classify(["api/client/app.js", "tests/unit/api/client/app.test.js"]),
                         dict(agent=False, javascript=True, kmod=False))

    def test_kernel_changes_keep_api_builder_tests(self):
        self.assertEqual(changes.classify(["kmod/main.c"]),
                         dict(agent=False, javascript=True, kmod=True))

    def test_shared_and_unknown_inputs_run_everything(self):
        for path in ["Makefile", "third_party/openssl", "compat/unistd.h", "agent/main.c",
                     "tests/common_redaction.sh", ".github/workflows/ci-isa.yml", "new-build-system"]:
            with self.subTest(path=path):
                self.assertTrue(all(changes.classify([path]).values()))

    def test_renames_check_both_source_and_destination(self):
        self.assertTrue(all(changes.classify(["agent/old.c", "docs/old.c"]).values()))

    def test_dispatch_release_and_forced_runs_are_full(self):
        for event in ["release", "workflow_dispatch", "schedule"]:
            self.assertTrue(all(changes.select({}, event).values()))
        self.assertTrue(all(changes.select({}, "push", force=True).values()))

    def test_missing_push_base_is_full(self):
        self.assertTrue(all(changes.select({"before": "0" * 40}, "push").values()))

    @patch.object(changes.subprocess, "check_output", return_value=b"api/agent/app.js\0docs/a.md\0")
    @patch.object(changes.subprocess, "run")
    def test_full_push_diff_not_just_last_commit(self, fetch, diff):
        result = changes.select({"before": "a" * 40}, "push")
        self.assertFalse(result["agent"])
        self.assertEqual(diff.call_args.args[0],
                         ["git", "diff", "--name-only", "--no-renames", "-z", "a" * 40, "HEAD"])

    @patch.object(changes.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git"))
    def test_unavailable_diff_fails_open_to_full_checks(self, fetch):
        self.assertTrue(all(changes.select({"before": "a" * 40}, "push").values()))


class CacheTests(unittest.TestCase):
    def test_recipe_inputs_invalidate_but_application_changes_do_not(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            os.chdir(directory)
            try:
                for filename in ["Makefile", ".gitmodules", "tools/libssh_cc_launcher.py",
                                 "compat/header.h", "build_support/config.m4", "tools/ci/build-isa.sh",
                                 ".github/actions/setup-cross/action.yml", "agent/main.c"]:
                    path = Path(filename)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("original")
                tree = b"160000 dependency-revision-a"

                def command(args):
                    if args[0] == "git": return tree
                    return b"compiler-version"

                with patch.object(cache.subprocess, "check_output", side_effect=command):
                    baseline = cache.dependency_key("x86_64-linux-musl")
                    Path("agent/main.c").write_text("new application code")
                    self.assertEqual(baseline, cache.dependency_key("x86_64-linux-musl"))
                    self.assertNotEqual(baseline, cache.dependency_key("arm-linux-musleabi"))
                    for filename in ["Makefile", "compat/header.h", "build_support/config.m4",
                                     "tools/ci/build-isa.sh", ".github/actions/setup-cross/action.yml"]:
                        path = Path(filename)
                        path.write_text("changed")
                        self.assertNotEqual(baseline, cache.dependency_key("x86_64-linux-musl"))
                        path.write_text("original")
                    tree = b"160000 dependency-revision-b"
                    self.assertNotEqual(baseline, cache.dependency_key("x86_64-linux-musl"))
            finally:
                os.chdir(previous)


class ReleaseTests(unittest.TestCase):
    def test_only_complete_exact_commit_artifacts_can_be_staged(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            target = Path(directory) / "publish"
            marker = source / "tested-commit" / "commit.json"
            marker.parent.mkdir(parents=True)
            marker.write_text(json.dumps(dict(schema=1, sha="a" * 40)))
            for isa in ["x86_64", "powerpc-le"]:
                binary = source / f"ela-{isa}" / f"ela-{isa}"
                binary.parent.mkdir()
                binary.write_bytes(b"test binary")
            with self.assertRaises(ValueError):
                release.stage(source, target, "b" * 40, ["x86_64"])
            self.assertFalse(target.exists())
            with self.assertRaises(ValueError):
                release.stage(source, target, "a" * 40, ["x86_64", "arm32-le"])
            self.assertFalse(target.exists())
            release.stage(source, target, "a" * 40, ["x86_64", "powerpc-le"])
            self.assertEqual((target / "powerpc-le/ela-powerpc64-le").read_bytes(), b"test binary")


if __name__ == "__main__":
    unittest.main()
