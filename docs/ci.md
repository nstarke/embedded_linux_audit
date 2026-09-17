# CI builds, tests and release reuse

`Agent Tests` runs directly on pull requests, pushes to `main`, and manual
dispatches. `ci-changes.yml` compares the complete push/PR change set. API-only
changes select JavaScript jobs; kernel-module changes also select the host
module build. Documentation-only changes skip those checks. Changes to agent
code, shared tests, build recipes, dependency revisions, CI, or unknown paths
select all checks. Missing diff history falls back to all checks. Scheduled
security scans and manually dispatched workflows always run their full scope.

Workflow-level path filters are intentionally avoided: the workflow still
reports a result when its expensive jobs are unnecessary. `CI / required`
checks the actual results of every selected job and rejects unexpected skips,
failures and cancellations. `tests/agent/qemu-summary` remains a stable summary
check. If branch rules require individual build-job names, update them for the
new reusable-workflow names, or require `CI / required` instead. The repository
does not modify branch protection automatically.

## Architecture jobs

`tools/ci/targets.json` defines the 15 architectures and their ordered Zig
compiler candidates. `ci-isa.yml` runs once per architecture, with up to 15
concurrent invocations:

1. Shallow-checkout the source and required submodules, restore dependencies,
   and build both the release binary and C unit-test binary with the same
   successful compiler target.
2. Immediately run that architecture's QEMU tests using its artifacts.
3. For x86_64, also run native shell and script tests as soon as its build ends.

JavaScript, QEMU, shell and script consumers do not fetch dependency submodules.
QEMU always requires a supplied release binary; missing artifacts fail rather
than silently triggering a second build. Release publication waits for all
architectures, native C coverage/unit tests, JavaScript tests, module checks,
and CI regression tests.

## Dependency cache

`.github/actions/setup-cross` caches Zig 0.14.0 separately from compiled
dependencies. Dependency cache keys include the ISA and complete candidate
list, pinned dependency tree, Makefile, compatibility headers, build support,
CI build scripts, compiler versions, runner image and absolute workspace path.
There are no prefix restore keys. Each target's archives and generated headers
remain in its compiler-specific build directory. A successful fallback target
is recorded in that exact cache so future builds can try it first.

Application binaries, generated application sources, CA bundles, coverage and
efivar's shared in-source build are not cached. `make clean-app` always rebuilds
the agent and unit-test binaries; `make clean` retains its full cleanup behavior.
On an exact cache hit, the build ignores the fresh Makefile's timestamp for
libcurl because the Makefile content has already been checked by the cache key.
wolfSSL's tool availability check is order-only, so it no longer forces the
dependency to rebuild on every invocation.

## Releases

`Release Cross Static Builds` handles published releases and manual dispatches;
it no longer duplicates the push build. It resolves the exact tag commit and
looks for a successful `Agent Tests` push run on `main` in this repository with
all 15 release artifacts and a `tested-commit` manifest. It waits up to roughly
15 minutes if a matching push is still running. PR runs are never reused.

If artifacts are absent, incomplete, expired, or from an unsuccessful run, the
release workflow invokes the complete test workflow at the resolved commit.
Before staging assets, it verifies the manifest SHA and every expected binary.
`Publish Release Assets` runs only after that release workflow succeeds.
Superseded PR workflows are cancelled; release workflows are not.

## Local checks

```sh
python3 tests/ci/test_ci.py
node --test tests/ci/find-tested-run.test.cjs
bash -n tools/ci/build-isa.sh tools/ci/checkout-submodules.sh
actionlint
```

For the initial change, an isolated x86_64 build with four build workers took
117.2 seconds cold and 15.9 seconds after restoring dependency directories into
a fresh checkout at the same path. The 18 restored dependency archives retained
their original timestamps. The rebuilt unit-test binary and release `--help`
both passed. These are local measurements, not GitHub-hosted timing guarantees;
the full architecture matrix and remote cache/artifact transport need a hosted
workflow run.
