# Tests

This repository includes shell-based argument coverage tests under `tests/`.

## Prerequisites

- Build the binary first:

```bash
make
```

- Test scripts expect `./embedded_linux_audit` at the repo root.

## Run all tests

Use either:

```bash
make test
```

or directly:

```bash
bash tests/test_all.sh
```

`test_all.sh` executes:
- `tests/test_env_args.sh`
- `tests/test_image_args.sh`
- `tests/test_audit_args.sh`
- `tests/test_dmesg_args.sh`
- `tests/test_remote_copy_args.sh`

It returns non-zero if any test group fails.

## Run individual test groups

```bash
sh tests/test_env_args.sh
sh tests/test_image_args.sh
sh tests/test_audit_args.sh
sh tests/test_dmesg_args.sh
sh tests/test_remote_copy_args.sh
```

## What each test script covers

- `test_env_args.sh`: validates accepted/expected behavior of `env` arguments.
- `test_image_args.sh`: validates accepted/expected behavior of `image` arguments and mode combinations.
- `test_audit_args.sh`: validates accepted/expected behavior of `audit` arguments, output formats, and rule selections.
- `test_dmesg_args.sh`: validates accepted/expected behavior of `dmesg` arguments and `--output-format` warning behavior.
- `test_remote_copy_args.sh`: validates accepted/expected behavior of `remote-copy` arguments and transfer-target constraints.

These are argument/CLI behavior coverage tests, not full hardware integration tests.

## Optional HTTP/HTTPS output override while testing

`test_all.sh` supports:

```bash
bash tests/test_all.sh --output-http http://127.0.0.1:5000/test
bash tests/test_all.sh --output-https https://127.0.0.1:5443/test
```

You can also set environment variables used by shared test helpers:

- `TEST_OUTPUT_HTTP`
- `TEST_OUTPUT_HTTPS`

Set only one of them at a time.

## Download helper for release-binary test runs

`tests/download_tests.sh` can download test scripts and a selected release binary from a web server.

List supported ISAs (derived from `tools/release_binaries/embedded_linux_audit-*`):

```bash
sh tests/download_tests.sh --list-isa
```

Download scripts + binary:

```bash
sh tests/download_tests.sh --webserver http://<host>:<port> --isa <arch>
```

Optional output directory:

```bash
sh tests/download_tests.sh --webserver http://<host>:<port> --isa <arch> --output-directory /tmp/fw-tests
```
