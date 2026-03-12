#!/usr/bin/env python3

import os
import subprocess
import sys


DROP_FLAGS = {
    "-D_GNU_SOURCE",
    "-fstack-clash-protection",
    "-Wstrict-prototypes",
    "-Werror=strict-prototypes",
}

REWRITE_FLAGS = {
    "-Werror=strict-prototypes": "-Wno-error=strict-prototypes",
    "-Wstrict-prototypes": "-Wno-strict-prototypes",
}


def main() -> int:
    if len(sys.argv) < 2:
        print("libssh_cc_launcher.py: missing compiler command", file=sys.stderr)
        return 1

    filtered = []
    for arg in sys.argv[1:]:
        replacement = REWRITE_FLAGS.get(arg)
        if replacement is not None:
            filtered.append(replacement)
            continue
        if arg in DROP_FLAGS:
            continue
        filtered.append(arg)

    return subprocess.call(filtered, env=os.environ.copy())


if __name__ == "__main__":
    raise SystemExit(main())