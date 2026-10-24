#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Fail when a test skips.

A green suite that skipped 39 OIDC tests is worse than a red one: the badge
says "357 passing" while the security layer a buyer is paying for was never
executed. Skipping is how that happens quietly, so it is not allowed here.

Tests that genuinely cannot run on a platform should be marked with an
explicit reason and added to ALLOWED, which forces the decision to be visible
in review rather than emergent from a missing dependency.
"""

from __future__ import annotations

import re
import subprocess
import sys

# Empty on purpose. Add an entry only with a reason, e.g. "windows-only: ...".
ALLOWED: tuple[str, ...] = ()

SUMMARY = re.compile(r"^(?:SKIPPED|XFAIL)\b", re.M)


def main() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", "--no-header"],
        capture_output=True, text=True,
    )
    output = proc.stdout + proc.stderr

    if proc.returncode != 0:
        print(output[-4000:])
        print(f"pytest failed with exit code {proc.returncode}", file=sys.stderr)
        return 1

    skips = [line.strip() for line in SUMMARY.findall(output)]
    # `-rs` prints a summary section; count the entries rather than the header.
    entries = [
        line for line in output.splitlines()
        if line.startswith("SKIPPED") or line.startswith("XFAIL")
    ]
    entries = [line for line in entries if line not in ALLOWED]

    if entries:
        print(f"{len(entries)} test(s) skipped — a skipped security test is an "
              "unverified security claim:", file=sys.stderr)
        for line in entries:
            print(f"  {line}", file=sys.stderr)
        return 1

    del skips
    print("no tests skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
