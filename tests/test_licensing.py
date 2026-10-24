# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""The license split is a legal claim, so it gets a test.

Every one of these assertions has failed in a real project at some point:
a new file with no license header, a README that promises one license while
the license file says another, and a commercial module that quietly gained an
import from a path the NOTICE does not cover. The cost of finding out during
a diligence review is higher than the cost of asserting it here.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

COMMERCIAL = [
    "axon/shield.py",
    "axon/observe.py",
    "axon/vault.py",
    "axon/compliance.py",
    "axon/dashboard.py",
    "axon/integrations.py",
]


def _source_files():
    for pattern in ("axon/**/*.py", "scripts/*.py", "tests/*.py", "data/*.py"):
        yield from ROOT.glob(pattern)


def _header(path, lines=8):
    """Only the top of the file. An identifier quoted inside an assertion is
    prose, not a declaration, and must not be read as one."""
    return "".join(path.read_text(encoding="utf-8").splitlines(keepends=True)[:lines])


def test_every_source_file_declares_a_license():
    missing = []
    for path in _source_files():
        if "__pycache__" in str(path) or "egg-info" in str(path):
            continue
        if "SPDX-License-Identifier" not in _header(path):
            missing.append(str(path.relative_to(ROOT)))
    assert not missing, f"files with no SPDX header: {missing}"


def test_commercial_modules_carry_the_commercial_license():
    for rel in COMMERCIAL:
        text = _header(ROOT / rel)
        assert "SPDX-License-Identifier: BUSL-1.1" in text, (
            f"{rel} is listed in NOTICE as a commercial module but does not "
            "declare BUSL-1.1. A file that is sold cannot be ambiguous."
        )


def test_open_core_files_are_not_accidentally_commercial():
    """A stray header would make an open-core file unsellable-as-open.

    The reverse mistake — marking a commercial file as Apache — is caught
    above. This catches copy-paste in the other direction.
    """
    for path in _source_files():
        rel = str(path.relative_to(ROOT))
        if "__pycache__" in rel or "egg-info" in rel or rel in COMMERCIAL:
            continue
        text = _header(path)
        assert "SPDX-License-Identifier: BUSL-1.1" not in text, (
            f"{rel} declares BUSL-1.1 but is not in the NOTICE commercial list"
        )


def test_the_notice_lists_exactly_the_commercial_modules():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    for rel in COMMERCIAL:
        assert rel in notice, f"NOTICE does not name {rel}"
    # And the NOTICE must not claim a file that does not exist.
    listed = set(re.findall(r"^\s+(axon/[\w/]+\.py)\s*$", notice, re.M))
    for rel in sorted(listed):
        assert (ROOT / rel).exists(), f"NOTICE names {rel}, which does not exist"


def test_the_two_license_files_are_present_and_substantive():
    apache = (ROOT / "LICENSE").read_text(encoding="utf-8")
    busl = (ROOT / "LICENSE-COMMERCIAL").read_text(encoding="utf-8")
    assert "Apache License" in apache and "Version 2.0" in apache
    assert "Business Source License 1.1" in busl
    assert "[yyyy]" not in apache, "the Apache template placeholder was never filled in"
    # BUSL only functions if the parameters are real rather than placeholders.
    for field in ("Licensor:", "Licensed Work:", "Additional Use Grant:",
                  "Change Date:", "Change License:"):
        assert field in busl, f"LICENSE-COMMERCIAL is missing the {field} parameter"


def test_the_readme_does_not_promise_a_single_license():
    """The README said "everything is Apache-2.0" while the plan sold Shield.

    Two documents describing the same repository under different licenses is
    the failure a buyer's lawyer finds. The README must point at NOTICE.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "NOTICE" in readme
    assert "BUSL-1.1" in readme
    assert "no separate enterprise edition" not in readme


def test_the_core_imports_do_not_require_a_commercial_module():
    """The open core must stand alone, or 'open core' is a claim with no teeth.

    `axon/cli.py` is Apache-2.0 and must stay usable with the commercial files
    deleted. Its imports of them are therefore function-local and lazy; a
    module-level import would make the CLI unimportable without the paid half.
    """
    cli = (ROOT / "axon" / "cli.py").read_text(encoding="utf-8")
    top_level = re.findall(r"^from \.(\w+) import|^import axon\.(\w+)", cli, re.M)
    flat = {name for pair in top_level for name in pair if name}
    commercial_stems = {pathlib.Path(p).stem for p in COMMERCIAL}
    leaked = flat & commercial_stems
    assert not leaked, (
        f"axon/cli.py imports {sorted(leaked)} at module level; that couples the "
        "Apache-2.0 core to the BUSL-1.1 half"
    )


def test_paid_commands_degrade_cleanly_when_not_installed(tmp_path):
    """Deleting the commercial modules must not produce a traceback.

    This is the state an open-core-only user is in by definition, so it is the
    one state that has to look intentional. A bare ModuleNotFoundError naming
    an internal path reads like a broken install, not like a paid tier.
    """
    import shutil
    import subprocess
    import sys

    sandbox = tmp_path / "opencore"
    shutil.copytree(
        ROOT, sandbox,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.egg-info", ".venv"),
    )
    for rel in COMMERCIAL:
        (sandbox / rel).unlink()

    env = {"PYTHONPATH": str(sandbox), "PATH": "/usr/bin:/bin"}
    for command in ("compliance", "shield", "observe"):
        proc = subprocess.run(
            [sys.executable, "-m", "axon.cli", command],
            cwd=sandbox, capture_output=True, text=True, env=env, timeout=120,
        )
        combined = proc.stdout + proc.stderr
        assert "Traceback" not in combined, (
            f"`axon {command}` crashed without its commercial module:\n{combined}"
        )
        assert proc.returncode == 8, (
            f"`axon {command}` should exit 8 when its module is missing, "
            f"got {proc.returncode}"
        )
        assert "commercial module" in combined


def test_the_open_core_still_governs_without_the_paid_half(tmp_path):
    """The core promise must survive deleting the commercial files.

    If policy enforcement or the audit ledger only worked with the paid half
    present, the license split would be marketing rather than architecture.
    """
    import shutil
    import subprocess
    import sys

    sandbox = tmp_path / "opencore"
    shutil.copytree(
        ROOT, sandbox,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.egg-info", ".venv"),
    )
    for rel in COMMERCIAL:
        (sandbox / rel).unlink()

    env = {"PYTHONPATH": str(sandbox), "PATH": "/usr/bin:/bin"}

    denied = subprocess.run(
        [sys.executable, "-m", "axon.cli", "policy-check",
         "tool.read_file", "--target", "/home/x/secrets/k"],
        cwd=sandbox, capture_output=True, text=True, env=env, timeout=120,
    )
    assert denied.returncode == 3, "deny-by-default stopped working without the paid half"

    ran = subprocess.run(
        [sys.executable, "-m", "axon.cli", "run", "task",
         "--provider", "mock", "--budget", "0.5"],
        cwd=sandbox, capture_output=True, text=True, env=env, timeout=120,
    )
    assert ran.returncode == 0, f"a governed run failed:\n{ran.stdout}{ran.stderr}"

    verified = subprocess.run(
        [sys.executable, "-m", "axon.cli", "audit", "--ledger", "axon-audit.jsonl"],
        cwd=sandbox, capture_output=True, text=True, env=env, timeout=120,
    )
    assert "chain intact" in verified.stdout
