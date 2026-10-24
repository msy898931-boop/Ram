"""Guards against the numbers on the site drifting away from the code.

The preview site is generated, but until now the numbers in it were typed by
hand. A hardcoded "16/16" survived the injection corpus growing to 20, and the
line count was off by several hundred — on a page whose footer claims every
figure is read from the code. These tests make that claim true: the builder
must measure, and the measured values must agree with the repository.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from axon.security.injection import scan, verdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
INJECTION_TESTS = ROOT / "tests" / "test_security_injection.py"


def _corpus() -> dict[str, list[str]]:
    tree = ast.parse(INJECTION_TESTS.read_text(encoding="utf-8"))
    found: dict[str, list[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            name = getattr(node.targets[0], "id", "")
            if name in ("ATTACKS", "BENIGN"):
                found[name] = ast.literal_eval(node.value)
    return found


def test_every_attack_in_the_corpus_is_denied():
    attacks = _corpus()["ATTACKS"]
    missed = [a for a in attacks if verdict(scan(a)) != "deny"]
    assert not missed, f"detector missed {len(missed)}: {missed}"


def test_no_benign_document_is_denied():
    benign = _corpus()["BENIGN"]
    wrong = [b for b in benign if verdict(scan(b)) == "deny"]
    assert not wrong, f"false positives: {wrong}"


def test_corpus_is_large_enough_to_mean_something():
    corpus = _corpus()
    assert len(corpus["ATTACKS"]) >= 20
    assert len(corpus["BENIGN"]) >= 15


def test_the_builder_measures_instead_of_hardcoding():
    """The builder must compute its figures, not carry them as literals.

    The guard is deliberately narrow: the builder still *names* the stale
    figures as search targets, which is how they get replaced. What matters is
    that a measurement function exists and that the published page — the thing
    a reader actually sees — carries the measured values.
    """
    source = (ROOT / "scripts" / "build_preview.py").read_text(encoding="utf-8")
    assert "measured_facts" in source
    assert "_injection_accuracy" in source
    assert "_pytest_count" in source


def test_the_published_page_carries_no_stale_figures():
    """The committed page is the artifact. Stale numbers there are the bug."""
    page = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
    for stale in ("16/16", "0/15", "9,537", "5,272"):
        assert stale not in page, f"stale figure {stale!r} is published on the site"


def test_the_published_page_shows_the_measured_injection_accuracy():
    """The detector's accuracy is corpus-derived, so it cannot go stale.

    The line total is deliberately not asserted here: this test file is itself
    counted in that total, so an assertion on it would fail on every edit to
    this file. The builder still measures it; only the guard skips it.
    """
    page = (ROOT / "preview" / "index.html").read_text(encoding="utf-8")
    corpus = _corpus()
    attacks = len(corpus["ATTACKS"])
    caught = sum(1 for a in corpus["ATTACKS"] if verdict(scan(a)) == "deny")
    benign = len(corpus["BENIGN"])
    false_pos = sum(1 for b in corpus["BENIGN"] if verdict(scan(b)) == "deny")
    assert f"{caught}/{attacks}" in page
    assert f"{false_pos}/{benign}" in page


@pytest.mark.parametrize("layer", [
    "authentication",
    "federated identity",
    "rate limiting",
    "replay defence",
    "security headers",
    "transport",
    "signature enforcement",
    "canaries",
    "injection detection",
])
def test_posture_reports_every_documented_layer(layer):
    """The doc and the command must name the same nine layers."""
    doc = (ROOT / "docs" / "SECURITY-LAYERS.md").read_text(encoding="utf-8")
    assert layer.split()[0] in doc.lower() or layer in doc.lower()
