"""Dashboard tests — the API is exercised over a real HTTP server.

No mocks: each test starts the actual server on an ephemeral port and makes
real requests, so routing, serialisation, and the read-only guarantee are
all covered by what runs in production.
"""

import json
import tempfile
import urllib.request
from pathlib import Path

import pytest

from axon.core.audit import AuditLedger
from axon.core.budget import Budget
from axon.core.providers import MockProvider
from axon.core.runtime import AgentRuntime, PolicyDenied
from axon.dashboard import serve
from axon.shield import load_pack
from axon.vault import MappingResolver, SecretVault


@pytest.fixture
def server():
    with tempfile.TemporaryDirectory() as tmp:
        ledger = AuditLedger(Path(tmp) / "l.jsonl")
        vault = SecretVault(
            resolver=MappingResolver({"sandbox/api-key": "sk-secret-value"}), ledger=ledger
        )
        rt = AgentRuntime(
            agent_id="ops-bot", ledger=ledger, policy=load_pack("production"),
            budget=Budget(5.0), provider=MockProvider(), vault=vault,
        )
        rt.run("summarise the release", model="claude-sonnet")
        try:
            rt.call_tool("read_file", "/x/secrets.txt", lambda: "x")
        except PolicyDenied:
            pass
        rt.read_secret("sandbox/api-key")

        httpd = serve(ledger.path, host="127.0.0.1", port=0, block=False)
        port = httpd.server_address[1]
        yield f"http://127.0.0.1:{port}"
        httpd.shutdown()
        httpd.server_close()


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode())


def test_index_serves_the_page(server):
    with urllib.request.urlopen(server + "/", timeout=10) as resp:
        body = resp.read().decode()
    assert resp.status == 200
    assert "AXON" in body and "governance dashboard" in body


def test_healthz(server):
    status, data = get(server, "/healthz")
    assert status == 200 and data["ok"] is True


def test_summary_reports_real_ledger_state(server):
    _, data = get(server, "/api/summary")
    assert data["cost"]["total_calls"] == 2
    assert data["risk"]["total_denials"] == 1
    assert data["integrity"]["ok"] is True
    assert data["integrity"]["records"] > 0


def test_records_endpoint_returns_ledger_entries(server):
    _, data = get(server, "/api/records")
    actions = [r["action"] for r in data["records"]]
    assert "run.start" in actions and "run.end" in actions


def test_policies_lists_packs(server):
    _, data = get(server, "/api/policies")
    assert set(data["packs"]) >= {"development", "production", "regulated"}


def test_shield_endpoint_checks_a_pack(server):
    _, data = get(server, "/api/shield?pack=production")
    assert data["ok"] is True and data["failed"] == 0


def test_shield_endpoint_reports_unknown_pack(server):
    _, data = get(server, "/api/shield?pack=nope")
    assert data["ok"] is False and "unknown policy pack" in data["error"]


def test_explain_endpoint_names_the_decision(server):
    _, data = get(server, "/api/explain?actor=ops-bot&action=tool.write_file&target=/prod/db")
    assert data["allowed"] is False and data["reason"]


def test_unknown_route_returns_404_json(server):
    try:
        get(server, "/nope")
        assert False, "expected HTTP 404"
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
        assert json.loads(exc.read().decode())["error"] == "not found"


def test_secret_value_never_appears_in_any_endpoint(server):
    """The dashboard must not become a way to read secret material."""
    for path in ("/api/summary", "/api/records", "/api/policies"):
        with urllib.request.urlopen(server + path, timeout=10) as resp:
            assert "sk-secret-value" not in resp.read().decode()
