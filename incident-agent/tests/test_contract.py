import json
import os
import tempfile
import uuid
import sys
from pathlib import Path

# Keep test state outside the repository.
os.environ["DB_PATH"] = str(Path(tempfile.mkdtemp(prefix="incident-agent-tests-")) / "state.sqlite3")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
import main

client = TestClient(main.app)


def _tool(name, properties, required):
    return {
        "name": name,
        "description": name,
        "inputSchema": {
            "type": "object", "properties": properties, "required": required,
            "additionalProperties": False,
        },
    }


CATALOG = [
    _tool("query_metrics", {"service": {"type": "string"}, "metric": {"type": "string"}, "window_minutes": {"type": "integer", "minimum": 1}}, ["service", "metric", "window_minutes"]),
    _tool("query_logs", {"service": {"type": "string"}, "query": {"type": "string"}, "lookback_minutes": {"type": "integer", "minimum": 1}}, ["service", "query", "lookback_minutes"]),
    _tool("scale_service", {"service": {"type": "string"}, "replicas": {"type": "integer", "minimum": 1}}, ["service", "replicas"]),
    _tool("page_owner", {"service": {"type": "string"}, "severity": {"type": "string"}, "reason": {"type": "string"}}, ["service", "severity", "reason"]),
    _tool("rollback_deployment", {"service": {"type": "string"}, "deployment_id": {"type": "string"}}, ["service", "deployment_id"]),
]


def _body(run_id, transcript=None, effect_tools=None, approvals=None):
    if transcript is None:
        transcript = "[ev_000001] CPU is high.\n[ev_000002] Error rate is high.\n[ev_000003] Logs show errors."
    if effect_tools is None:
        effect_tools = ["scale_service", "page_owner", "rollback_deployment"]
    if approvals is None:
        approvals = ["rollback_deployment", "disable_feature"]
    return {
        "profile": "ga5-incident-agent/v2", "runId": run_id,
        "agentName": "incident-response", "publicMarker": "marker-" + run_id,
        "sensitive": {"accessToken": "top-secret", "privateNote": "private"},
        "incident": {
            "incidentId": "INC-12345", "title": "Checkout issue", "service": "checkout", "severity": "SEV-1",
            "transcript": transcript,
            "allowedRootCauses": ["database connection pool exhaustion", "bad deployment", "capacity limit reached"],
        },
        "toolCatalog": CATALOG,
        "policy": {"maximumDiagnostics": 3, "effectTools": effect_tools,
                   "approvalRequiredFor": approvals, "doNotExport": ["accessToken", "privateNote"]},
    }


def _plan(_data, effect, arguments):
    return ({
        "rootCause": "database connection pool exhaustion",
        "evidence": ["ev_000001", "ev_000002"],
        "diagnostics": [
            {"toolName": "query_metrics", "arguments": {"service": "checkout", "metric": "error_rate", "window_minutes": 10}, "evidence": ["ev_000001"]},
            {"toolName": "query_logs", "arguments": {"service": "checkout", "query": "connection pool", "lookback_minutes": 15}, "evidence": ["ev_000002"]},
        ],
        "effectTool": effect, "effectArguments": arguments,
    }, "google", "gemini-3.8-flash")


def _outcome(dispatch, status=200, error_type=None):
    item = {
        "actionId": dispatch["actionId"], "callId": dispatch["callId"], "attempt": dispatch["attempt"],
        "status": status,
        "resultClass": "diagnosis_confirmed" if dispatch["phase"] == "diagnostic" else "effect_applied",
        "nonce": str(uuid.uuid4()),
    }
    if error_type:
        item["errorType"] = error_type
    return item


def _spans(final):
    return final["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]


def test_replay_conflicts_and_final_trace(monkeypatch):
    body = _body("test-success-0001")
    monkeypatch.setattr(main, "call_planner", lambda data: _plan(data, "scale_service", {"service": "checkout", "replicas": 4}))
    initial = client.post("/v2/incidents", json=body).json()
    receipt_one = {"receiptId": "receipt-success-01", "outcomes": [_outcome(d) for d in initial["dispatches"]]}
    effect = client.post("/v2/incidents/test-success-0001/receipts", json=receipt_one).json()["dispatches"][0]
    receipt_two = {"receiptId": "receipt-success-02", "outcomes": [_outcome(effect)]}
    final = client.post("/v2/incidents/test-success-0001/receipts", json=receipt_two).json()
    assert final["status"] == "completed"
    assert client.post("/v2/incidents", json=body).json() == initial
    assert client.get("/v2/incidents/test-success-0001").json()["status"] == "completed"
    assert client.post("/v2/incidents/test-success-0001/receipts", json=receipt_two).json() == final
    assert client.post("/v2/incidents", json={**body, "publicMarker": "changed"}).status_code == 409
    assert client.post("/v2/incidents/test-success-0001/receipts", json={"receiptId": "receipt-success-02", "outcomes": [{**receipt_two["outcomes"][0], "status": 500}]}).status_code == 409
    spans = _spans(final)
    assert len({span["spanId"] for span in spans}) == len(spans)
    assert sum(span["name"] == "chat incident-plan" for span in spans) == 1
    assert sum(span["name"] == "incident.join" for span in spans) == 1
    assert not any("top-secret" in json.dumps(span) or "private" in json.dumps(span) for span in spans)


def test_503_gets_one_retry_and_matching_telemetry(monkeypatch):
    body = _body("test-retry-0001")
    monkeypatch.setattr(main, "call_planner", lambda data: _plan(data, "scale_service", {"service": "checkout", "replicas": 4}))
    initial = client.post("/v2/incidents", json=body).json()
    first = initial["dispatches"][0]
    retry_receipt = {"receiptId": "receipt-retry-01", "outcomes": [_outcome(first, 503)]}
    response = client.post("/v2/incidents/test-retry-0001/receipts", json=retry_receipt).json()
    retry = response["dispatches"][0]
    assert retry["attempt"] == 2 and retry["actionId"] == first["actionId"] and retry["callId"] == first["callId"]
    assert retry["traceparent"].split("-")[2] != first["traceparent"].split("-")[2]
    finish = {"receiptId": "receipt-retry-02", "outcomes": [_outcome(x) for x in initial["dispatches"][1:]] + [_outcome(retry)]}
    effect = client.post("/v2/incidents/test-retry-0001/receipts", json=finish).json()["dispatches"][0]
    final = client.post("/v2/incidents/test-retry-0001/receipts", json={"receiptId": "receipt-retry-03", "outcomes": [_outcome(effect)]}).json()
    assert final["status"] == "completed"
    client_spans = [s for s in _spans(final) if s["name"] == "POST tool/" + first["toolName"]]
    assert any(any(a["key"] == "error.type" and a["value"]["stringValue"] == "503" for a in s["attributes"]) and s["status"]["code"] == 2 for s in client_spans)
    assert any(any(a["key"] == "http.request.resend_count" and a["value"]["intValue"] == "1" for a in s["attributes"]) for s in client_spans)


def test_timeout_suppresses_effect_and_finishes_other_diagnostic(monkeypatch):
    body = _body("test-timeout-0001")
    monkeypatch.setattr(main, "call_planner", lambda data: _plan(data, "scale_service", {"service": "checkout", "replicas": 4}))
    initial = client.post("/v2/incidents", json=body).json()
    first, second = initial["dispatches"]
    response = client.post("/v2/incidents/test-timeout-0001/receipts", json={"receiptId": "receipt-timeout-01", "outcomes": [_outcome(first, 0, "timeout")]}).json()
    assert response["status"] == "waiting" and all(x["phase"] != "effect" for x in response["actionLog"])
    final = client.post("/v2/incidents/test-timeout-0001/receipts", json={"receiptId": "receipt-timeout-02", "outcomes": [_outcome(second)]}).json()
    assert final["status"] == "failed" and final["chosenEffect"] is None and "scale_service" in final["suppressed"]
    assert all(x["phase"] != "effect" for x in final["actionLog"])
    timeout_span = next(s for s in _spans(final) if s["name"] == "POST tool/" + first["toolName"])
    assert timeout_span["status"]["code"] == 2
    assert any(a["key"] == "error.type" and a["value"]["stringValue"] == "timeout" for a in timeout_span["attributes"])


def test_scaling_limit_pages_owner_instead_of_scaling(monkeypatch):
    transcript = "[ev_000001] Autoscaler reports service already at its permitted scaling limit.\n[ev_000002] Queue depth is increasing."
    body = _body("test-limit-0001", transcript, ["scale_service", "page_owner"], [])
    monkeypatch.setattr(main, "call_planner", lambda data: _plan(data, "scale_service", {"service": "checkout", "replicas": 16}))
    initial = client.post("/v2/incidents", json=body).json()
    receipt = {"receiptId": "receipt-limit-01", "outcomes": [_outcome(d) for d in initial["dispatches"]]}
    page = client.post("/v2/incidents/test-limit-0001/receipts", json=receipt).json()["dispatches"][0]
    assert page["toolName"] == "page_owner"
    final = client.post("/v2/incidents/test-limit-0001/receipts", json={"receiptId": "receipt-limit-02", "outcomes": [_outcome(page)]}).json()
    assert final["chosenEffect"] == "page_owner" and "scale_service" in final["suppressed"]


def test_destructive_effect_requires_approval_and_is_correlated(monkeypatch):
    body = _body("test-approval-0001")
    monkeypatch.setattr(main, "call_planner", lambda data: _plan(data, "rollback_deployment", {"service": "checkout", "deployment_id": "deployment-x"}))
    initial = client.post("/v2/incidents", json=body).json()
    approval_response = client.post("/v2/incidents/test-approval-0001/receipts", json={
        "receiptId": "receipt-approval-01", "outcomes": [_outcome(d) for d in initial["dispatches"]],
    }).json()
    assert not approval_response["dispatches"] and len(approval_response["approvals"]) == 1
    approval = approval_response["approvals"][0]
    nonce = str(uuid.uuid4())
    effect = client.post("/v2/incidents/test-approval-0001/receipts", json={
        "receiptId": "receipt-approval-02", "approvals": [{"approvalId": approval["approvalId"], "decision": "approved", "nonce": nonce}],
    }).json()["dispatches"][0]
    assert effect["approvalId"] == approval["approvalId"] and effect["approvalNonce"] == nonce
    final = client.post("/v2/incidents/test-approval-0001/receipts", json={
        "receiptId": "receipt-approval-03", "outcomes": [_outcome(effect)],
    }).json()
    gate = next(s for s in _spans(final) if s["name"] == "approval_gate")
    assert any(a["key"] == "ga5.approval.nonce" and a["value"]["stringValue"] == nonce for a in gate["attributes"])
    assert "top-secret" not in json.dumps(final)
