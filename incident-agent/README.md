# Public HTTPS Incident Agent (ga5-incident-agent/v2)

A FastAPI service implementing the incident run, receipt, approval, replay/conflict, persistent state, and OTLP trace contract.

## Deploy (Render)

1. Push this folder to a new public GitHub repository.
2. In Render, select **New → Blueprint**, connect the repository, and deploy `render.yaml`.
3. Add a Gemini API key as the `GEMINI_API_KEY` secret in the Render service environment. The default model is `gemini-3.8-flash`; alternatively configure `OPENAI_API_KEY`, `OPENAI_MODEL`, and optionally `OPENAI_BASE_URL`.
4. Wait for `/healthz` to return `{"status":"ok","profile":"ga5-incident-agent/v2"}` over HTTPS.
5. Submit only the resulting public HTTPS service origin, e.g. `https://<your-render-service>.onrender.com` (without path, query, fragment, or credentials). Do not submit this placeholder.

A persistent disk is configured for SQLite so state survives process restarts. The Render `starter` plan is used because persistent disks are not available on the free web-service plan. Change the platform or persistence adapter if you have a different budget/host.

## Local run

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
export GEMINI_API_KEY='...' # PowerShell: $env:GEMINI_API_KEY='...'
uvicorn main:app --host 0.0.0.0 --port 8000
```

Check `GET /healthz`. Use `/v2/incidents` to create a run, `/v2/incidents/{runId}/receipts` to submit an action outcome or approval receipt, and `GET /v2/incidents/{runId}` to read current stored state.

For deterministic local smoke tests only, set `PLANNER_BACKEND=heuristic`; this is not suitable for grader scoring. Production runs require a real planner API key.

## Safety and implementation notes

- The `sensitive` object is excluded from the model prompt and never included in responses or telemetry. Only a request content hash is persisted for idempotency/conflict detection.
- First-seen run planning is serialized; receipt replay reads the stored response and never calls the model or repeats actions.
- Tool dispatches are catalog/schema-validated. Effects are selected only from `policy.effectTools`. `rollback_deployment` and `disable_feature` are always approval-gated. A detected scaling-limit incident forces a schema-valid owner-page/notification tool instead of a scale tool.
- State and receipts are stored in SQLite. Receipt IDs and run IDs reject changed-content conflicts.
- OTLP spans redact transcripts, prompts, tool arguments/results and credentials. Final trace includes logical tool spans, physical-attempt client spans, retry counts, receipt correlation, diagnostic join links, and approval-gate metadata.

## Important limitation

The grading incident catalog and transcripts are supplied at runtime. The planner therefore must be configured with an API key and a model that can handle the transcript context within the request deadline. Test in your deployment before spending the final Check/Save allowance.

## Run the contract tests

```bash
pip install -r requirements-dev.txt
pytest -q
```
