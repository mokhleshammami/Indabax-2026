"""SENTINEL v1 defense HTTP service.

    uv run uvicorn aegis.service.main:app --port 8080

Then, from the simulator repository::

    uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
        --defense-url http://127.0.0.1:8080

Environment:
    AEGIS_ABLATION   component to disable for an ablation run (default "none")
    AEGIS_TRACE_DIR  where trace JSONL lands (default "traces")
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from aegis.defense import AegisDefense
from aegis.types import DefenseDecision, DefenseRequest

app = FastAPI(title="AEGIS defense", docs_url=None, redoc_url=None, openapi_url=None)

_defense = AegisDefense(ablation=os.environ.get("AEGIS_ABLATION", "none"))


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "defense": _defense.name, "ablation": _defense.ablation}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    return _defense.decide(request)
