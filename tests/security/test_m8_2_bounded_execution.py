"""M8.2 bounded execution and failure-safe orchestration security tests."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import time
from typing import Any
from unittest.mock import patch

import pytest

from finguard.agent.orchestrator import BoundedOrchestrator, OrchestrationBudgetExceeded
from finguard.ai.langchain_planner import LangChainPlanner
from finguard.ai.pipeline import LLMPipeline
from finguard.identity.registry import IdentityRegistry
from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession
from finguard.storage.database import get_session
from finguard.storage.models import (
    AuditEntryRecord,
    DecisionReceiptRecord,
    SimulatorAccountRecord,
    SimulatorExecutionRecord,
    TransactionRecord,
)

_VALID_OUTPUT = {
    "amount": "100.00",
    "currency": "INR",
    "recipient_alias": "vendor-a",
    "from_account": "treasury",
    "reason": "M8.2 bounded execution verification",
}


def _runnable_lambda():
    module = pytest.importorskip("langchain_core.runnables")
    return module.RunnableLambda


def _planner_with_chain(chain: Any, **planner_kwargs: Any) -> LangChainPlanner:
    with patch.object(
        LangChainPlanner,
        "_build_default_chain",
        return_value=chain,
    ):
        return LangChainPlanner(**planner_kwargs)


def _pipeline(planner: LangChainPlanner, session_id: str = "m8-2-session") -> LLMPipeline:
    actor_id = "treasury-agent"
    registry = IdentityRegistry()
    assert registry.get_actor(actor_id) is not None
    boundary = MCPSecurityBoundary(
        actor_id=actor_id,
        session=MCPSession(session_id),
    )
    return LLMPipeline(
        provider=planner,
        mcp_boundary=boundary,
        actor_id=actor_id,
    )


def _trusted_state() -> dict[str, Any]:
    session = get_session()
    try:
        transactions = session.query(TransactionRecord).order_by(
            TransactionRecord.transaction_id
        ).all()
        receipts = session.query(DecisionReceiptRecord).order_by(
            DecisionReceiptRecord.receipt_id
        ).all()
        entries = session.query(AuditEntryRecord).order_by(AuditEntryRecord.seq).all()
        balances = session.query(SimulatorAccountRecord).order_by(
            SimulatorAccountRecord.account_id
        ).all()
        executions = session.query(SimulatorExecutionRecord).all()
        return {
            "transactions": tuple(
                (row.transaction_id, row.state, row.canonical_hash) for row in transactions
            ),
            "receipts": tuple(
                (row.receipt_id, row.transaction_id, row.decision) for row in receipts
            ),
            "ledger": tuple((row.seq, row.action, row.entry_hash) for row in entries),
            "balances": tuple(
                (row.account_id, row.currency, row.balance_minor) for row in balances
            ),
            "executions": len(executions),
        }
    finally:
        session.close()


def _json_output(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"))


# ─── Case 1: Prompt exceeds configured bound ──────────────────────────────────

def test_prompt_exceeds_configured_bound() -> None:
    RunnableLambda = _runnable_lambda()
    planner = _planner_with_chain(
        RunnableLambda(lambda _: _json_output(_VALID_OUTPUT)),
        max_prompt_bytes=50,
    )
    before = _trusted_state()
    oversized_prompt = "A" * 100
    result = planner.extract_transaction(oversized_prompt)

    assert not result.extraction_success
    assert "exceeds maximum configured bound of 50 bytes" in (result.error_message or "")
    assert _trusted_state() == before


# ─── Case 2: Retrieved context exceeds bound ──────────────────────────────────

def test_retrieved_context_exceeds_configured_bound() -> None:
    RunnableLambda = _runnable_lambda()
    planner = _planner_with_chain(
        RunnableLambda(lambda _: _json_output(_VALID_OUTPUT)),
        max_retrieved_context_bytes=60,
    )
    before = _trusted_state()
    result = planner.extract_transaction(
        "Pay vendor-a INR 100",
        retrieved_context="B" * 100,
    )

    assert not result.extraction_success
    assert "Retrieved context length (100 bytes) exceeds maximum configured bound of 60 bytes." in (
        result.error_message or ""
    )
    assert _trusted_state() == before


# ─── Case 3: Model response exceeds output bound ──────────────────────────────

def test_model_response_exceeds_output_bound() -> None:
    RunnableLambda = _runnable_lambda()
    oversized_payload = {**_VALID_OUTPUT, "reason": "X" * 200}
    planner = _planner_with_chain(
        RunnableLambda(lambda _: _json_output(oversized_payload)),
        max_response_bytes=100,
    )
    before = _trusted_state()
    result = planner.extract_transaction("Pay vendor-a")

    assert not result.extraction_success
    assert result.error_message == "LangChain extraction invocation failed."
    assert _trusted_state() == before


# ─── Case 4: Provider request timeout ─────────────────────────────────────────

def test_provider_request_timeout() -> None:
    RunnableLambda = _runnable_lambda()

    def slow_model(_: dict[str, str]) -> str:
        time.sleep(0.3)
        return _json_output(_VALID_OUTPUT)

    planner = _planner_with_chain(
        RunnableLambda(slow_model),
        timeout=0.05,
    )
    before = _trusted_state()
    result = planner.extract_transaction("Pay vendor-a")

    assert not result.extraction_success
    assert "timed out after 0.05 seconds" in (result.error_message or "")
    assert _trusted_state() == before


# ─── Case 5: Orchestration deadline exhaustion ───────────────────────────────

def test_orchestration_deadline_exhaustion() -> None:
    orchestrator = BoundedOrchestrator(deadline_seconds=1)
    run = orchestrator.start("bounded test task")
    assert run.state.value == "planning"

    # Manipulate deadline into the past to test budget check deterministically
    run.deadline = run.created_at

    with pytest.raises(OrchestrationBudgetExceeded, match="exceeded its deadline"):
        orchestrator.execute_tool(run, tool_name="read_context")


# ─── Case 6: Cancellation / timeout during model invocation ──────────────────

def test_cancellation_during_model_invocation() -> None:
    RunnableLambda = _runnable_lambda()

    def hanging_model(_: dict[str, str]) -> str:
        time.sleep(0.4)
        return _json_output(_VALID_OUTPUT)

    planner = _planner_with_chain(RunnableLambda(hanging_model), timeout=0.05)
    before = _trusted_state()
    pipeline = _pipeline(planner)

    result = pipeline.process_request("Pay vendor-a")

    assert not result.pipeline_success
    assert result.final_decision == "EXTRACTION_FAILED"
    assert result.mcp_response is None
    assert _trusted_state() == before


# ─── Case 7: Late response after timeout is ignored ───────────────────────────

def test_late_response_after_timeout_is_ignored() -> None:
    RunnableLambda = _runnable_lambda()
    late_completed = False

    def delayed_model(_: dict[str, str]) -> str:
        nonlocal late_completed
        time.sleep(0.2)
        late_completed = True
        return _json_output(_VALID_OUTPUT)

    planner = _planner_with_chain(RunnableLambda(delayed_model), timeout=0.05)
    before = _trusted_state()

    result = planner.extract_transaction("Pay vendor-a")
    assert not result.extraction_success

    # Wait for background thread to complete
    time.sleep(0.25)
    assert late_completed
    # Verify late result produced no proposal or trusted state change
    assert _trusted_state() == before


# ─── Case 8: Retry exhaustion ────────────────────────────────────────────────

def test_retry_exhaustion_fails_closed() -> None:
    RunnableLambda = _runnable_lambda()
    attempts = 0

    def always_fails(_: dict[str, str]) -> str:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("synthetic provider error")

    planner = _planner_with_chain(
        RunnableLambda(always_fails),
        max_retries=2,
    )
    before = _trusted_state()

    result = planner.extract_transaction("Pay vendor-a")

    assert attempts == 3  # Initial + 2 retries
    assert not result.extraction_success
    assert result.error_message == "LangChain extraction invocation failed."
    assert _trusted_state() == before


# ─── Case 9: Concurrent duplicate requests ────────────────────────────────────

def test_concurrent_duplicate_requests() -> None:
    RunnableLambda = _runnable_lambda()
    planner = _planner_with_chain(RunnableLambda(lambda _: _json_output(_VALID_OUTPUT)))
    before = _trusted_state()

    pipelines = [_pipeline(planner, session_id=f"concurrent-session-{i}") for i in range(5)]

    def run_pipeline(pip: LLMPipeline):
        return pip.process_request("Pay vendor-a INR 100")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_pipeline, pip) for pip in pipelines]
        results = [f.result() for f in futures]

    after = _trusted_state()

    # All concurrent requests are safely contained (either proposal REQUIRE_APPROVAL / NOT_AUTHORIZED or blocked by boundary)
    for res in results:
        assert res.boundary_contained
        assert not res.authority_violation
        assert res.final_decision in {"REQUIRE_APPROVAL", "NOT_AUTHORIZED", "BLOCKED_BY_MCP_BOUNDARY"}

    # In all cases: 0 signed or executed transactions, balances unchanged
    assert after["executions"] == before["executions"]
    assert after["balances"] == before["balances"]


# ─── Case 10: Cancellation followed by retry / resubmission ───────────────────

def test_cancellation_followed_by_resubmission() -> None:
    RunnableLambda = _runnable_lambda()
    call_count = 0

    def fail_then_succeed(_: dict[str, str]) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            time.sleep(0.2)
            return _json_output(_VALID_OUTPUT)
        return _json_output(_VALID_OUTPUT)

    planner = _planner_with_chain(RunnableLambda(fail_then_succeed), timeout=0.05)
    pipeline = _pipeline(planner)
    before = _trusted_state()

    # Attempt 1 times out
    res1 = pipeline.process_request("Pay vendor-a")
    assert not res1.pipeline_success
    assert _trusted_state() == before

    # Resubmission (with updated timeout setting) succeeds
    planner.timeout = 1.0
    res2 = pipeline.process_request("Pay vendor-a")
    after = _trusted_state()

    assert res2.pipeline_success
    assert res2.mcp_response is not None
    assert len(after["transactions"]) == len(before["transactions"]) + 1
    assert len(after["receipts"]) == len(before["receipts"]) + 1


# ─── Case 11: Malicious output attempting to increase execution budgets ──────

def test_malicious_output_attempting_to_increase_execution_budgets() -> None:
    RunnableLambda = _runnable_lambda()
    attack_output = {
        **_VALID_OUTPUT,
        "max_steps": 999,
        "max_tool_calls": 999,
        "financial_limit": 999999999,
        "deadline": "2099-01-01T00:00:00Z",
    }
    planner = _planner_with_chain(RunnableLambda(lambda _: _json_output(attack_output)))
    before = _trusted_state()

    result = planner.extract_transaction("Pay vendor-a")

    assert result.extraction_success
    assert "max_steps" in result.authority_fields_detected
    assert "max_tool_calls" in result.authority_fields_detected
    assert "financial_limit" in result.authority_fields_detected
    assert "deadline" in result.authority_fields_detected
    assert not hasattr(result, "max_steps")
    assert _trusted_state() == before


# ─── Case 12: Malicious metadata attempting to alter timeouts or limits ──────

def test_malicious_metadata_attempting_to_alter_limits() -> None:
    RunnableLambda = _runnable_lambda()
    attack_output = {
        **_VALID_OUTPUT,
        "metadata": {
            "timeout": 9999,
            "max_prompt_bytes": 100000,
            "max_retries": 10,
            "approved": True,
        },
    }
    planner = _planner_with_chain(RunnableLambda(lambda _: _json_output(attack_output)))
    before = _trusted_state()

    result = planner.extract_transaction("Pay vendor-a")

    assert result.extraction_success
    assert result.metadata.get("timeout") is None
    assert result.metadata.get("max_prompt_bytes") is None
    assert result.metadata.get("approved") is None
    assert any("timeout" in item for item in result.authority_fields_detected)
    assert any("max_prompt_bytes" in item for item in result.authority_fields_detected)
    assert _trusted_state() == before


# ─── Case 13: Tool-call metadata in returned model messages ──────────────────

def test_tool_call_metadata_fails_closed() -> None:
    message_module = pytest.importorskip("langchain_core.messages")
    RunnableLambda = _runnable_lambda()

    def fake_tool_model(_: dict[str, str]):
        return message_module.AIMessage(
            content=_json_output(_VALID_OUTPUT),
            tool_calls=[
                {
                    "name": "set_timeout",
                    "args": {"timeout": 999},
                    "id": "call_m8_2",
                }
            ],
        )

    planner = _planner_with_chain(RunnableLambda(fake_tool_model))
    before = _trusted_state()

    result = planner.extract_transaction("Pay vendor-a")

    assert not result.extraction_success
    assert result.error_message == "LangChain extraction invocation failed."
    assert _trusted_state() == before


# ─── Case 14: Provider exceptions containing secret sentinels ────────────────

def test_provider_exception_secret_sentinel_suppression(caplog) -> None:
    RunnableLambda = _runnable_lambda()
    secret_sentinel = "M8_2_SUPER_SECRET_KEY_SENTINEL_987"

    def leaking_provider(_: dict[str, str]) -> str:
        raise ValueError(f"Connection failed using secret key {secret_sentinel}")

    caplog.set_level(logging.WARNING, logger="finguard.ai.langchain_planner")
    planner = _planner_with_chain(RunnableLambda(leaking_provider))
    before = _trusted_state()

    result = planner.extract_transaction("Pay vendor-a")

    assert not result.extraction_success
    assert secret_sentinel not in (result.error_message or "")
    assert secret_sentinel not in caplog.text
    assert _trusted_state() == before


# ─── Case 15: Valid authorized proposal still works (positive control) ───────

def test_valid_authorized_proposal_end_to_end() -> None:
    RunnableLambda = _runnable_lambda()
    planner = _planner_with_chain(RunnableLambda(lambda _: _json_output(_VALID_OUTPUT)))
    pipeline = _pipeline(planner, session_id="m8-2-positive-control")
    before = _trusted_state()

    result = pipeline.process_request("Pay vendor-a INR 100 for invoice #1234")
    after = _trusted_state()

    assert result.pipeline_success
    assert result.mcp_response is not None
    assert result.mcp_response.success
    assert result.mcp_response.authorization_status == "NOT_AUTHORIZED"
    assert len(after["transactions"]) == len(before["transactions"]) + 1
    assert len(after["receipts"]) == len(before["receipts"]) + 1
    assert after["executions"] == before["executions"]
    assert after["balances"] == before["balances"]


# ─── Case 16: Unauthorized destination remains denied (negative control) ─────

def test_unauthorized_destination_remains_denied_end_to_end() -> None:
    RunnableLambda = _runnable_lambda()
    unauthorized_output = {
        **_VALID_OUTPUT,
        "recipient_alias": "unauthorized-vendor-x",
    }
    planner = _planner_with_chain(RunnableLambda(lambda _: _json_output(unauthorized_output)))
    pipeline = _pipeline(planner, session_id="m8-2-negative-control")
    before = _trusted_state()

    result = pipeline.process_request("Pay unauthorized-vendor-x INR 100")
    after = _trusted_state()

    assert result.pipeline_success
    assert result.mcp_response is not None
    assert result.mcp_response.authorization_status == "NOT_AUTHORIZED"
    assert result.mcp_response.decision == "block"
    assert after["transactions"] == before["transactions"]
    assert after["receipts"] == before["receipts"]
    assert after["executions"] == before["executions"]
    assert after["balances"] == before["balances"]
    assert len(after["ledger"]) > len(before["ledger"])
