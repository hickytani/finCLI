import pytest

from finguard.agent import BoundedOrchestrator
from finguard.agent.orchestrator import OrchestrationBudgetExceeded, OrchestrationPlan
from finguard.core.enums import OrchestrationState


def test_bounded_orchestrator_starts_with_plan_and_tracks_budget():
    orchestrator = BoundedOrchestrator(max_steps=5, max_tool_calls=2, deadline_seconds=30)
    run = orchestrator.start("check the payment flow")

    assert run.state == OrchestrationState.PLANNING
    assert run.steps_used == 1
    assert run.plan is not None
    assert run.plan.version == "v1"

    run = orchestrator.execute_tool(
        run,
        tool_name="read_context",
        arguments={"question": "what is the task?"},
        capability="transaction.propose",
    )

    assert run.state == OrchestrationState.OBSERVATION
    assert run.tool_calls_used == 1
    assert run.steps_used == 2

    run = orchestrator.guardrail_check(run, capability="transaction.propose", financial_amount=10)
    assert run.state == OrchestrationState.EXECUTION_BOUNDARY

    run = orchestrator.complete(run)
    assert run.state == OrchestrationState.COMPLETED


def test_replan_keeps_budgets_and_denies_reset():
    orchestrator = BoundedOrchestrator(max_steps=3, max_tool_calls=1)
    run = orchestrator.start("pay vendor")

    run = orchestrator.execute_tool(run, tool_name="read_context", capability="transaction.propose")
    run = orchestrator.replan(run, reason="Need to narrow the plan")

    assert run.state == OrchestrationState.PLANNING
    assert run.steps_used >= 2
    assert run.tool_calls_used == 1

    with pytest.raises(ValueError):
        orchestrator.replan(
            run,
            new_plan=OrchestrationPlan(
                plan_id=run.plan.plan_id,
                version=run.plan.version,
                task=run.plan.task,
                steps=run.plan.steps,
                capabilities=("transaction.admin",),
                financial_limit=run.plan.financial_limit,
                created_at=run.plan.created_at,
            ),
            reason="Attempt to self-grant capability",
        )


def test_budget_exceeded_rejects_without_resetting_state():
    orchestrator = BoundedOrchestrator(max_steps=2, max_tool_calls=1)
    run = orchestrator.start("pay vendor")

    run = orchestrator.execute_tool(run, tool_name="read_context", capability="transaction.propose")
    with pytest.raises(OrchestrationBudgetExceeded):
        orchestrator.execute_tool(run, tool_name="read_context", capability="transaction.propose")


def test_approval_required_is_not_authorization():
    orchestrator = BoundedOrchestrator(max_steps=3, max_tool_calls=2, financial_limit=100)
    run = orchestrator.start("pay vendor")
    run = orchestrator.execute_tool(run, tool_name="read_context", capability="transaction.propose")
    run = orchestrator.guardrail_check(run, capability="transaction.propose", financial_amount=200)

    assert run.state == OrchestrationState.APPROVAL_REQUIRED
    assert run.decision == "APPROVAL_REQUIRED"
