"""Bounded M4 orchestration for untrusted agent work.

The orchestrator is a coordinator only. It enforces explicit capabilities,
step/tool budgets, deterministic plans, and guardrail checks before the
existing trusted financial path is reached. It never becomes a signer,
approver, policy engine, or execution authority.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar

from finguard.core.enums import OrchestrationState
from finguard.core.errors import SecurityError, ValidationError


class InvalidTransitionError(ValueError):
    """Raised when an orchestrator state transition violates the M4 graph."""


class OrchestrationBudgetExceeded(SecurityError):
    """Raised when the run exceeds its configured orchestration budget."""


@dataclass(frozen=True)
class OrchestrationTool:
    """Minimal tool description for a bounded agent action."""

    name: str
    description: str
    capability: str
    resource: str
    function: Callable[..., Any] | None = None


@dataclass(frozen=True)
class PlanStep:
    """One deterministic step in the trusted orchestration plan."""

    index: int
    description: str
    tool_name: str | None = None
    requires_approval: bool = False
    resource: str | None = None


@dataclass(frozen=True)
class OrchestrationPlan:
    """A versioned plan with a fixed step list and budget metadata."""

    plan_id: str = field(default_factory=lambda: f"PLAN-{uuid.uuid4().hex[:12].upper()}")
    version: str = "v1"
    task: str = ""
    steps: tuple[PlanStep, ...] = ()
    capabilities: tuple[str, ...] = ()
    financial_limit: int | None = None
    created_at: _dt.datetime = field(default_factory=lambda: _dt.datetime.now(_dt.UTC))


@dataclass
class OrchestrationRun:
    """Mutable execution state for a single bounded orchestration run."""

    run_id: str
    task: str
    state: OrchestrationState = OrchestrationState.REQUESTED
    allowed_capabilities: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    plan: OrchestrationPlan | None = None
    steps_used: int = 0
    tool_calls_used: int = 0
    created_at: _dt.datetime = field(default_factory=lambda: _dt.datetime.now(_dt.UTC))
    deadline: _dt.datetime | None = None
    max_steps: int = 5
    max_tool_calls: int = 3
    financial_limit: int | None = None
    last_reason: str | None = None
    observations: list[dict[str, Any]] = field(default_factory=list)
    tool_history: list[str] = field(default_factory=list)
    decision: str | None = None

    @property
    def is_terminal(self) -> bool:
        return self.state in {
            OrchestrationState.COMPLETED,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        }


class DeterministicPlanner:
    """Deterministic, non-LLM planner used to bind an execution plan."""

    def plan(
        self,
        task: str,
        *,
        allowed_capabilities: Sequence[str] | None = None,
        financial_limit: int | None = None,
    ) -> OrchestrationPlan:
        if not task or not task.strip():
            raise ValidationError("Task cannot be empty")
        steps = (
            PlanStep(1, "Inspect task context and determine the bounded action", tool_name="read_context"),
            PlanStep(2, "Check that the requested capability remains within the trusted policy", tool_name=None),
            PlanStep(3, "Submit the proposed action through the existing financial boundary", tool_name="submit_intent", requires_approval=False),
        )
        caps = tuple(allowed_capabilities or ("transaction.propose",))
        return OrchestrationPlan(
            task=task.strip(),
            steps=steps,
            capabilities=caps,
            financial_limit=financial_limit,
        )


class BoundedOrchestrator:
    """Bounded M4 coordinator. It tracks budget, state, and tool use.

    It never becomes an authority, approval service, signer, or executor. It only
    directs an untrusted agent through a deterministic run with explicit limits.
    """

    _ALLOWED_TRANSITIONS: ClassVar[dict[OrchestrationState, set[OrchestrationState]]] = {
        OrchestrationState.REQUESTED: {OrchestrationState.PLANNING},
        OrchestrationState.PLANNING: {
            OrchestrationState.TOOL_CALL,
            OrchestrationState.REPLAN,
            OrchestrationState.APPROVAL_REQUIRED,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        },
        OrchestrationState.TOOL_CALL: {
            OrchestrationState.OBSERVATION,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        },
        OrchestrationState.OBSERVATION: {
            OrchestrationState.GUARDRAIL_CHECK,
            OrchestrationState.REPLAN,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        },
        OrchestrationState.GUARDRAIL_CHECK: {
            OrchestrationState.APPROVAL_REQUIRED,
            OrchestrationState.EXECUTION_BOUNDARY,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        },
        OrchestrationState.REPLAN: {
            OrchestrationState.PLANNING,
            OrchestrationState.TOOL_CALL,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        },
        OrchestrationState.APPROVAL_REQUIRED: {
            OrchestrationState.EXECUTION_BOUNDARY,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        },
        OrchestrationState.EXECUTION_BOUNDARY: {
            OrchestrationState.COMPLETED,
            OrchestrationState.REJECTED,
            OrchestrationState.FAILED,
            OrchestrationState.CANCELLED,
        },
        OrchestrationState.COMPLETED: set(),
        OrchestrationState.REJECTED: set(),
        OrchestrationState.FAILED: set(),
        OrchestrationState.CANCELLED: set(),
    }

    def __init__(
        self,
        *,
        max_steps: int = 5,
        max_tool_calls: int = 3,
        deadline_seconds: int = 300,
        allowed_capabilities: Sequence[str] | None = None,
        allowed_tools: Sequence[str] | None = None,
        planner: DeterministicPlanner | None = None,
        financial_limit: int | None = None,
    ) -> None:
        if max_steps <= 0:
            raise ValueError("max_steps must be positive")
        if max_tool_calls <= 0:
            raise ValueError("max_tool_calls must be positive")
        if deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")
        self.max_steps = int(max_steps)
        self.max_tool_calls = int(max_tool_calls)
        self.deadline_seconds = int(deadline_seconds)
        self.allowed_capabilities = tuple(allowed_capabilities or ("transaction.propose",))
        self.allowed_tools = tuple(allowed_tools or ("read_context", "submit_intent"))
        self.planner = planner or DeterministicPlanner()
        self.financial_limit = financial_limit

    def _snapshot_run(self, run: OrchestrationRun) -> OrchestrationRun:
        return replace(run)

    def start(
        self,
        task: str,
        *,
        capabilities: Sequence[str] | None = None,
        financial_limit: int | None = None,
        deadline: _dt.datetime | None = None,
    ) -> OrchestrationRun:
        if not task or not task.strip():
            raise ValidationError("Task cannot be empty")
        run = OrchestrationRun(
            run_id=f"RUN-{uuid.uuid4().hex[:12].upper()}",
            task=task.strip(),
            allowed_capabilities=tuple(capabilities or self.allowed_capabilities),
            allowed_tools=self.allowed_tools,
            max_steps=self.max_steps,
            max_tool_calls=self.max_tool_calls,
            financial_limit=financial_limit if financial_limit is not None else self.financial_limit,
            deadline=deadline or _dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=self.deadline_seconds),
        )
        return self.plan(run)

    def plan(
        self,
        run: OrchestrationRun,
        *,
        plan: OrchestrationPlan | None = None,
    ) -> OrchestrationRun:
        self._ensure_not_terminal(run)
        self._check_budget(run, "planning")
        if plan is None:
            plan = self.planner.plan(
                run.task,
                allowed_capabilities=run.allowed_capabilities,
                financial_limit=run.financial_limit,
            )
        if not plan.steps:
            raise ValidationError("Plan must contain at least one step")
        run.plan = plan
        run.state = OrchestrationState.PLANNING
        run.steps_used += 1
        return self._transition(run, OrchestrationState.PLANNING)

    def execute_tool(
        self,
        run: OrchestrationRun,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        capability: str | None = None,
        resource: str | None = None,
        tool: OrchestrationTool | None = None,
    ) -> OrchestrationRun:
        self._ensure_not_terminal(run)
        self._check_budget(run, "tool execution")
        if tool_name not in run.allowed_tools:
            return self.reject(run, f"Tool '{tool_name}' is not in the bounded allowlist")
        if capability and capability not in run.allowed_capabilities:
            return self.reject(run, f"Capability '{capability}' is not permitted for this run")

        run.state = OrchestrationState.TOOL_CALL
        run.tool_calls_used += 1
        run.steps_used += 1
        run.tool_history.append(tool_name)
        record = {"tool": tool_name, "arguments": arguments or {}, "resource": resource, "capability": capability}
        run.observations.append({"stage": OrchestrationState.TOOL_CALL.value, **record})
        result = None
        if tool is not None and tool.function is not None:
            try:
                result = tool.function(**(arguments or {}))
            except (AttributeError, KeyError, RuntimeError, TypeError, ValueError) as exc:
                return self.fail(run, f"Tool execution failed: {exc}")
        else:
            result = {"status": "ok", "tool": tool_name, "arguments": arguments or {}}
        run.observations.append({"stage": OrchestrationState.OBSERVATION.value, "tool": tool_name, "result": result})
        run.state = OrchestrationState.OBSERVATION
        return run

    def replan(
        self,
        run: OrchestrationRun,
        *,
        new_plan: OrchestrationPlan | None = None,
        reason: str | None = None,
    ) -> OrchestrationRun:
        self._ensure_not_terminal(run)
        if run.state not in {OrchestrationState.OBSERVATION, OrchestrationState.GUARDRAIL_CHECK, OrchestrationState.REPLAN}:
            raise InvalidTransitionError(
                f"Cannot replan while in state {run.state.value}; only observation or guardrail states are allowed."
            )
        if new_plan is not None:
            if tuple(new_plan.capabilities) != run.allowed_capabilities:
                raise InvalidTransitionError("Replan cannot change the original run's allowed capabilities")
            if new_plan.financial_limit is not None and run.financial_limit is not None and new_plan.financial_limit != run.financial_limit:
                raise InvalidTransitionError("Replan cannot reset or broaden the original financial limit")
            if run.financial_limit is None and new_plan.financial_limit is not None:
                raise InvalidTransitionError("Replan cannot introduce a new financial limit")
        self._check_budget(run, "replan")
        if reason:
            run.last_reason = reason
        run.steps_used += 1
        run.state = OrchestrationState.REPLAN
        return self._transition(run, OrchestrationState.PLANNING)

    def guardrail_check(
        self,
        run: OrchestrationRun,
        *,
        capability: str | None = None,
        resource: str | None = None,
        action: str | None = None,
        financial_amount: int | None = None,
    ) -> OrchestrationRun:
        self._ensure_not_terminal(run)
        self._check_budget(run, "guardrail check")
        if capability and capability not in run.allowed_capabilities:
            return self.reject(run, f"Capability '{capability}' is not allowed in this run")
        if action in {"approve_transaction", "sign_transaction", "execute_transaction"}:
            return self.reject(run, "Privileged financial actions are not available to the orchestrator")
        if financial_amount is not None and run.financial_limit is not None and financial_amount > run.financial_limit:
            return self.require_approval(run, "Financial amount exceeds the configured run budget")
        run.state = OrchestrationState.GUARDRAIL_CHECK
        run.observations.append({
            "stage": OrchestrationState.GUARDRAIL_CHECK.value,
            "capability": capability,
            "resource": resource,
            "action": action,
            "financial_amount": financial_amount,
        })
        return self._transition(run, OrchestrationState.EXECUTION_BOUNDARY)

    def require_approval(
        self,
        run: OrchestrationRun,
        reason: str,
    ) -> OrchestrationRun:
        self._ensure_not_terminal(run)
        run.last_reason = reason
        run.decision = "APPROVAL_REQUIRED"
        run.state = OrchestrationState.APPROVAL_REQUIRED
        return run

    def complete(self, run: OrchestrationRun, *, decision: str = "COMPLETED") -> OrchestrationRun:
        self._ensure_not_terminal(run)
        self._check_budget(run, "completion")
        run.decision = decision
        run.state = OrchestrationState.EXECUTION_BOUNDARY
        return self._transition(run, OrchestrationState.COMPLETED)

    def reject(self, run: OrchestrationRun, reason: str) -> OrchestrationRun:
        run.last_reason = reason
        run.decision = "REJECTED"
        run.state = OrchestrationState.REJECTED
        return run

    def fail(self, run: OrchestrationRun, reason: str) -> OrchestrationRun:
        run.last_reason = reason
        run.decision = "FAILED"
        run.state = OrchestrationState.FAILED
        return run

    def cancel(self, run: OrchestrationRun, reason: str) -> OrchestrationRun:
        run.last_reason = reason
        run.decision = "CANCELLED"
        run.state = OrchestrationState.CANCELLED
        return run

    def _transition(self, run: OrchestrationRun, target: OrchestrationState) -> OrchestrationRun:
        current = run.state
        if current == target:
            return run
        if current not in self._ALLOWED_TRANSITIONS:
            raise InvalidTransitionError(f"Unknown state: {current.value}")
        allowed = self._ALLOWED_TRANSITIONS[current]
        if target not in allowed:
            raise InvalidTransitionError(
                f"Invalid orchestrator transition from {current.value} to {target.value}. "
                f"Allowed: {sorted(state.value for state in allowed)}"
            )
        run.state = target
        return run

    def _check_budget(self, run: OrchestrationRun, step_name: str) -> None:
        if run.deadline is not None and _dt.datetime.now(_dt.UTC) > run.deadline:
            raise OrchestrationBudgetExceeded(f"Run exceeded its deadline while {step_name}")
        if step_name == "tool execution":
            if run.tool_calls_used >= run.max_tool_calls:
                raise OrchestrationBudgetExceeded("Run exceeded the maximum number of tool calls")
            return
        if run.steps_used >= run.max_steps:
            raise OrchestrationBudgetExceeded("Run exceeded the maximum number of organizational steps")

    def _ensure_not_terminal(self, run: OrchestrationRun) -> None:
        if run.is_terminal:
            raise OrchestrationBudgetExceeded(f"Run is already terminal in state {run.state.value}")


__all__ = [
    "BoundedOrchestrator",
    "DeterministicPlanner",
    "InvalidTransitionError",
    "OrchestrationBudgetExceeded",
    "OrchestrationPlan",
    "OrchestrationRun",
    "OrchestrationState",
    "OrchestrationTool",
    "PlanStep",
]
