from app.controls.base import encoded
from app.core.transaction import Operation, SecurityTransaction
from app.policy.loader import ModelCost, Policy


def estimate(tx: SecurityTransaction, policy: Policy) -> tuple[int, float]:
    # UTF-8 bytes are a conservative local tokenizer-independent input bound.
    tx.budget.estimated_input_tokens = len(encoded(tx.payload))
    if tx.operation == Operation.LLM_REQUEST:
        tx.budget.max_output_tokens = tx.payload.get("max_tokens", 256)
        cost = policy.resource_costs.models.get(tx.resource.model, ModelCost())
        credits = (
            tx.budget.estimated_input_tokens * cost.per_1000_input_tokens
            + tx.budget.max_output_tokens * cost.per_1000_output_tokens
        ) / 1000
        return tx.budget.estimated_input_tokens + tx.budget.max_output_tokens, credits
    tx.budget.max_output_tokens = 0
    return tx.budget.estimated_input_tokens, policy.resource_costs.tools.get(
        tx.resource.name if tx.resource else tx.operation.value, policy.resource_costs.default_tool
    )


def actual_credits(tx: SecurityTransaction, policy: Policy, input_tokens: int, output_tokens: int) -> float:
    if tx.operation == Operation.LLM_REQUEST:
        cost = policy.resource_costs.models.get(tx.resource.model, ModelCost())
        return (
            input_tokens * cost.per_1000_input_tokens + output_tokens * cost.per_1000_output_tokens
        ) / 1000
    return tx.budget.reserved_credits
