import pytest
from pydantic import ValidationError

from app.policy.loader import ResourceCosts


@pytest.mark.parametrize("price", [-1, float("inf"), float("nan")])
def test_tool_costs_must_be_nonnegative_and_finite(price):
    with pytest.raises(ValidationError):
        ResourceCosts(tools={"github.search": price})
