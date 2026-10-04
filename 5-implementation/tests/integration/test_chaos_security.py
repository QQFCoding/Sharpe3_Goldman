import pytest

from app.evaluation.chaos import FAILURES, fault_case


@pytest.mark.parametrize("failure", FAILURES)
async def test_failure_security_matrix(failure):
    await fault_case(failure)
