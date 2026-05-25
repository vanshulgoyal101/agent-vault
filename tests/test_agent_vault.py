"""
Unit tests for the AgentVault Core SDK Policy Engine and validation schema.
These tests run in isolation and do not require external Web3 RPC connections.
"""

import pytest
from pydantic import ValidationError
from agent_vault.agent_vault import (
    TransactionProposal, 
    AgentVault, 
    PolicyViolationError, 
    InvalidProposalError
)

# Test addresses
VALID_WHITELISTED_ADDR = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
VALID_NON_WHITELISTED_ADDR = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
INVALID_ADDRESS_FORMAT = "0xinvalidaddressformat12345"

# Setup default test variables
DEFAULT_WHITELIST = [VALID_WHITELISTED_ADDR]
MAX_AMOUNT = 0.05


# =====================================================================
# 1. Pydantic Model Validation Tests (TransactionProposal)
# =====================================================================

def test_transaction_proposal_valid():
    """Verify that a standard valid proposal is successfully parsed and checksummed."""
    # Input with lowercase address
    lowercase_addr = VALID_WHITELISTED_ADDR.lower()
    proposal = TransactionProposal(
        target_address=lowercase_addr,
        amount_eth=0.03,
        intent="Provide liquidity"
    )
    assert proposal.amount_eth == 0.03
    assert proposal.intent == "Provide liquidity"
    # Verify address gets normalized to checksum format
    assert proposal.target_address == VALID_WHITELISTED_ADDR


def test_transaction_proposal_invalid_address():
    """Verify validation fails for structurally invalid Ethereum addresses."""
    with pytest.raises(ValidationError) as excinfo:
        TransactionProposal(
            target_address=INVALID_ADDRESS_FORMAT,
            amount_eth=0.03,
            intent="Arbitrary transfer"
        )
    assert "Invalid Ethereum address format" in str(excinfo.value)


def test_transaction_proposal_negative_amount():
    """Verify validation fails for zero or negative Ether amounts."""
    with pytest.raises(ValidationError) as excinfo:
        TransactionProposal(
            target_address=VALID_WHITELISTED_ADDR,
            amount_eth=-0.01,
            intent="Refund gas"
        )
    assert "Amount must be strictly positive" in str(excinfo.value)

    with pytest.raises(ValidationError) as excinfo:
        TransactionProposal(
            target_address=VALID_WHITELISTED_ADDR,
            amount_eth=0.0,
            intent="Zero test"
        )
    assert "Amount must be strictly positive" in str(excinfo.value)


def test_transaction_proposal_empty_intent():
    """Verify validation fails for empty or blank intent fields."""
    with pytest.raises(ValidationError) as excinfo:
        TransactionProposal(
            target_address=VALID_WHITELISTED_ADDR,
            amount_eth=0.01,
            intent="   "
        )
    assert "Transaction intent description cannot be empty" in str(excinfo.value)


# =====================================================================
# 2. AgentVault Policy Engine Unit Tests
# =====================================================================

def test_policy_engine_valid_proposal():
    """Verify that a whitelisted address and amount within limits passes evaluation."""
    vault = AgentVault(
        whitelist=DEFAULT_WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    proposal = TransactionProposal(
        target_address=VALID_WHITELISTED_ADDR,
        amount_eth=0.02,
        intent="Refill safe pool"
    )
    # Should run without raising any exceptions
    vault.evaluate_policy(proposal)


def test_policy_engine_violates_whitelist():
    """Verify that a non-whitelisted address triggers a PolicyViolationError."""
    vault = AgentVault(
        whitelist=DEFAULT_WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    proposal = TransactionProposal(
        target_address=VALID_NON_WHITELISTED_ADDR,
        amount_eth=0.02,
        intent="Send to non-whitelisted hot wallet"
    )
    with pytest.raises(PolicyViolationError) as excinfo:
        vault.evaluate_policy(proposal)
    assert "is NOT in the whitelist" in str(excinfo.value)


def test_policy_engine_violates_amount_limit():
    """Verify that an amount exceeding the maximum spend limit triggers a PolicyViolationError."""
    vault = AgentVault(
        whitelist=DEFAULT_WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    proposal = TransactionProposal(
        target_address=VALID_WHITELISTED_ADDR,
        amount_eth=0.06,  # limit is 0.05
        intent="Fund gas buffer"
    )
    with pytest.raises(PolicyViolationError) as excinfo:
        vault.evaluate_policy(proposal)
    assert "exceeds the maximum limit" in str(excinfo.value)


def test_policy_engine_whitelist_case_insensitivity():
    """Verify that policy evaluations are case-insensitive due to internal address checksumming."""
    # Initialize vault with lowercase address in whitelist
    vault = AgentVault(
        whitelist=[VALID_WHITELISTED_ADDR.lower()],
        max_amount_eth=MAX_AMOUNT
    )
    proposal = TransactionProposal(
        target_address=VALID_WHITELISTED_ADDR.upper(),
        amount_eth=0.01,
        intent="Validate case independence"
    )
    # Should resolve successfully
    vault.evaluate_policy(proposal)
