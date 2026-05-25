"""
Unit tests for the ERC-7715 & EIP-712 Session Key validator module.
Verifies session signature validity, expiration checks, whitelist boundaries, 
and spend limits on delegated agent execution keys.
"""

import time
import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from agent_vault.agent_vault import PolicyViolationError
from agent_vault.session_keys import (
    generate_agent_session_key,
    build_permission_grant_struct,
    sign_permission_grant,
    verify_session_signature
)

# Test environment configurations
OWNER_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OWNER_ADDRESS = Account.from_key(OWNER_PRIVATE_KEY).address
WHITELISTED_ADDR = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
NON_WHITELISTED_ADDR = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"


@pytest.fixture
def session_setup():
    """Generates test variables: agent keys, owner grants, signatures."""
    agent_pkey, agent_addr = generate_agent_session_key()
    
    # 1 hour expiry
    expiry = int(time.time()) + 3600
    
    grant = build_permission_grant_struct(
        signer=agent_addr,
        account=OWNER_ADDRESS,
        whitelist=[WHITELISTED_ADDR],
        max_amount_eth=0.05,
        expiry=expiry
    )
    
    owner_sig = sign_permission_grant(OWNER_PRIVATE_KEY, grant)
    
    return {
        "agent_pkey": agent_pkey,
        "agent_addr": agent_addr,
        "grant": grant,
        "owner_sig": owner_sig,
        "expiry": expiry
    }


# =====================================================================
# Tests
# =====================================================================

def test_session_verification_success(session_setup):
    """Verify that a valid transaction and valid session keys passes validation."""
    tx_payload = {
        "target_address": WHITELISTED_ADDR,
        "amount_eth": 0.03,
        "intent": "Gas refill"
    }
    
    # Agent signs the proposal message
    proposal_message = f"Execute: {tx_payload['target_address']} for {tx_payload['amount_eth']} ETH. Intent: {tx_payload['intent']}"
    signable_proposal = encode_defunct(text=proposal_message)
    session_sig = Account.sign_message(signable_proposal, private_key=session_setup["agent_pkey"]).signature.hex()
    
    # Run validation
    success = verify_session_signature(
        grant_struct=session_setup["grant"],
        owner_signature=session_setup["owner_sig"],
        tx_payload=tx_payload,
        session_signature=session_sig
    )
    assert success is True


def test_session_violates_whitelist(session_setup):
    """Verify that targeting a non-whitelisted address fails verification."""
    tx_payload = {
        "target_address": NON_WHITELISTED_ADDR,
        "amount_eth": 0.03,
        "intent": "Malicious drain attempt"
    }
    
    proposal_message = f"Execute: {tx_payload['target_address']} for {tx_payload['amount_eth']} ETH. Intent: {tx_payload['intent']}"
    signable_proposal = encode_defunct(text=proposal_message)
    session_sig = Account.sign_message(signable_proposal, private_key=session_setup["agent_pkey"]).signature.hex()
    
    with pytest.raises(PolicyViolationError) as excinfo:
        verify_session_signature(
            grant_struct=session_setup["grant"],
            owner_signature=session_setup["owner_sig"],
            tx_payload=tx_payload,
            session_signature=session_sig
        )
    assert "not whitelisted in session policy" in str(excinfo.value)


def test_session_violates_amount_limit(session_setup):
    """Verify that exceeding the session spend cap fails verification."""
    tx_payload = {
        "target_address": WHITELISTED_ADDR,
        "amount_eth": 0.06,  # Cap is 0.05
        "intent": "Whale swap"
    }
    
    proposal_message = f"Execute: {tx_payload['target_address']} for {tx_payload['amount_eth']} ETH. Intent: {tx_payload['intent']}"
    signable_proposal = encode_defunct(text=proposal_message)
    session_sig = Account.sign_message(signable_proposal, private_key=session_setup["agent_pkey"]).signature.hex()
    
    with pytest.raises(PolicyViolationError) as excinfo:
        verify_session_signature(
            grant_struct=session_setup["grant"],
            owner_signature=session_setup["owner_sig"],
            tx_payload=tx_payload,
            session_signature=session_sig
        )
    assert "exceeds session cap" in str(excinfo.value)


def test_session_has_expired(session_setup):
    """Verify that an expired session fails validation."""
    tx_payload = {
        "target_address": WHITELISTED_ADDR,
        "amount_eth": 0.03,
        "intent": "Delayed gas refill"
    }
    
    # Configure an expired grant
    expired_grant = session_setup["grant"].copy()
    expired_grant["message"]["expiry"] = int(time.time()) - 10  # 10 seconds in the past
    
    # Owner signs the expired grant
    owner_sig_expired = sign_permission_grant(OWNER_PRIVATE_KEY, expired_grant)
    
    proposal_message = f"Execute: {tx_payload['target_address']} for {tx_payload['amount_eth']} ETH. Intent: {tx_payload['intent']}"
    signable_proposal = encode_defunct(text=proposal_message)
    session_sig = Account.sign_message(signable_proposal, private_key=session_setup["agent_pkey"]).signature.hex()
    
    with pytest.raises(PolicyViolationError) as excinfo:
        verify_session_signature(
            grant_struct=expired_grant,
            owner_signature=owner_sig_expired,
            tx_payload=tx_payload,
            session_signature=session_sig
        )
    assert "Session key has expired" in str(excinfo.value)


def test_session_invalid_owner_sig(session_setup):
    """Verify that tampering with the owner's grant signature fails verification."""
    tx_payload = {
        "target_address": WHITELISTED_ADDR,
        "amount_eth": 0.03,
        "intent": "Gas refill"
    }
    
    proposal_message = f"Execute: {tx_payload['target_address']} for {tx_payload['amount_eth']} ETH. Intent: {tx_payload['intent']}"
    signable_proposal = encode_defunct(text=proposal_message)
    session_sig = Account.sign_message(signable_proposal, private_key=session_setup["agent_pkey"]).signature.hex()
    
    # Maliciously altered signature
    forged_owner_sig = session_setup["owner_sig"][:-4] + "0000"
    
    with pytest.raises(PolicyViolationError) as excinfo:
        verify_session_signature(
            grant_struct=session_setup["grant"],
            owner_signature=forged_owner_sig,
            tx_payload=tx_payload,
            session_signature=session_sig
        )
    assert "signature mismatch" in str(excinfo.value) or "Invalid owner signature" in str(excinfo.value)
