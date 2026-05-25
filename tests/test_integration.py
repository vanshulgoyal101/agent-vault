"""
Integration tests for AgentVault.
Uses unittest.mock to simulate Web3 provider connections, transaction signing, 
and broadcasting, allowing the execution flow to be fully verified in CI or local environments
without requiring a running Ethereum node.
"""

import os
import json
from unittest.mock import MagicMock, patch
import pytest
from hexbytes import HexBytes
from agent_vault.agent_vault import (
    AgentVault, 
    PolicyViolationError, 
    InvalidProposalError
)

# Test configs
VALID_WHITELISTED_ADDR = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
WHITELIST = [VALID_WHITELISTED_ADDR]
MAX_AMOUNT = 0.05
DUMMY_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


@pytest.fixture
def mock_web3():
    """Configures a mocked Web3 instance with standard Ethereum provider signatures."""
    with patch('agent_vault.agent_vault.Web3') as mock_w3_class:
        # Mock class-level attributes/methods called directly on Web3 class
        mock_w3_class.is_address.side_effect = lambda x: True
        mock_w3_class.to_checksum_address.side_effect = lambda x: x
        
        # Create a mock web3 instance
        instance = MagicMock()
        mock_w3_class.return_value = instance
        
        # Connection status mock
        instance.is_connected.return_value = True
        
        # Web3 utility functions
        instance.to_checksum_address.side_effect = lambda x: x  # identity helper for mocked addresses
        instance.to_wei.side_effect = lambda value, unit: int(value * 1e18)
        
        # Eth namespace mocks
        instance.eth.get_transaction_count.return_value = 42
        instance.eth.gas_price = 20000000000
        instance.eth.chain_id = 1
        
        # Account mocks
        mock_account = MagicMock()
        mock_account.address = VALID_WHITELISTED_ADDR
        instance.eth.account.from_key.return_value = mock_account
        
        # Signing mock
        mock_signed_tx = MagicMock()
        mock_signed_tx.raw_transaction = b"mocked_raw_transaction_bytes"
        instance.eth.account.sign_transaction.return_value = mock_signed_tx
        
        # Broadcast mock
        instance.eth.send_raw_transaction.return_value = HexBytes("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        
        yield instance


# =====================================================================
# 1. Success Flow Integration Tests
# =====================================================================

def test_execute_proposal_success(mock_web3):
    """Verify the entire end-to-end execution flow of a valid proposal."""
    vault = AgentVault(
        private_key=DUMMY_PRIVATE_KEY,
        whitelist=WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    
    valid_proposal = {
        "target_address": VALID_WHITELISTED_ADDR,
        "amount_eth": 0.03,
        "intent": "Rebalance Uniswap v3 vault reserves"
    }
    proposal_json = json.dumps(valid_proposal)
    
    tx_hash = vault.execute_proposal(proposal_json)
    
    # Assertions on execution output
    assert tx_hash == "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    
    # Assert Web3 interactions took place correctly
    mock_web3.is_connected.assert_called_once()
    mock_web3.eth.account.from_key.assert_called_once_with(DUMMY_PRIVATE_KEY)
    mock_web3.eth.get_transaction_count.assert_called_once_with(VALID_WHITELISTED_ADDR)
    mock_web3.eth.account.sign_transaction.assert_called_once()
    mock_web3.eth.send_raw_transaction.assert_called_once_with(b"mocked_raw_transaction_bytes")


# =====================================================================
# 2. Schema and Parsing Failure Tests
# =====================================================================

def test_execute_proposal_invalid_json(mock_web3):
    """Verify that a syntactically invalid JSON payload raises InvalidProposalError."""
    vault = AgentVault(
        private_key=DUMMY_PRIVATE_KEY,
        whitelist=WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    
    malformed_json = '{"target_address": "' + VALID_WHITELISTED_ADDR + '", "amount_eth": 0.03'  # Missing closing brace
    
    with pytest.raises(InvalidProposalError) as excinfo:
        vault.execute_proposal(malformed_json)
    assert "Malformed JSON payload" in str(excinfo.value)
    
    # Ensure key was never loaded or signed
    mock_web3.eth.account.from_key.assert_not_called()


def test_execute_proposal_schema_violation(mock_web3):
    """Verify that a valid JSON payload missing required parameters raises InvalidProposalError."""
    vault = AgentVault(
        private_key=DUMMY_PRIVATE_KEY,
        whitelist=WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    
    missing_fields_json = json.dumps({
        "target_address": VALID_WHITELISTED_ADDR
        # missing amount_eth and intent
    })
    
    with pytest.raises(InvalidProposalError) as excinfo:
        vault.execute_proposal(missing_fields_json)
    assert "JSON proposal does not match required schema" in str(excinfo.value)
    
    # Ensure key was never loaded
    mock_web3.eth.account.from_key.assert_not_called()


# =====================================================================
# 3. Policy Guard Interception Tests
# =====================================================================

def test_execute_proposal_policy_violated(mock_web3):
    """Verify that a proposal violating whitelist policy is blocked before key loading."""
    vault = AgentVault(
        private_key=DUMMY_PRIVATE_KEY,
        whitelist=WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    
    malicious_proposal = {
        "target_address": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",  # not whitelisted
        "amount_eth": 0.02,
        "intent": "Malicious Transfer"
    }
    
    with pytest.raises(PolicyViolationError) as excinfo:
        vault.execute_proposal(json.dumps(malicious_proposal))
    assert "is NOT in the whitelist" in str(excinfo.value)
    
    # CRITICAL: Confirm Web3 key JIT-loader was never triggered
    mock_web3.eth.account.from_key.assert_not_called()
    mock_web3.eth.send_raw_transaction.assert_not_called()


# =====================================================================
# 4. System and Environmental Failure Tests
# =====================================================================

def test_execute_proposal_disconnected_rpc(mock_web3):
    """Verify that Web3 RPC connectivity failure raises ConnectionError and halts execution."""
    mock_web3.is_connected.return_value = False
    
    vault = AgentVault(
        private_key=DUMMY_PRIVATE_KEY,
        whitelist=WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    
    valid_proposal = {
        "target_address": VALID_WHITELISTED_ADDR,
        "amount_eth": 0.03,
        "intent": "Rebalance reserves"
    }
    
    with pytest.raises(ConnectionError) as excinfo:
        vault.execute_proposal(json.dumps(valid_proposal))
    assert "EVM Node RPC client is disconnected" in str(excinfo.value)
    
    # Ensure JIT signing was never run
    mock_web3.eth.account.from_key.assert_not_called()


def test_execute_proposal_missing_key(mock_web3):
    """Verify that missing private key configuration raises a ValueError."""
    # Initialize vault with private_key = None
    vault = AgentVault(
        private_key=None,
        whitelist=WHITELIST,
        max_amount_eth=MAX_AMOUNT
    )
    # Ensure environment is also patched to have no key
    with patch.dict(os.environ, {}, clear=True):
        vault._private_key = None  # force none
        
        valid_proposal = {
            "target_address": VALID_WHITELISTED_ADDR,
            "amount_eth": 0.03,
            "intent": "Rebalance reserves"
        }
        
        with pytest.raises(ValueError) as excinfo:
            vault.execute_proposal(json.dumps(valid_proposal))
        assert "Private key not configured" in str(excinfo.value)
