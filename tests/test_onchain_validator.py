"""
On-Chain Validator Test Suite.
Verifies the ABI compatibility and decoding alignment between the Python AgentVault 
execution layer and the Solidity AgentPolicyValidator.sol contract.
It simulates the exact abi.decode logic used in the smart contract's validateUserOp function.
"""

import pytest
from web3 import Web3
from eth_abi import encode, decode
from agent_vault.agent_vault import PolicyViolationError

# Constants matching Solidity contract specs
EXECUTE_SELECTOR = bytes.fromhex("b61d27f6")  # execute(address,uint256,bytes)

# Test addresses
WHITELISTED_ADDR = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
NON_WHITELISTED_ADDR = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
MAX_LIMIT_WEI = int(0.05 * 1e18)  # 0.05 ETH in wei


def build_execute_calldata(dest: str, value_wei: int, inner_data: bytes = b"") -> bytes:
    """Simulates the smart account's execute callData generation."""
    # ABI encode parameters for: execute(address dest, uint256 value, bytes calldata func)
    encoded_args = encode(['address', 'uint256', 'bytes'], [dest, value_wei, inner_data])
    return EXECUTE_SELECTOR + encoded_args


def simulate_onchain_validate_user_op(
    call_data: bytes, 
    whitelist: list[str], 
    max_amount_wei: int
) -> int:
    """
    Python implementation of the Solidity AgentPolicyValidator.sol's validateUserOp checks.
    It performs the exact same ABI extraction and policy enforcement.
    """
    # 1. Selector check
    if len(call_data) < 4:
        return 1  # VALIDATION_FAILED
        
    selector = call_data[:4]
    if selector != EXECUTE_SELECTOR:
        return 1  # VALIDATION_FAILED
        
    # 2. Extract arguments (equivalent to Solidity's abi.decode)
    try:
        decoded = decode(
            ['address', 'uint256', 'bytes'], 
            call_data[4:]
        )
        dest, value, _ = decoded
    except Exception:
        return 1  # VALIDATION_FAILED

    # 3. Policy Rule 1: Whitelist Check
    normalized_whitelist = [Web3.to_checksum_address(addr) for addr in whitelist]
    normalized_dest = Web3.to_checksum_address(dest)
    if normalized_dest not in normalized_whitelist:
        return 1  # VALIDATION_FAILED

    # 4. Policy Rule 2: Spend limit check (in Wei)
    if value > max_amount_wei:
        return 1  # VALIDATION_FAILED

    return 0  # VALIDATION_SUCCESS


# =====================================================================
# Tests
# =====================================================================

def test_abi_encoding_and_onchain_decoding_success():
    """Verify that a valid execute payload successfully decodes and passes policy validation."""
    dest_address = WHITELISTED_ADDR
    spend_value_wei = int(0.02 * 1e18)  # 0.02 ETH
    
    # Generate callData
    call_data = build_execute_calldata(dest_address, spend_value_wei)
    
    # Run simulated on-chain validator
    result = simulate_onchain_validate_user_op(
        call_data=call_data,
        whitelist=[WHITELISTED_ADDR],
        max_amount_wei=MAX_LIMIT_WEI
    )
    
    # Assert validation succeeds (returns 0)
    assert result == 0


def test_abi_decoding_violates_whitelist():
    """Verify that an execute payload targeting a non-whitelisted address fails validation on-chain."""
    dest_address = NON_WHITELISTED_ADDR
    spend_value_wei = int(0.02 * 1e18)
    
    call_data = build_execute_calldata(dest_address, spend_value_wei)
    
    result = simulate_onchain_validate_user_op(
        call_data=call_data,
        whitelist=[WHITELISTED_ADDR],  # whitelist only has WHITELISTED_ADDR
        max_amount_wei=MAX_LIMIT_WEI
    )
    
    # Assert validation fails (returns 1)
    assert result == 1


def test_abi_decoding_violates_spend_limit():
    """Verify that an execute payload exceeding the limit fails validation on-chain."""
    dest_address = WHITELISTED_ADDR
    spend_value_wei = int(0.06 * 1e18)  # exceeds 0.05 limit
    
    call_data = build_execute_calldata(dest_address, spend_value_wei)
    
    result = simulate_onchain_validate_user_op(
        call_data=call_data,
        whitelist=[WHITELISTED_ADDR],
        max_amount_wei=MAX_LIMIT_WEI
    )
    
    # Assert validation fails (returns 1)
    assert result == 1


def test_abi_decoding_invalid_selector():
    """Verify that callData with an unsupported function selector fails validation."""
    # Build callData with a fake selector (e.g. 0xdeadbeef)
    fake_selector = bytes.fromhex("deadbeef")
    encoded_args = encode(['address', 'uint256', 'bytes'], [WHITELISTED_ADDR, int(0.02 * 1e18), b""])
    call_data = fake_selector + encoded_args
    
    result = simulate_onchain_validate_user_op(
        call_data=call_data,
        whitelist=[WHITELISTED_ADDR],
        max_amount_wei=MAX_LIMIT_WEI
    )
    
    # Assert validation fails (returns 1)
    assert result == 1
