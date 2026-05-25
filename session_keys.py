"""
ERC-7715 & EIP-712 Session Keys Module for AgentVault.

Enables secure delegated execution where the human owner signs a temporary, 
restricted permission grant for an agent's local session key. The agent can 
then sign transactions using its local key without having access to the master key.
"""

import time
from typing import List, Dict, Any, Tuple
from eth_account import Account
from eth_account.messages import encode_typed_data, encode_defunct
from web3 import Web3
from .agent_vault import PolicyViolationError


def generate_agent_session_key() -> Tuple[str, str]:
    """
    Generates a secure, local secp256k1 keypair inside the agent environment.
    
    Returns:
        Tuple[str, str]: (session_private_key_hex, session_address_checksummed)
    """
    acct = Account.create()
    return acct.key.hex(), acct.address


def build_permission_grant_struct(
    signer: str, 
    account: str, 
    whitelist: List[str], 
    max_amount_eth: float, 
    expiry: int
) -> Dict[str, Any]:
    """
    Builds the EIP-712 structured dictionary representing the permission grant.
    """
    w3 = Web3()
    
    # Normalize addresses
    normalized_signer = w3.to_checksum_address(signer)
    normalized_account = w3.to_checksum_address(account)
    normalized_whitelist = [w3.to_checksum_address(addr) for addr in whitelist]

    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "PermissionGrant": [
                {"name": "signer", "type": "address"},
                {"name": "account", "type": "address"},
                {"name": "whitelist", "type": "address[]"},
                {"name": "maxAmountEth", "type": "string"},
                {"name": "expiry", "type": "uint256"}
            ]
        },
        "primaryType": "PermissionGrant",
        "domain": {
            "name": "AgentVaultPermission",
            "version": "1",
            "chainId": 31337,  # Default local chain ID
            "verifyingContract": "0x0000000000000000000000000000000000000000"
        },
        "message": {
            "signer": normalized_signer,
            "account": normalized_account,
            "whitelist": normalized_whitelist,
            "maxAmountEth": str(max_amount_eth),
            "expiry": expiry
        }
    }


def sign_permission_grant(
    owner_private_key: str, 
    grant_struct: Dict[str, Any]
) -> str:
    """
    Signs the EIP-712 permission grant using the human owner's private key.
    
    Returns:
        str: Hex signature string.
    """
    signable_msg = encode_typed_data(full_message=grant_struct)
    signed_msg = Account.sign_message(signable_msg, private_key=owner_private_key)
    return signed_msg.signature.hex()


def verify_session_signature(
    grant_struct: Dict[str, Any],
    owner_signature: str,
    tx_payload: Dict[str, Any],
    session_signature: str
) -> bool:
    """
    Verifies that the transaction matches permission boundaries, that the session signature 
    is valid, and that the owner authorized this session key.

    Args:
        grant_struct: The EIP-712 permission grant struct.
        owner_signature: Hex signature from the owner validating the grant.
        tx_payload: The transaction proposal details (target_address, amount_eth, intent).
        session_signature: Hex signature from the agent's session key.

    Raises:
        PolicyViolationError: If policies are breached or signatures are invalid.
    """
    w3 = Web3()
    
    # 1. Check Expiration
    current_time = int(time.time())
    expiry = grant_struct["message"]["expiry"]
    if current_time >= expiry:
        raise PolicyViolationError("Session key has expired. Permission revoked.")

    # 2. Check Whitelist Policy
    target = w3.to_checksum_address(tx_payload["target_address"])
    whitelist = grant_struct["message"]["whitelist"]
    if target not in whitelist:
        raise PolicyViolationError(f"Target address {target} is not whitelisted in session policy.")

    # 3. Check Spend Limit Policy
    amount = float(tx_payload["amount_eth"])
    limit = float(grant_struct["message"]["maxAmountEth"])
    if amount > limit:
        raise PolicyViolationError(f"Transaction amount ({amount} ETH) exceeds session cap of {limit} ETH.")

    # 4. Verify Owner's Permission Signature
    signable_grant = encode_typed_data(full_message=grant_struct)
    try:
        recovered_owner = Account.recover_message(signable_grant, signature=owner_signature)
    except Exception as e:
        raise PolicyViolationError(f"Invalid owner signature: {str(e)}")

    expected_owner = grant_struct["message"]["account"]
    if w3.to_checksum_address(recovered_owner) != w3.to_checksum_address(expected_owner):
        raise PolicyViolationError(
            f"Permission grant signature mismatch. Expected signer {expected_owner}, "
            f"recovered {recovered_owner}."
        )

    # 5. Verify Agent's Session Signature
    # Encode the transaction proposal payload to be signed by the agent session key
    # Simple message hash verification for tx execution
    proposal_message = f"Execute: {target} for {amount} ETH. Intent: {tx_payload.get('intent', '')}"
    signable_proposal = encode_defunct(text=proposal_message)
    
    try:
        recovered_session_signer = Account.recover_message(signable_proposal, signature=session_signature)
    except Exception as e:
        raise PolicyViolationError(f"Invalid session signature: {str(e)}")

    expected_session_signer = grant_struct["message"]["signer"]
    if w3.to_checksum_address(recovered_session_signer) != w3.to_checksum_address(expected_session_signer):
        raise PolicyViolationError(
            f"Agent session signature mismatch. Expected signer {expected_session_signer}, "
            f"recovered {recovered_session_signer}."
        )

    return True
