"""
AgentVault: Secure DeFi Execution & Cryptographic Identity Layer for AI Agents.

This module acts as a gatekeeper between an untrusted LLM agent and a private key.
It enforces structured output parsing via Pydantic, validates the output against 
deterministic security policies, and securely signs and broadcasts Ethereum transactions.
"""

import json
import os
from typing import Set
from pydantic import BaseModel, Field, field_validator, ValidationError
from web3 import Web3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class PolicyViolationError(Exception):
    """Raised when a transaction proposal violates a security policy rule."""
    pass


class InvalidProposalError(Exception):
    """Raised when a transaction proposal JSON is malformed or invalid."""
    pass


class TransactionProposal(BaseModel):
    """
    Pydantic schema representing a structured transaction proposal from an LLM.
    
    Fields:
        target_address: The EVM destination address (validated to checksum format).
        amount_eth: The transfer amount in Ether (must be positive).
        intent: A descriptive string explaining the purpose of the transaction.
    """
    target_address: str = Field(
        ..., 
        description="The checksummed Ethereum address of the recipient."
    )
    amount_eth: float = Field(
        ..., 
        description="The amount of ETH to transfer, must be greater than zero."
    )
    intent: str = Field(
        ..., 
        description="Description of the rationale/intent of the transaction."
    )

    @field_validator('target_address')
    @classmethod
    def validate_and_checksum_address(cls, v: str) -> str:
        """Ensures the address is valid and returns its checksum format."""
        clean_address = v.strip()
        if not Web3.is_address(clean_address):
            raise ValueError(f"Invalid Ethereum address format: '{v}'")
        return Web3.to_checksum_address(clean_address)

    @field_validator('amount_eth')
    @classmethod
    def validate_amount_eth(cls, v: float) -> float:
        """Ensures the transaction amount is positive and non-zero."""
        if v <= 0:
            raise ValueError(f"Amount must be strictly positive (greater than 0). Got: {v}")
        return v

    @field_validator('intent')
    @classmethod
    def validate_intent(cls, v: str) -> str:
        """Ensures the intent is documented and non-empty."""
        clean_intent = v.strip()
        if not clean_intent:
            raise ValueError("Transaction intent description cannot be empty.")
        return clean_intent


class AgentVault:
    """
    Secure transaction coordinator that isolates private keys from agent execution context.
    
    It validates proposed transaction JSON payloads against a hardcoded security policy 
    (whitelist and max spend limits). If and only if the policies pass, it JIT-loads 
    the private key to sign and broadcast the transaction.
    """
    
    def __init__(
        self,
        private_key: str | None = None,
        provider_url: str | None = None,
        whitelist: list[str] | None = None,
        max_amount_eth: float = 0.05
    ):
        """
        Initialize the AgentVault.

        Args:
            private_key: Hex string of the private key. If None, reads AGENT_VAULT_PRIVATE_KEY from environment.
            provider_url: Ethereum node RPC URL. If None, reads ETH_RPC_URL (default: http://127.0.0.1:8545).
            whitelist: A list of pre-approved target Ethereum addresses.
            max_amount_eth: The maximum allowed transaction spend in ETH.
        """
        # Load RPC Provider
        env_provider = os.getenv("ETH_RPC_URL", "http://127.0.0.1:8545")
        self.provider_url = provider_url or env_provider
        self.w3 = Web3(Web3.HTTPProvider(self.provider_url))

        # Normalize Whitelist addresses to checksum format
        self.whitelist: Set[str] = set()
        if whitelist:
            for addr in whitelist:
                if Web3.is_address(addr):
                    self.whitelist.add(Web3.to_checksum_address(addr))
                else:
                    raise ValueError(f"Invalid address in whitelist: {addr}")

        # Set maximum spend limit
        self.max_amount_eth = max_amount_eth

        # Fetch Private Key securely from parameter or env
        self._private_key = private_key or os.getenv("AGENT_VAULT_PRIVATE_KEY")
        if self._private_key:
            # Normalize key prefix
            if not self._private_key.startswith("0x") and len(self._private_key) == 64:
                self._private_key = f"0x{self._private_key}"

    def evaluate_policy(self, proposal: TransactionProposal) -> None:
        """
        Deterministically evaluates policies on the proposal.

        Args:
            proposal: The parsed Pydantic TransactionProposal object.

        Raises:
            PolicyViolationError: If target address is not whitelisted or amount exceeds limits.
        """
        # Policy Rule 1: Whitelist Check
        if proposal.target_address not in self.whitelist:
            raise PolicyViolationError(
                f"Address {proposal.target_address} is NOT in the whitelist. "
                "Transaction rejected."
            )

        # Policy Rule 2: Limit Check
        if proposal.amount_eth > self.max_amount_eth:
            raise PolicyViolationError(
                f"Transaction amount ({proposal.amount_eth} ETH) exceeds the maximum "
                f"limit of {self.max_amount_eth} ETH. Transaction rejected."
            )

    def execute_proposal(self, json_proposal_str: str) -> str:
        """
        Parses a raw JSON proposal from the agent, evaluates policies, 
        and JIT-signs and broadcasts the transaction.

        Args:
            json_proposal_str: Raw JSON string matching the TransactionProposal schema.

        Returns:
            str: The transaction hash hex string.

        Raises:
            InvalidProposalError: If the JSON cannot be parsed or Pydantic validation fails.
            PolicyViolationError: If security policies are violated.
            ValueError: If private key is missing or invalid.
            ConnectionError: If connection to EVM RPC provider fails.
        """
        # Step 1: Parse and strictly validate schema
        try:
            data = json.loads(json_proposal_str)
        except json.JSONDecodeError as e:
            raise InvalidProposalError(
                f"Malformed JSON payload. Error: {str(e)}"
            ) from e

        try:
            proposal = TransactionProposal.model_validate(data)
        except ValidationError as e:
            # Standardize Pydantic validation error representation
            error_details = e.errors()
            raise InvalidProposalError(
                f"JSON proposal does not match required schema. Validation errors: {error_details}"
            ) from e

        # Step 2: Policy Engine validation
        self.evaluate_policy(proposal)

        # Step 3: Validate RPC Connection
        if not self.w3.is_connected():
            raise ConnectionError(
                f"EVM Node RPC client is disconnected or unavailable at: {self.provider_url}. "
                "Ensure your local Anvil network is running."
            )

        # Step 4: Validate Private Key presence
        if not self._private_key:
            raise ValueError(
                "Private key not configured. Set AGENT_VAULT_PRIVATE_KEY in .env "
                "or pass it to the AgentVault initializer."
            )

        # Step 5: JIT Key loading & Account derivation in-memory
        try:
            account = self.w3.eth.account.from_key(self._private_key)
        except Exception as e:
            raise ValueError(f"Failed to load cryptographic account from private key: {str(e)}") from e

        # Step 6: Create, sign, and broadcast the transaction
        try:
            # Get nonce from the network
            nonce = self.w3.eth.get_transaction_count(account.address)
            
            # Fetch gas price estimate from network
            gas_price = self.w3.eth.gas_price

            # Standard simple transfer tx structure
            tx = {
                'nonce': nonce,
                'to': proposal.target_address,
                'value': self.w3.to_wei(proposal.amount_eth, 'ether'),
                'gas': 21000,  # Standard gas limit for simple transfer
                'gasPrice': gas_price,
                'chainId': self.w3.eth.chain_id
            }

            # Sign transaction JIT
            signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self._private_key)
            
            # Broadcast to network
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            
            return tx_hash.hex()

        except Exception as e:
            raise RuntimeError(f"Transaction signing or broadcast failed: {str(e)}") from e
