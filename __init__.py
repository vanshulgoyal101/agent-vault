"""
AgentVault Package.
Exposes the core execution engine, Pydantic validation schema, and policy exceptions.
"""

from .agent_vault import (
    AgentVault,
    TransactionProposal,
    PolicyViolationError,
    InvalidProposalError,
)

__all__ = [
    "AgentVault",
    "TransactionProposal",
    "PolicyViolationError",
    "InvalidProposalError",
]
