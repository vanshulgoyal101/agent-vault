"""
Sandbox Demo: Live transaction verification script.
Spins up the Sandbox Node in the background, loads AgentVault, and 
executes transaction proposals, verifying policy passes and violations.
"""

import os
import sys
import subprocess
import time
import json
from dotenv import load_dotenv

# Ensure we can import agent_vault
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agent_vault import AgentVault, PolicyViolationError, InvalidProposalError

# Load variables
load_dotenv()

# Test config
RPC_URL = "http://127.0.0.1:8545"
WHITELISTED_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
NON_WHITELISTED_ADDRESS = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
PRIVATE_KEY = os.getenv(
    "AGENT_VAULT_PRIVATE_KEY",
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)


def run_demo():
    server_proc = None
    try:
        # Step 1: Spin up Sandbox RPC Server in the background
        print("[DEMO] Starting local Sandbox RPC Node on port 8545...")
        node_script = os.path.join(os.path.dirname(__file__), "sandbox_node.py")
        server_proc = subprocess.Popen(
            [sys.executable, "-u", node_script, "8545"],
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        
        # Give the server a moment to bind and launch
        time.sleep(1.5)
        
        # Verify the process is still running
        if server_proc.poll() is not None:
            raise RuntimeError(
                f"Failed to start Sandbox Node. Exit code: {server_proc.returncode}."
            )
            
        print("[DEMO] Sandbox Node is running. Initializing AgentVault...")

        # Step 2: Initialize AgentVault with rules
        vault = AgentVault(
            private_key=PRIVATE_KEY,
            provider_url=RPC_URL,
            whitelist=[WHITELISTED_ADDRESS],
            max_amount_eth=0.05
        )

        # =====================================================================
        # Case A: VALID Transaction Proposal (Whitelist pass, Limit pass)
        # =====================================================================
        print("\n====================================================")
        print(" CASE A: VALID PROPOSAL (0.02 ETH to Whitelisted)")
        print("====================================================")
        
        valid_proposal = {
            "target_address": WHITELISTED_ADDRESS,
            "amount_eth": 0.02,
            "intent": "Rebalance treasury gas reserves on Uniswap router"
        }
        proposal_json = json.dumps(valid_proposal, indent=2)
        
        print(f"Submitting proposal:\n{proposal_json}")
        
        tx_hash = vault.execute_proposal(proposal_json)
        print(f"\n[DEMO RESULT] Success! Tx broadcasted to sandbox node.")
        print(f"  Tx Hash Returned: {tx_hash}")

        # =====================================================================
        # Case B: INVALID Whitelist Transaction Proposal (Whitelist violation)
        # =====================================================================
        print("\n====================================================")
        print(" CASE B: INVALID WHITELIST ADDRESS (Should be blocked)")
        print("====================================================")
        
        invalid_whitelist_proposal = {
            "target_address": NON_WHITELISTED_ADDRESS,
            "amount_eth": 0.02,
            "intent": "Drain to external hot wallet"
        }
        proposal_json = json.dumps(invalid_whitelist_proposal, indent=2)
        
        print(f"Submitting proposal:\n{proposal_json}")
        
        try:
            vault.execute_proposal(proposal_json)
            print("[DEMO ERROR] CRITICAL FAILURE: Whitelist policy violation was NOT blocked!")
        except PolicyViolationError as e:
            print(f"\n[DEMO RESULT] Success! Blocked by Policy Engine: {str(e)}")

        # =====================================================================
        # Case C: INVALID Spend Limit Transaction Proposal (Limit violation)
        # =====================================================================
        print("\n====================================================")
        print(" CASE C: EXCEED MAX SPEND LIMIT (Should be blocked)")
        print("====================================================")
        
        invalid_amount_proposal = {
            "target_address": WHITELISTED_ADDRESS,
            "amount_eth": 0.10,  # exceeds max_amount_eth limit of 0.05
            "intent": "Buy treasury buffer"
        }
        proposal_json = json.dumps(invalid_amount_proposal, indent=2)
        
        print(f"Submitting proposal:\n{proposal_json}")
        
        try:
            vault.execute_proposal(proposal_json)
            print("[DEMO ERROR] CRITICAL FAILURE: Spend limit policy violation was NOT blocked!")
        except PolicyViolationError as e:
            print(f"\n[DEMO RESULT] Success! Blocked by Policy Engine: {str(e)}")

    finally:
        # Step 3: Stop local Sandbox server cleanly
        if server_proc:
            print("\n[DEMO] Cleaning up. Shutting down Sandbox RPC Server...")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
                print("[DEMO] Sandbox RPC Server shutdown successfully.")
            except subprocess.TimeoutExpired:
                print("[DEMO] Server did not exit in time. Killing process...")
                server_proc.kill()
                server_proc.wait()


if __name__ == "__main__":
    print("====================================================")
    print("     AGENTVAULT SANDBOX LIVE VERIFICATION DEMO      ")
    print("====================================================")
    run_demo()
