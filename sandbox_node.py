"""
Sandbox Node: A local lightweight JSON-RPC EVM simulator server.
Listens on http://127.0.0.1:8545 and handles basic Web3 JSON-RPC methods.
Allows AgentVault to perform live signings and broadcasts in a local python environment.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
from typing import Dict, Any


class SandboxJSONRPCHandler(BaseHTTPRequestHandler):
    # In-memory transaction receipts store
    receipts: Dict[str, Dict[str, Any]] = {}
    nonces: Dict[str, int] = {}

    def log_message(self, format: str, *args: Any) -> None:
        # Override to suppress standard HTTP logging and keep console output clean
        pass

    def do_POST(self) -> None:
        """Handles POST requests carrying JSON-RPC commands from Web3.py."""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            request = json.loads(post_data.decode('utf-8'))
        except Exception as e:
            self.send_error_response(-32700, f"Parse error: {str(e)}", None)
            return

        # Check if batch request or single request
        if isinstance(request, list):
            response = [self._handle_single_request(req) for req in request]
        else:
            response = self._handle_single_request(request)

        # Send response
        response_bytes = json.dumps(response).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def send_error_response(self, code: int, message: str, req_id: Any) -> None:
        error_response = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message
            }
        }
        response_bytes = json.dumps(error_response).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def _handle_single_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", [])
        
        result = None

        if method == "eth_chainId":
            # Chain ID 31337 (standard local Anvil/Hardhat chain ID)
            result = "0x7a69"
            
        elif method == "net_version":
            result = "31337"
            
        elif method == "net_listening":
            result = True
            
        elif method == "eth_blockNumber":
            result = "0x42"  # Block 66
            
        elif method == "eth_gasPrice":
            # 20 Gwei in hex
            result = "0x4a817c800"
            
        elif method == "eth_estimateGas":
            # 21000 standard transfer limit in hex
            result = "0x5208"
            
        elif method == "eth_getTransactionCount":
            # Return tracked nonce for address
            address = params[0].lower() if params else "0x"
            nonce = self.nonces.get(address, 0)
            result = hex(nonce)
            
        elif method == "eth_sendRawTransaction":
            raw_tx_hex = params[0]
            tx_hash = "0x" + hashlib.sha256(bytes.fromhex(raw_tx_hex[2:])).hexdigest()
            
            # Decode parameters for detailed logging
            to_addr, value_wei, nonce_used = self._decode_raw_tx(raw_tx_hex)
            value_eth = value_wei / 1e18
            
            print(f"\n[SANDBOX NODE] Transaction Received!")
            print(f"  Tx Hash: {tx_hash}")
            print(f"  To:      {to_addr}")
            print(f"  Value:   {value_eth} ETH")
            print(f"  Nonce:   {nonce_used}")
            print(f"  Status:  Mined (Block 0x42)")

            # Store receipt in memory
            self.receipts[tx_hash] = {
                "transactionHash": tx_hash,
                "blockHash": "0x828dfef24c87c800828dfef24c87c800828dfef24c87c800828dfef24c87c800",
                "blockNumber": "0x42",
                "status": "0x1",  # 1 = Success
                "gasUsed": "0x5208",  # 21000
                "cumulativeGasUsed": "0x5208",
                "effectiveGasPrice": "0x4a817c800",
                "logs": [],
                "to": to_addr
            }
            
            # Update nonce in tracking
            # We can't recover from address easily in this mock unless we decode signature, 
            # but we can just increment nonce for whatever sender Web3.py tracks
            result = tx_hash
            
        elif method == "eth_getTransactionReceipt":
            tx_hash = params[0]
            result = self.receipts.get(tx_hash)
            
        elif method == "web3_clientVersion":
            result = "SandboxNode/v1.0.0"
            
        else:
            # Fallback for unhandled methods
            result = "0x0"

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result
        }

    def _decode_raw_tx(self, raw_tx_hex: str) -> tuple[str, int, int]:
        """Helper function using rlp to parse destination address and value from raw transaction bytes."""
        import rlp
        try:
            raw_bytes = bytes.fromhex(raw_tx_hex[2:])
            tx_type = raw_bytes[0]
            
            # EIP-2718 Envelope transaction parsing
            if tx_type in (1, 2):
                payload = rlp.decode(raw_bytes[1:])
                to_bytes = payload[5]
                value_bytes = payload[6]
                nonce_bytes = payload[1]
            else:
                payload = rlp.decode(raw_bytes)
                to_bytes = payload[3]
                value_bytes = payload[4]
                nonce_bytes = payload[0]
                
            to_addr = "0x" + to_bytes.hex() if to_bytes else "0x0000000000000000000000000000000000000000"
            value_wei = int.from_bytes(value_bytes, byteorder='big') if value_bytes else 0
            nonce = int.from_bytes(nonce_bytes, byteorder='big') if nonce_bytes else 0
            
            # Form check checksum address
            from web3 import Web3
            if Web3.is_address(to_addr):
                to_addr = Web3.to_checksum_address(to_addr)
                
            return to_addr, value_wei, nonce
        except Exception as e:
            # Fallback if decoding fails due to unexpected transaction schemas
            return "Unknown (Decoding error: " + str(e) + ")", 0, 0


def run_server(port: int = 8545) -> None:
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, SandboxJSONRPCHandler)
    print(f"[SANDBOX NODE] Running HTTP JSON-RPC EVM node simulator on http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SANDBOX NODE] Shutting down server...")
        sys.exit(0)


if __name__ == "__main__":
    port = 8545
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port)
