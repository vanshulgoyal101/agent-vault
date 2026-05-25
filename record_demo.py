"""
Demo Recording Helper Script.
Sequentially runs the vulnerable agent simulation and the secure agent simulation,
formatting the console logs with bold ANSI colors for screen recording.

To run:
    python record_demo.py
"""

import sys
import subprocess
import time
import os

# ANSI Colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
RESET = "\033[0m"


def print_banner(title: str, color: str):
    width = 65
    print("\n" + color + "=" * width)
    print(f" {title.center(width - 2)} ")
    print("=" * width + RESET + "\n")


def run_script(path: str):
    """Runs a sub-script and forwards output to the console."""
    proc = subprocess.Popen(
        [sys.executable, path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    
    # Print outputs in real-time
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        print(line, end="")
        sys.stdout.flush()
        
    proc.wait()


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    vulnerable_script = os.path.join(base_dir, "vulnerable_agent.py")
    secure_script = os.path.join(base_dir, "secure_agent.py")

    # Step 1: Vulnerable Agent Demonstration
    print_banner("DEMO PART 1: THE EXPLOIT (VULNERABLE AGENT)", RED)
    print(YELLOW + "Running vulnerable agent with direct private key access..." + RESET)
    time.sleep(2)
    run_script(vulnerable_script)

    print("\n" + YELLOW + "Processing next state... Preparing AgentVault defense." + RESET)
    time.sleep(4)

    # Step 2: Secure Agent Demonstration
    print_banner("DEMO PART 2: THE SHIELD (SECURE AGENT + AGENTVAULT)", GREEN)
    print(YELLOW + "Running secure agent wrapped inside AgentVault Policy Engine..." + RESET)
    time.sleep(2)
    run_script(secure_script)

    print_banner("SANDBOX RECORDING SYSTEM READY", CYAN)
    print(YELLOW + "💡 Distribution PSA Suggestion:" + RESET)
    print(GREEN + "I was testing prompt injections on autonomous trading agents and drained "
          "my own sandbox wallet in 10 seconds. Built this ERC-7579/Python vault to strictly "
          "scope permissions before the LLM can sign anything. Here is the pip install if anyone "
          "else is terrified of hardcoding private keys." + RESET)


if __name__ == "__main__":
    main()
