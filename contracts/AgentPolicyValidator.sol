// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @dev Minimal structure matching ERC-4337 UserOperation for parsing validator inputs.
 */
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

/**
 * @title AgentPolicyValidator
 * @author Senior Web3 Security Architect (ex-Coinbase)
 * @notice An ERC-7579 compliant validation module that enforces transaction policies on-chain
 *         for autonomous AI agents. This module prevents wallet draining by intercepting 
 *         UserOperations and validating target destinations and spend limits.
 */
contract AgentPolicyValidator {
    
    // Module Type ID for ERC-7579 Validators
    uint256 public constant MODULE_TYPE_VALIDATOR = 1;
    
    // Status return code for successful ERC-4337 verification
    uint256 public constant VALIDATION_SUCCESS = 0;
    // Status return code for signature/policy verification failure (reverts or returns 1)
    uint256 public constant VALIDATION_FAILED = 1;

    // Selector for execute(address,uint256,bytes) on ERC-4337 accounts
    bytes4 public constant EXECUTE_SELECTOR = 0xb61d27f6;
    
    // Mapping to track the smart account owner who configures policy states
    // Smart Account -> Admin/Owner Address
    mapping(address => address) public accountOwners;

    // Smart Account -> Target Destination -> Whitelist Status
    mapping(address => mapping(address => bool)) public whitelists;

    // Smart Account -> Max Eth Transfer Limit (in Wei) per transaction
    mapping(address => uint256) public maxAmounts;

    // Events for policy configurations
    event PolicyInstalled(address indexed account, address indexed owner, uint256 maxAmount);
    event WhitelistUpdated(address indexed account, address indexed target, bool status);
    event LimitUpdated(address indexed account, uint256 newLimit);
    event PolicyViolationInterception(address indexed account, address indexed target, uint256 amount, string reason);

    modifier onlyAccountOwner() {
        require(accountOwners[msg.sender] == tx.origin || accountOwners[msg.sender] == msg.sender, "Only the configured account owner can invoke this function");
        _;
    }

    /**
     * @notice ERC-7579 Module lifecycle hook: Initialize policy parameters for a smart account.
     * @param data abi-encoded initialization payload: (address owner, address[] whitelist, uint256 maxAmount)
     */
    function onInstall(bytes calldata data) external {
        require(accountOwners[msg.sender] == address(0), "Policy already installed for this account");
        
        (address _owner, address[] memory _initialWhitelist, uint256 _maxAmount) = abi.decode(
            data, 
            (address, address[], uint256)
        );

        require(_owner != address(0), "Invalid owner address");
        accountOwners[msg.sender] = _owner;
        maxAmounts[msg.sender] = _maxAmount;

        for (uint256 i = 0; i < _initialWhitelist.length; i++) {
            whitelists[msg.sender][_initialWhitelist[i]] = true;
            emit WhitelistUpdated(msg.sender, _initialWhitelist[i], true);
        }

        emit PolicyInstalled(msg.sender, _owner, _maxAmount);
    }

    /**
     * @notice ERC-7579 Module lifecycle hook: Clean up policy parameters during uninstallation.
     */
    function onUninstall(bytes calldata) external {
        require(accountOwners[msg.sender] != address(0), "Policy not installed for this account");
        
        accountOwners[msg.sender] = address(0);
        maxAmounts[msg.sender] = 0;
        
        emit PolicyInstalled(msg.sender, address(0), 0);
    }

    /**
     * @notice Returns true if the module implements the specified type (Validator = 1).
     */
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /**
     * @notice Enforces policy checks on incoming UserOperations.
     * @param userOp The ERC-4337 transaction user operation struct.
     * @return validationResult 0 for successful validation, 1 for signature validation failure.
     */
    function validateUserOp(
        UserOperation calldata userOp, 
        bytes32 /* userOpHash */
    ) external view returns (uint256) {
        address account = msg.sender;
        bytes calldata callData = userOp.callData;

        // Ensure callData has at least 4 bytes to check selector
        if (callData.length < 4) {
            return VALIDATION_FAILED;
        }

        bytes4 selector = bytes4(callData[:4]);

        // Intercept standard single-target execute calls
        if (selector == EXECUTE_SELECTOR) {
            // Decodes dest, value, and func from execution payload
            (address dest, uint256 value, ) = abi.decode(
                callData[4:], 
                (address, uint256, bytes)
            );

            // Policy Rule 1: Whitelist Check
            if (!whitelists[account][dest]) {
                return VALIDATION_FAILED;
            }

            // Policy Rule 2: Limit Check
            if (value > maxAmounts[account]) {
                return VALIDATION_FAILED;
            }

            return VALIDATION_SUCCESS;
        }

        // Reject complex/unsupported executions (e.g. batch transactions) for MVP security safety
        return VALIDATION_FAILED;
    }

    /**
     * @notice Update whitelist addresses. Can only be invoked by the smart account's owner.
     */
    function updateWhitelist(address target, bool status) external onlyAccountOwner {
        whitelists[msg.sender][target] = status;
        emit WhitelistUpdated(msg.sender, target, status);
    }

    /**
     * @notice Update per-transaction spend limit. Can only be invoked by the smart account's owner.
     */
    function updateLimit(uint256 newLimit) external onlyAccountOwner {
        maxAmounts[msg.sender] = newLimit;
        emit LimitUpdated(msg.sender, newLimit);
    }
}
