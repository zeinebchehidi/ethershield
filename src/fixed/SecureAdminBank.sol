// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureAdminBank is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    uint256 public constant MAX_FEE_BPS = 1_000; // plafond 10 %

    address public feeRecipient;
    uint256 public feeBps = 250;
    bool public paused;
    mapping(address => uint256) public balances;

    event FeeRecipientChanged(address indexed newRecipient);
    event FeeBpsChanged(uint256 newFeeBps);
    event PausedChanged(bool paused);

    constructor(address admin, address pauser) {
        require(admin != address(0) && pauser != address(0), "zero address");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, pauser);
        feeRecipient = admin;
    }

    function deposit() external payable {
        require(!paused, "paused");
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(!paused, "paused");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function setFeeRecipient(address r) external onlyRole(ADMIN_ROLE) {
        require(r != address(0), "zero address");
        feeRecipient = r;
        emit FeeRecipientChanged(r);
    }

    function setFeeBps(uint256 b) external onlyRole(ADMIN_ROLE) {
        require(b <= MAX_FEE_BPS, "fee too high");
        feeBps = b;
        emit FeeBpsChanged(b);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        paused = true;
        emit PausedChanged(true);
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        paused = false;
        emit PausedChanged(false);
    }

    // emergencyWithdraw et transferOwnership supprimées :
    // les fonds ne sortent que par withdraw(), les droits se gèrent via grantRole/revokeRole
}
