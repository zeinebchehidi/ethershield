// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice CONTRAT VOLONTAIREMENT VULNÉRABLE - usage laboratoire uniquement
contract VulnerableAdminBank {
    address public owner;
    address public feeRecipient;
    uint256 public feeBps = 250;
    bool public paused;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
        feeRecipient = msg.sender;
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

    // ❌ Aucune vérification de msg.sender sur les fonctions suivantes
    function setFeeRecipient(address r) external {
        feeRecipient = r;
    }

    function setFeeBps(uint256 b) external {
        feeBps = b;
    }

    function pause() external {
        paused = true;
    }

    function transferOwnership(address n) external {
        owner = n;
    }

    function emergencyWithdraw() external {
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }
}
