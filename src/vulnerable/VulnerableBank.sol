// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev VOLONTAIREMENT VULNÉRABLE : usage pédagogique uniquement.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Solde nul");

        // BUG : l'ether est envoyé AVANT la mise à jour du solde
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfert echoue");

        balances[msg.sender] = 0;
    }

    function totalBalance() external view returns (uint256) {
        return address(this).balance;
    }
}