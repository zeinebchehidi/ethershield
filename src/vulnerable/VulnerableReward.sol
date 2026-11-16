// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VulnerableReward
/// @notice LAB ONLY. Pays the first person who submits the right answer.
/// @dev VULNERABLE: the answer travels in clear text in the pending
///      transaction, so anyone can copy it and front-run the sender.
contract VulnerableReward {
    bytes32 public immutable answerHash;
    bool public claimed;

    event Claimed(address indexed winner, uint256 amount);

    constructor(bytes32 _answerHash) payable {
        answerHash = _answerHash;
    }

        function claim(string calldata answer) external {
        require(!claimed, "Already claimed");
        require(keccak256(bytes(answer)) == answerHash, "Wrong answer");

        claimed = true;

        uint256 amount = address(this).balance;
        emit Claimed(msg.sender, amount); // l'emit AVANT l'envoi

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}