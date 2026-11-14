// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// Correctif : pattern "pull payment". Le contrat n'envoie jamais d'ETH à un tiers
/// pendant bid() ; chaque enchérisseur retire lui-même son remboursement.
contract SecureAuction is ReentrancyGuard {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    event NewHighestBid(address indexed bidder, uint256 amount);
    event Withdrawal(address indexed bidder, uint256 amount);

    function bid() external payable {
        require(msg.value > highestBid, "Offre trop basse");

        // Le remboursement est seulement ENREGISTRÉ, jamais envoyé ici
        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
        emit NewHighestBid(msg.sender, msg.value);
    }

    function withdraw() external nonReentrant {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "Rien a retirer");

        // Checks-Effects-Interactions
        pendingReturns[msg.sender] = 0;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfert echoue");
        emit Withdrawal(msg.sender, amount);
    }
}
