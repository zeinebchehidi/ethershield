// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev VOLONTAIREMENT VULNÉRABLE : usage pédagogique uniquement.
/// Enchère simple : chaque nouvelle offre doit dépasser la précédente,
/// et l'ancien meilleur enchérisseur est remboursé immédiatement ("push payment").
contract VulnerableAuction {
    address public highestBidder;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid, "Offre trop basse");

        address previousBidder = highestBidder;
        uint256 previousBid = highestBid;

        highestBidder = msg.sender;
        highestBid = msg.value;

        // BUG : le remboursement est envoyé de force à l'ancien enchérisseur.
        // S'il s'agit d'un contrat dont receive() revert, require(ok) annule
        // TOUTE nouvelle enchère : l'enchère est bloquée définitivement.
        if (previousBidder != address(0)) {
            (bool ok,) = previousBidder.call{value: previousBid}("");
            require(ok, "Remboursement echoue");
        }
    }
}
