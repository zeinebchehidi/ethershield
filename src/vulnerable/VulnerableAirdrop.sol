// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev VOLONTAIREMENT VULNÉRABLE : usage pédagogique uniquement.
/// Airdrop : les participants s'inscrivent, puis l'owner distribue l'ETH à tous en une transaction.
contract VulnerableAirdrop {
    address public owner;
    bool public distributed;
    address[] public participants;

    constructor() {
        owner = msg.sender;
    }

    function fund() external payable {}

    // BUG 1 : ni plafond ni dédoublonnage, n'importe qui peut remplir le tableau à volonté
    function register() external {
        participants.push(msg.sender);
    }

    function participantsCount() external view returns (uint256) {
        return participants.length;
    }

    function distribute() external {
        require(msg.sender == owner, "Reserve a l'owner");
        require(!distributed, "Deja distribue");
        uint256 n = participants.length;
        require(n > 0, "Aucun participant");

        distributed = true;
        uint256 share = address(this).balance / n;

        // BUG 2 : boucle NON BORNÉE, dont le coût croît avec le nombre de participants
        // BUG 3 : un seul destinataire qui refuse l'ETH fait échouer toute la distribution
        for (uint256 i = 0; i < n; i++) {
            (bool ok,) = participants[i].call{value: share}("");
            require(ok, "Envoi echoue");
        }
    }
}
