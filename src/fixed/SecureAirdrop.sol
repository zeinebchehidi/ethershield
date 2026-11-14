// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// Correctif : plus aucune boucle sur les participants. Chacun réclame sa part (pull payment),
/// l'inscription est dédoublonnée et plafonnée.
contract SecureAirdrop is ReentrancyGuard {
    uint256 public constant MAX_PARTICIPANTS = 1_000;

    address public immutable owner;
    uint256 public participantCount;
    uint256 public sharePerParticipant;
    bool public claimsOpen;

    mapping(address => bool) public registered;
    mapping(address => bool) public claimed;

    event Registered(address indexed participant);
    event ClaimsOpened(uint256 share, uint256 participants);
    event Claimed(address indexed participant, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function fund() external payable {
        require(!claimsOpen, "Reclamations ouvertes");
    }

    function register() external {
        require(!claimsOpen, "Inscriptions closes");
        require(!registered[msg.sender], "Deja inscrit");
        require(participantCount < MAX_PARTICIPANTS, "Complet");

        registered[msg.sender] = true;
        participantCount++;
        emit Registered(msg.sender);
    }

    /// Fige la part de chacun : plus de dépendance à address(this).balance après ce point
    function openClaims() external {
        require(msg.sender == owner, "Reserve a l'owner");
        require(!claimsOpen, "Deja ouvert");
        require(participantCount > 0, "Aucun participant");

        claimsOpen = true;
        sharePerParticipant = address(this).balance / participantCount;
        emit ClaimsOpened(sharePerParticipant, participantCount);
    }

    function claim() external nonReentrant {
        require(claimsOpen, "Reclamations fermees");
        require(registered[msg.sender], "Non inscrit");
        require(!claimed[msg.sender], "Deja reclame");

        claimed[msg.sender] = true;
        uint256 amount = sharePerParticipant;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfert echoue");
        emit Claimed(msg.sender, amount);
    }
}
