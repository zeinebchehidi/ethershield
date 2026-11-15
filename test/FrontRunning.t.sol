// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {VulnerableReward} from "../src/vulnerable/VulnerableReward.sol";

contract FrontRunningTest is Test {
    VulnerableReward reward;

    address alice = makeAddr("alice");     // la gagnante légitime
    address mallory = makeAddr("mallory"); // l'attaquante

    string constant ANSWER = "ethershield";
    uint256 constant PRIZE = 10 ether;

    function setUp() public {
        reward = new VulnerableReward{value: PRIZE}(keccak256(bytes(ANSWER)));
    }

    // Référence : si Alice passe en premier, elle gagne.
    function test_Baseline_AliceWinsWhenFirst() public {
        vm.prank(alice);
        reward.claim(ANSWER);

        assertEq(alice.balance, PRIZE);
    }

    // Exploit : Mallory copie la réponse et passe avant Alice.
    function test_Exploit_MalloryFrontRunsAlice() public {
        // Mallory a copié la réponse dans le mempool, sa transaction est minée d'abord.
        vm.prank(mallory);
        reward.claim(ANSWER);

        // La transaction d'Alice arrive trop tard.
        vm.prank(alice);
        vm.expectRevert("Already claimed");
        reward.claim(ANSWER);

        assertEq(mallory.balance, PRIZE); // Mallory a volé la récompense
        assertEq(alice.balance, 0);       // Alice n'a rien reçu
    }
}