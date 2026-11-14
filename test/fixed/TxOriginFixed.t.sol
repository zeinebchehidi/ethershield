// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TxOriginWalletFixed} from "../../src/fixed/TxOriginWalletFixed.sol";
import {TxOriginAttackerVsFixed} from "./TxOriginAttackerVsFixed.sol";

contract TxOriginFixedTest is Test {
    TxOriginWalletFixed wallet;
    TxOriginAttackerVsFixed attackerContract;

    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);

        vm.prank(victim);
        wallet = new TxOriginWalletFixed{value: 5 ether}();

        vm.prank(attacker);
        attackerContract = new TxOriginAttackerVsFixed(wallet);
    }

    // 1. PROTECTION : la meme attaque de phishing est maintenant bloquee
    function test_ProtectionHolds_PhishingBlocked() public {
        vm.prank(victim, victim); // msg.sender = victim ET tx.origin = victim
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                address(attackerContract)
            )
        );
        attackerContract.claimAirdrop();

        assertEq(address(wallet).balance, 5 ether); // fonds intacts
        assertEq(attacker.balance, 1 ether);        // l'attaquant n'a rien gagne
    }

    // 2. NON-REGRESSION : le proprietaire peut toujours utiliser son wallet
    function test_OwnerCanStillTransfer() public {
        address recipient = makeAddr("recipient");

        vm.prank(victim);
        wallet.transferTo(payable(recipient), 2 ether);

        assertEq(recipient.balance, 2 ether);
        assertEq(address(wallet).balance, 3 ether);
    }

    // 3. Correction du finding missing-zero-check
    function test_ZeroAddressRejected() public {
        vm.prank(victim);
        vm.expectRevert(bytes("zero address"));
        wallet.transferTo(payable(address(0)), 1 ether);
    }
}
