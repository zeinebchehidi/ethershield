// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/vulnerable/VulnerableBank.sol";
import "../src/fixed/SecureBank.sol";

contract Attacker {
    VulnerableBank public bank;

    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }

    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();
        }
    }
}

contract ReentrancyTest is Test {
    VulnerableBank bank;
    Attacker attacker;

    function setUp() public {
        bank = new VulnerableBank();
        address victim = makeAddr("victim");
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        bank.deposit{value: 10 ether}();

        attacker = new Attacker(address(bank));
    }

    function test_ReentrancyDrainsBank() public {
        vm.deal(address(this), 1 ether);
        attacker.attack{value: 1 ether}();

        assertEq(address(bank).balance, 0, "La banque doit etre videe");
        assertEq(address(attacker).balance, 11 ether, "L'attaquant a vole 10 ether");
    }

    function test_SecureBankBlocksReentrancy() public {
        SecureBank secure = new SecureBank();
        address victim = makeAddr("victim2");
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        secure.deposit{value: 10 ether}();

        Attacker attackerOnSecure = new Attacker(address(secure));

        vm.deal(address(this), 1 ether);
        vm.expectRevert();
        attackerOnSecure.attack{value: 1 ether}();

        assertEq(address(secure).balance, 10 ether);
    }

    function test_SecureBankLegitWithdrawStillWorks() public {
        SecureBank secure = new SecureBank();
        address user = makeAddr("user");
        vm.deal(user, 2 ether);

        vm.startPrank(user);
        secure.deposit{value: 2 ether}();
        secure.withdraw();
        vm.stopPrank();

        assertEq(user.balance, 2 ether);
        assertEq(secure.balances(user), 0);
    }
}
