// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SignatureReplayVaultFixed} from "../../src/fixed/SignatureReplayVaultFixed.sol";

contract SignatureReplayFixedTest is Test {
    SignatureReplayVaultFixed vault;

    address signer;
    uint256 signerKey;
    address bob = makeAddr("bob");

    bytes32 constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address to,uint256 amount,uint256 nonce,uint256 deadline)");

    function setUp() public {
        (signer, signerKey) = makeAddrAndKey("signer");
        vault = new SignatureReplayVaultFixed{value: 5 ether}(signer);
    }

    // Construit la signature EIP-712 pour un vault donne
    function _digest(
        SignatureReplayVaultFixed v,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(WITHDRAW_TYPEHASH, to, amount, nonce, deadline)
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("SignatureReplayVault")),
                keccak256(bytes("1")),
                block.chainid,
                address(v)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _sign(
        uint256 key,
        SignatureReplayVaultFixed v,
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(key, _digest(v, to, amount, nonce, deadline));
        return abi.encodePacked(r, s, vv);
    }

    // 1. NON-REGRESSION
    function test_LegitWithdrawWorks() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, vault, bob, 1 ether, 0, deadline);

        vault.withdrawWithSignature(payable(bob), 1 ether, deadline, sig);

        assertEq(bob.balance, 1 ether);
        assertEq(address(vault).balance, 4 ether);
        assertEq(vault.nonce(), 1);
    }

    // 2. PROTECTION : le rejeu est bloque
    function test_ProtectionHolds_ReplayBlocked() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, vault, bob, 1 ether, 0, deadline);

        vault.withdrawWithSignature(payable(bob), 1 ether, deadline, sig);

        vm.expectRevert(bytes("bad signature"));
        vault.withdrawWithSignature(payable(bob), 1 ether, deadline, sig);

        assertEq(bob.balance, 1 ether);
        assertEq(address(vault).balance, 4 ether);
    }

    // 3. Expiration
    function test_ExpiredSignatureRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, vault, bob, 1 ether, 0, deadline);

        vm.warp(deadline + 1);
        vm.expectRevert(bytes("signature expired"));
        vault.withdrawWithSignature(payable(bob), 1 ether, deadline, sig);
    }

    // 4. Mauvais signataire
    function test_WrongSignerRejected() public {
        (, uint256 otherKey) = makeAddrAndKey("attacker");
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(otherKey, vault, bob, 1 ether, 0, deadline);

        vm.expectRevert(bytes("bad signature"));
        vault.withdrawWithSignature(payable(bob), 1 ether, deadline, sig);
    }

    // 5. Montant modifie apres signature
    function test_TamperedAmountRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(signerKey, vault, bob, 1 ether, 0, deadline);

        vm.expectRevert(bytes("bad signature"));
        vault.withdrawWithSignature(payable(bob), 5 ether, deadline, sig);
    }

    // 6. Malleabilite : forme alternative (s haut, v inverse) refusee
    function test_MalleableSignatureRejected() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _digest(vault, bob, 1 ether, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);

        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 sHigh = bytes32(n - uint256(s));
        uint8 vFlipped = v == 27 ? 28 : 27;
        bytes memory malleable = abi.encodePacked(r, sHigh, vFlipped);

        vm.expectRevert(); // ECDSAInvalidSignatureS
        vault.withdrawWithSignature(payable(bob), 1 ether, deadline, malleable);
    }

    // 7. Separation de domaine : signature d'un autre vault
    function test_CrossContractReplayBlocked() public {
        SignatureReplayVaultFixed other = new SignatureReplayVaultFixed{value: 5 ether}(signer);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sigForOther = _sign(signerKey, other, bob, 1 ether, 0, deadline);

        vm.expectRevert(bytes("bad signature"));
        vault.withdrawWithSignature(payable(bob), 1 ether, deadline, sigForOther);
    }

    // 8. Signer nul refuse
    function test_ZeroSignerRejected() public {
        vm.expectRevert(bytes("zero signer"));
        new SignatureReplayVaultFixed(address(0));
    }
}
