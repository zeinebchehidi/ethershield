// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// VERSION CORRIGEE de SignatureReplayVault
contract SignatureReplayVaultFixed is EIP712 {
    bytes32 private constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address to,uint256 amount,uint256 nonce,uint256 deadline)");

    address public immutable signer;
    uint256 public nonce;

    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);

    constructor(address _signer) payable EIP712("SignatureReplayVault", "1") {
        require(_signer != address(0), "zero signer");
        signer = _signer;
    }

    function withdrawWithSignature(
        address payable to,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(to != address(0), "zero address");
        require(block.timestamp <= deadline, "signature expired");

        uint256 currentNonce = nonce;
        bytes32 structHash = keccak256(
            abi.encode(WITHDRAW_TYPEHASH, to, amount, currentNonce, deadline)
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        require(ECDSA.recover(digest, signature) == signer, "bad signature");

        nonce = currentNonce + 1; // consomme le nonce AVANT l'envoi

        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(to, amount, currentNonce);
    }

    receive() external payable {}
}
