// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// VOLONTAIREMENT VULNERABLE : usage pedagogique uniquement
contract SignatureReplayVault {
    address public immutable signer;

    constructor(address _signer) payable {
        signer = _signer;
    }

    function withdrawWithSignature(
        address payable to,
        uint256 amount,
        bytes calldata signature
    ) external {
        // Le message signe ne contient que (to, amount) : FAILLE
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        require(_recover(ethHash, signature) == signer, "bad signature");

        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function _recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(h, v, r, s);
    }

    receive() external payable {}
}
