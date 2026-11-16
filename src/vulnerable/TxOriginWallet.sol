// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// VOLONTAIREMENT VULNERABLE : usage pedagogique uniquement
contract TxOriginWallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    function transferTo(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner"); // FAILLE ICI
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
