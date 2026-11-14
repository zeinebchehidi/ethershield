// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// VERSION CORRIGEE de TxOriginWallet
contract TxOriginWalletFixed is Ownable {
    constructor() payable Ownable(msg.sender) {}

    function transferTo(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero address");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
