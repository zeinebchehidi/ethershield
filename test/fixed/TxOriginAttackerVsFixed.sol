// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TxOriginWalletFixed} from "../../src/fixed/TxOriginWalletFixed.sol";

// MEME attaque que TxOriginAttacker, mais contre la version corrigee
contract TxOriginAttackerVsFixed {
    TxOriginWalletFixed public immutable wallet;
    address payable public immutable attacker;

    constructor(TxOriginWalletFixed _wallet) {
        wallet = _wallet;
        attacker = payable(msg.sender);
    }

    function claimAirdrop() external {
        wallet.transferTo(attacker, address(wallet).balance);
    }
}
