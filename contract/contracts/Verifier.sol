// SPDX-License-Identifier: LGPL-3.0+
pragma solidity ^0.8.0;

import "./LibGroth16AltBN128.sol"; // 기존 라이브러리 import

contract Verifier {
    uint256[] private _vk;

    function verifyProof(
        uint256[] memory vk,
        uint256[] memory proof,
        uint256[] memory input
    ) public returns (bool) {
        _vk = vk;
        require(
            LibGroth16AltBN128._verify(_vk, proof, input),
            "verify is failed"
        );
        return true;
    }
}
