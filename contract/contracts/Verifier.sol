// SPDX-License-Identifier: LGPL-3.0+
pragma solidity ^0.8.0;

import "./LibGroth16AltBN128.sol"; // library import

contract Verifier {
    uint256[] private _vk;

    // verify groth16 proof
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

    // verify ecdsa signature
    function verifySignature(
        string memory message,
        uint8 v,
        bytes32 r,
        bytes32 s,
        address expectedSigner // pk
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(message);
        address recoveredSigner = ecrecover(messageHash, v, r, s);
        return (recoveredSigner == expectedSigner);
    }

    function getMessageHash(
        string memory message
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n",
                    uint2str(bytes(message).length),
                    message
                )
            );
    }

    // uint256 to string
    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) return "0";
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        while (_i != 0) {
            length -= 1;
            bstr[length] = bytes1(uint8(48 + (_i % 10)));
            _i /= 10;
        }
        return string(bstr);
    }
}
