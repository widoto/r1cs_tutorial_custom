// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;

library LibGroth16AltBN128 {
    // BN128 에서는 G1이 2개의 uint256로 구성되어 있고, G2는 4개의 uint256로 구성되어 있다.
    // 참고자료 : https://github.com/clearmatics/zeth/blob/master/zeth_contracts/contracts/LibGroth16AltBN128.sol

    // VerifyingKey :
    //      uint256[2] alpha    : G_1
    //      uint256[4] beta     : G_2 (minus)
    //      uint256[4] delta    : G_2 (minus)
    //      uint256[4] gamma    : G_2 (minus)
    //      uint256[ ] gamma_abc: G_1 (for public inputs: [1, ... PI])

    // Proof :
    //      uint256[2] A    : G_1
    //      uint256[4] B    : G_2
    //      uint256[2] C    : G_1
    //      uint256[2] D    : G_1

    // Verification equation:
    //      A*B = alpha*beta + C*dela + D*gamma
    //      A*B - alpha*beta - C*dela - D*gamma = 0

    uint256 internal constant _GENERAL_VK_LENGTH = 16;
    uint256 internal constant _PROOF_LENGTH = 8;
    uint256 internal constant _INPUT_VK_LENGTH = 2;

    function _verify(
        uint256[] storage vk,
        uint256[] memory proof,
        uint256[] memory inputs
    ) internal returns (bool) {
        require(proof.length == _PROOF_LENGTH, "Invalid proof length");
        require(
            vk.length == _GENERAL_VK_LENGTH + _INPUT_VK_LENGTH * inputs.length,
            "Invalid vk length"
        );

        uint256 vk_slot_num; // vk slot
        uint256[24] memory io; // bn256Add, bn256Pairing io
        bool success = true;

        assembly {
            let g := sub(gas(), 2000)
            // 배열 첫번째 원소에는 배열의 길이가 담겨져 있음
            // 즉, proof의 첫번째 word에는 길이가 존재
            let proof_i := add(proof, 0x20) // proof[0]의 주소

            mstore(io, vk.slot) // slot은 상태 변수의 idx를 뜻함
            vk_slot_num := keccak256(io, 0x20)
            let abc_slot_num := add(vk_slot_num, 14)

            // Initialize io with gamma_abc for 'one'
            mstore(io, sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)
            mstore(add(io, 0x20), sload(abc_slot_num))
            abc_slot_num := add(abc_slot_num, 1)

            // Iterate over all public input / gamma_abc values
            for {
                let input_i := add(inputs, 0x20) // address of inputs[0]
                let input_end := add(input_i, shl(0x05, mload(inputs)))
                // Location within io to do scalar mul operation
                let io_mul := add(io, 0x40)
            } lt(input_i, input_end) {
                input_i := add(input_i, 0x20)
            } {
                // Copy abc[i+1] into io_mul, incrementing abc_slot_num
                mstore(io_mul, sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)
                mstore(add(io_mul, 0x20), sload(abc_slot_num))
                abc_slot_num := add(abc_slot_num, 1)

                // Copy input[i] into io_mul + 0x40, and increment index_i
                mstore(add(io_mul, 0x40), mload(input_i))

                // bn256ScalarMul and bn256Add can be done with no copying
                let s1 := staticcall(g, 0x07, io_mul, 0x60, io_mul, 0x40)
                let s2 := staticcall(g, 0x06, io, 0x80, io, 0x40)
                success := and(success, and(s1, s2))
            }

            //mstore(add(io, 0x40), mload(add(proof_i, 0x100))) // proof[8]을 io[0]에 저장
            //mstore(add(io, 0x60), mload(add(proof_i, 0x120))) // proof[9]을 io[1]에 저장
            // calculate PI + proof.D and store it in io[18] ~ io[21]
            // success := and(
            //     success,
            //     call(
            //         gas(),
            //         0x06,
            //         0,
            //         io,
            //         0x80,
            //         add(io, 0x240), // io[18]
            //         0x40
            //     )
            // )
            mstore(add(io, 0x240), mload(io))
            mstore(add(io, 0x260), mload(add(io, 0x20)))
        }
        require(success, "bn256ops fail");

        // input 0x0000 ~ 0x0040 : A
        // input 0x0040 ~ 0x00c0 : B
        // input 0x00c0 ~ 0x0100 : alpha_g1
        // input 0x0100 ~ 0x0180 : minus_beta_g2
        // input 0x0180 ~ 0x01c0 : C
        // input 0x01c0 ~ 0x0240 : minus_delta_g2
        // input 0x0240 ~ 0x0280 : D
        // input 0x0280 ~ 0x0300 : minus_gamma_g2
        assembly {
            let proof_i := add(proof, 0x20)

            // input 0x0000 ~ 0x0040 : A
            // input 0x0040 ~ 0x00c0 : B
            mstore(io, mload(proof_i)) // A.X
            mstore(add(io, 0x20), mload(add(proof_i, 0x20))) // A.Y
            mstore(add(io, 0x40), mload(add(proof_i, 0x40))) // B.X1
            mstore(add(io, 0x60), mload(add(proof_i, 0x60))) // B.Y2
            mstore(add(io, 0x80), mload(add(proof_i, 0x80))) // B.Y3
            mstore(add(io, 0xa0), mload(add(proof_i, 0xa0))) // B.Y4

            // input 0x00c0 ~ 0x0100 : alpha_g1
            // input 0x0100 ~ 0x0180 : minus_beta_g2
            mstore(add(io, 0xc0), sload(vk_slot_num))
            mstore(add(io, 0xe0), sload(add(vk_slot_num, 1)))
            mstore(add(io, 0x100), sload(add(vk_slot_num, 2)))
            mstore(add(io, 0x120), sload(add(vk_slot_num, 3)))
            mstore(add(io, 0x140), sload(add(vk_slot_num, 4)))
            mstore(add(io, 0x160), sload(add(vk_slot_num, 5)))

            // input 0x0180 ~ 0x01c0 : C
            // input 0x01c0 ~ 0x0240 : minus_delta_g2
            mstore(add(io, 0x180), mload(add(proof_i, 0xc0)))
            mstore(add(io, 0x1a0), mload(add(proof_i, 0xe0)))
            mstore(add(io, 0x1c0), sload(add(vk_slot_num, 6)))
            mstore(add(io, 0x1e0), sload(add(vk_slot_num, 7)))
            mstore(add(io, 0x200), sload(add(vk_slot_num, 8)))
            mstore(add(io, 0x220), sload(add(vk_slot_num, 9)))

            // input 0x0280 ~ 0x0300 : minus_gamma_g2
            mstore(add(io, 0x280), sload(add(vk_slot_num, 10)))
            mstore(add(io, 0x2a0), sload(add(vk_slot_num, 11)))
            mstore(add(io, 0x2c0), sload(add(vk_slot_num, 12)))
            mstore(add(io, 0x2e0), sload(add(vk_slot_num, 13)))

            // verify io
            success := and(
                success,
                call(sub(gas(), 2000), 0x08, 0, io, 0x300, io, 0x20)
            )
        }
        require(success, "bn256Pairing fail");
        return io[0] == 1; // success should be 1, io[0] should be 1
    }
}
