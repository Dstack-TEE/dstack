/*
 * SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

pragma solidity ^0.8.24;

abstract contract RootKeyFixtures {
    // Well-formed root public keys whose point bytes are all `fill`; shared with
    // the off-chain implementations' tests.
    function ca(uint8 fill) internal pure returns (bytes memory key) {
        key = bytes.concat(hex"3059301306072a8648ce3d020106082a8648ce3d03010703420004", new bytes(64));
        for (uint256 i = 27; i < 91; i++) {
            key[i] = bytes1(fill);
        }
    }

    function k256(uint8 fill) internal pure returns (bytes memory key) {
        key = new bytes(33);
        key[0] = 0x02;
        for (uint256 i = 1; i < 33; i++) {
            key[i] = bytes1(fill);
        }
    }
}
