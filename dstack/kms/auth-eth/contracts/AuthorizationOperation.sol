// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.24;

/// The operation is performed by the attested subject, not the policy caller.
library AuthorizationOperation {
    bytes32 internal constant BOOTSTRAP = keccak256("bootstrap");
    bytes32 internal constant SERVE = keccak256("serve");
    bytes32 internal constant EXPORT_KMS_KEYS = keccak256("export_kms_keys");
    bytes32 internal constant IMPORT_KMS_KEYS = keccak256("import_kms_keys");
    bytes32 internal constant GET_APP_KEY = keccak256("get_app_key");
    bytes32 internal constant SIGN_CERT = keccak256("sign_cert");

    function isKms(bytes32 operation) internal pure returns (bool) {
        return
            operation == BOOTSTRAP || operation == SERVE || operation == EXPORT_KMS_KEYS || operation == IMPORT_KMS_KEYS;
    }

    function isApp(bytes32 operation) internal pure returns (bool) {
        return operation == GET_APP_KEY || operation == SIGN_CERT;
    }
}
