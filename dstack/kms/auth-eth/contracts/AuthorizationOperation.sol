// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.24;

/// The operation is performed by the attested subject, not the policy caller.
library AuthorizationOperation {
    bytes32 internal constant KMS_BOOTSTRAP = keccak256("kms_bootstrap");
    bytes32 internal constant KMS_SERVE = keccak256("kms_serve");
    bytes32 internal constant KMS_EXPORT_KEYS = keccak256("kms_export_keys");
    bytes32 internal constant KMS_IMPORT_KEYS = keccak256("kms_import_keys");
    bytes32 internal constant APP_GET_KEY = keccak256("app_get_key");
    bytes32 internal constant APP_GET_CERT = keccak256("app_get_cert");

    function isKms(bytes32 operation) internal pure returns (bool) {
        return operation == KMS_BOOTSTRAP || operation == KMS_SERVE || operation == KMS_EXPORT_KEYS
            || operation == KMS_IMPORT_KEYS;
    }

    function isApp(bytes32 operation) internal pure returns (bool) {
        return operation == APP_GET_KEY || operation == APP_GET_CERT;
    }
}
