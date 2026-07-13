#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

CERT_FILE=${1}
KEY_FILE=${CERT_FILE%.*}.key
CERT_DIR=../certs
URL=https://localhost:8043/prpc/KMS.GetAppKey

if [ -z "$CERT_FILE" ]; then
    curl -s --cacert ${CERT_DIR}/ca.cert ${URL}
else
    curl -vv --cacert ${CERT_DIR}/ca.cert --cert ${CERT_FILE} --key ${KEY_FILE} ${URL}
fi
