# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

package policy

import future.keywords.every

default nv_match := false

nv_match {
    count(input) > 0
    every claim in input {
        claim["x-nvidia-device-type"] == "gpu"
        claim.measres == "success"
        claim.secboot == true
        claim.dbgstat == "disabled"
        valid_cert_chain(claim["x-nvidia-gpu-attestation-report-cert-chain"])
        valid_cert_chain(claim["x-nvidia-gpu-driver-rim-cert-chain"])
        valid_cert_chain(claim["x-nvidia-gpu-vbios-rim-cert-chain"])
    }
}

valid_cert_chain(cert_chain) {
    cert_chain["x-nvidia-cert-status"] == "valid"
    cert_chain["x-nvidia-cert-ocsp-status"] == "good"
    cert_chain["x-nvidia-cert-ocsp-nonce-matches"] == true
    cert_chain["x-nvidia-cert-ocsp-response-valid"] == true
}
