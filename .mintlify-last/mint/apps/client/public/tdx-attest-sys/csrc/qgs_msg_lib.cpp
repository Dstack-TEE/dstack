/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "qgs_msg_lib.h"

#include <stdlib.h>
#include <string.h>

const uint32_t QGS_MSG_LIB_MAJOR_VER = 1;
const uint32_t QGS_MSG_LIB_MINOR_VER = 1;

void qgs_msg_free(void *p_buf) {
    free(p_buf);
}

/**
 * @brief Generate serialized get_quote request
 *
 * @param p_report  Cannot be NULL
 * @param report_size Cannot be 0
 * @param p_id_list Can be NULL
 * @param id_list_size Can be 0
 * @param pp_req returned serialized buffer, valid only if the return code is QGS_MSG_SUCCESS
 * @param p_req_size return size of the serialized buffer, valid only if the return code is QGS_MSG_SUCCESS
 * @return qgs_msg_error_t
 */
qgs_msg_error_t qgs_msg_gen_get_quote_req(
    const uint8_t *p_report, uint32_t report_size,
    const uint8_t *p_id_list, uint32_t id_list_size,
    uint8_t **pp_req, uint32_t *p_req_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_quote_req_t *p_req = NULL;
    uint32_t buf_size = 0;
    uint64_t temp = 0;

    if (!p_report || !report_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if ((!p_id_list && id_list_size) || (p_id_list && !id_list_size)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_req || !p_req_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    temp = sizeof(*p_req);
    temp += report_size;
    temp += id_list_size;
    if (temp < UINT32_MAX) {
        buf_size = temp & UINT32_MAX;
    } else {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    p_req = (qgs_msg_get_quote_req_t *)calloc(buf_size, sizeof(uint8_t));
    if (!p_req) {
        ret = QGS_MSG_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    p_req->header.major_version = QGS_MSG_LIB_MAJOR_VER;
    p_req->header.minor_version = QGS_MSG_LIB_MINOR_VER;
    p_req->header.type = GET_QUOTE_REQ;
    p_req->header.size = buf_size;
    p_req->header.error_code = 0;

    p_req->report_size = report_size;
    p_req->id_list_size = id_list_size;
    memcpy(p_req->report_id_list, p_report, report_size);
    if (id_list_size) {
        memcpy(p_req->report_id_list + report_size, p_id_list, id_list_size);
    }
    *pp_req = (uint8_t *)p_req;
    *p_req_size = buf_size;
    ret = QGS_MSG_SUCCESS;

ret_point :
    return ret;
}

/**
 * @brief Generate serialized get_collateral request
 *
 * @param p_fsmpc Cannot be NULL
 * @param fsmpc_size Cannot be 0
 * @param p_pckca Cannot be NULL
 * @param pckca_size Cannot be 0
 * @param pp_req returned serialized buffer, valid only if the return code is QGS_MSG_SUCCESS
 * @param p_req_size return size of the serialized buffer, valid only if the return code is QGS_MSG_SUCCESS
 * @return qgs_msg_error_t
 */
qgs_msg_error_t qgs_msg_gen_get_collateral_req(
    const uint8_t *p_fsmpc, uint32_t fsmpc_size,
    const uint8_t *p_pckca, uint32_t pckca_size,
    uint8_t **pp_req, uint32_t *p_req_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_collateral_req_t *p_req = NULL;
    uint32_t buf_size = 0;
    uint64_t temp = 0;

    if (!p_fsmpc || !fsmpc_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!p_pckca || !pckca_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_req || !p_req_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    temp = sizeof(*p_req);
    temp += fsmpc_size;
    temp += pckca_size;
    if (temp < UINT32_MAX) {
        buf_size = temp & UINT32_MAX;
    } else {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    p_req = (qgs_msg_get_collateral_req_t *)calloc(buf_size, sizeof(uint8_t));
    if (!p_req) {
        ret = QGS_MSG_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    p_req->header.major_version = QGS_MSG_LIB_MAJOR_VER;
    p_req->header.minor_version = QGS_MSG_LIB_MINOR_VER;
    p_req->header.type = GET_COLLATERAL_REQ;
    p_req->header.size = buf_size;
    p_req->header.error_code = 0;

    p_req->fsmpc_size = fsmpc_size;
    p_req->pckca_size = pckca_size;
    memcpy(p_req->fsmpc_pckca, p_fsmpc, fsmpc_size);
    memcpy(p_req->fsmpc_pckca + fsmpc_size, p_pckca, pckca_size);

    *pp_req = (uint8_t *)p_req;
    *p_req_size = buf_size;
    ret = QGS_MSG_SUCCESS;

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_inflate_get_quote_req(
    const uint8_t *p_serialized_req, uint32_t size,
    const uint8_t **pp_report, uint32_t *p_report_size,
    const uint8_t **pp_id_list, uint32_t *p_id_list_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_quote_req_t *p_req = NULL;
    uint64_t temp = 0;

    if (!p_serialized_req || !size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_report || !p_report_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_id_list || !p_id_list_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    // sanity check, the size shouldn't smaller than qgs_msg_get_quote_req_t
    if (size < sizeof(qgs_msg_get_quote_req_t)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_req = (qgs_msg_get_quote_req_t *)p_serialized_req;
    // Only major version is checked, minor change is deemed as compatible.
    if (p_req->header.major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }

    if (p_req->header.type != GET_QUOTE_REQ) {
        ret = QGS_MSG_ERROR_INVALID_TYPE;
        goto ret_point;
    }

    if (p_req->header.size != size) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    if (p_req->header.error_code != 0) {
        ret = QGS_MSG_ERROR_INVALID_CODE;
        goto ret_point;
    }

    if (!p_req->report_size) {
        ret = QGS_MSG_ERROR_INVALID_CODE;
        goto ret_point;
    }

    temp = sizeof(qgs_msg_get_quote_req_t);
    temp += p_req->report_size;
    temp += p_req->id_list_size;
    if (temp >= UINT32_MAX) {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    if (p_req->header.size != temp) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    *pp_report = p_req->report_id_list;
    if (p_req->id_list_size) {
        *pp_id_list = p_req->report_id_list + p_req->report_size;
    } else {
        *pp_id_list = NULL;
    }

    *p_report_size = p_req->report_size;
    *p_id_list_size = p_req->id_list_size;

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_inflate_get_collateral_req(
    const uint8_t *p_serialized_req, uint32_t size,
    const uint8_t **pp_fsmpc, uint32_t *p_fsmpc_size,
    const uint8_t **pp_pckca, uint32_t *p_pckca_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_collateral_req_t *p_req = NULL;
    uint64_t temp = 0;

    if (!p_serialized_req || !size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_fsmpc || !p_fsmpc_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_pckca || !p_pckca_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    // sanity check, the size shouldn't smaller than qgs_msg_get_quote_req_t
    if (size < sizeof(qgs_msg_get_collateral_req_t)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_req = (qgs_msg_get_collateral_req_t *)p_serialized_req;
    // Only major version is checked, minor change is deemed as compatible.
    if (p_req->header.major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }

    if (p_req->header.type != GET_COLLATERAL_REQ) {
        ret = QGS_MSG_ERROR_INVALID_TYPE;
        goto ret_point;
    }

    if (p_req->header.size != size) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    if (p_req->header.error_code != 0) {
        ret = QGS_MSG_ERROR_INVALID_CODE;
        goto ret_point;
    }

    if (!p_req->fsmpc_size || !p_req->pckca_size) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    temp = sizeof(qgs_msg_get_collateral_req_t);
    temp += p_req->fsmpc_size;
    temp += p_req->pckca_size;
    if (temp >= UINT32_MAX) {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    if (p_req->header.size != temp) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    *pp_fsmpc = p_req->fsmpc_pckca;
    *pp_pckca = p_req->fsmpc_pckca + p_req->fsmpc_size;

    *p_fsmpc_size = p_req->fsmpc_size;
    *p_pckca_size = p_req->pckca_size;

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_gen_error_resp(
    uint32_t error_code, uint32_t type,
    uint8_t **pp_resp, uint32_t *p_resp_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    uint32_t buf_size = 0;
    qgs_msg_header_t *p_resp = NULL;
    if (error_code == QGS_MSG_SUCCESS) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_resp || !p_resp_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    switch (type) {
    case GET_QUOTE_RESP:
        buf_size = sizeof(qgs_msg_get_quote_resp_t);
        break;
    case GET_COLLATERAL_RESP:
        buf_size = sizeof(qgs_msg_get_collateral_resp_t);
        break;
    case GET_PLATFORM_INFO_RESP:
        buf_size = sizeof(qgs_msg_get_platform_info_resp_t);
        break;
    default:
        ret = QGS_MSG_ERROR_INVALID_TYPE;
        goto ret_point;
    }
    p_resp = (qgs_msg_header_t *)calloc(buf_size, sizeof(uint8_t));
    if (!p_resp) {
        ret = QGS_MSG_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    p_resp->major_version = QGS_MSG_LIB_MAJOR_VER;
    p_resp->minor_version = QGS_MSG_LIB_MINOR_VER;
    p_resp->type = type;
    p_resp->size = buf_size;
    p_resp->error_code = error_code;

    *pp_resp = (uint8_t *)p_resp;
    *p_resp_size = buf_size;
    ret = QGS_MSG_SUCCESS;

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_gen_get_quote_resp(
    const uint8_t *p_selected_id, uint32_t id_size,
    const uint8_t *p_quote, uint32_t quote_size,
    uint8_t **pp_resp, uint32_t *p_resp_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_quote_resp_t *p_resp = NULL;
    uint32_t buf_size = 0;
    uint64_t temp = 0;

    if (!pp_resp || !p_resp_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if ((!p_selected_id && id_size) || (p_selected_id && !id_size)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!p_quote || !quote_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    temp = sizeof(*p_resp);
    temp += id_size;
    temp += quote_size;
    if (temp < UINT32_MAX) {
        buf_size = temp & UINT32_MAX;
    } else {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    p_resp = (qgs_msg_get_quote_resp_t *)calloc(buf_size, sizeof(uint8_t));
    if (!p_resp) {
        ret = QGS_MSG_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    p_resp->header.major_version = QGS_MSG_LIB_MAJOR_VER;
    p_resp->header.minor_version = QGS_MSG_LIB_MINOR_VER;
    p_resp->header.type = GET_QUOTE_RESP;
    p_resp->header.size = buf_size;
    p_resp->header.error_code = QGS_MSG_SUCCESS;

    p_resp->selected_id_size = id_size;
    p_resp->quote_size = quote_size;
    if (id_size) {
        memcpy(p_resp->id_quote, p_selected_id, id_size);
    }
    memcpy(p_resp->id_quote + id_size, p_quote, quote_size);

    *pp_resp = (uint8_t *)p_resp;
    *p_resp_size = buf_size;
    ret = QGS_MSG_SUCCESS;

ret_point :
    return ret;
}

qgs_msg_error_t qgs_msg_gen_get_collateral_resp(
    uint16_t major_version, uint16_t minor_version,
    const uint8_t *p_pck_crl_issuer_chain, uint32_t pck_crl_issuer_chain_size,
    const uint8_t *p_root_ca_crl, uint32_t root_ca_crl_size,
    const uint8_t *p_pck_crl, uint32_t pck_crl_size,
    const uint8_t *p_tcb_info_issuer_chain, uint32_t tcb_info_issuer_chain_size,
    const uint8_t *p_tcb_info, uint32_t tcb_info_size,
    const uint8_t *p_qe_identity_issuer_chain, uint32_t qe_identity_issuer_chain_size,
    const uint8_t *p_qe_identity, uint32_t qe_identity_size,
    uint8_t **pp_resp, uint32_t *p_resp_size,
    const qgs_msg_header_t *p_req_header) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_collateral_resp_t *p_resp = NULL;
    uint8_t *p_ptr = NULL;
    uint32_t buf_size = 0;
    uint64_t temp = 0;

    if (!pp_resp || !p_resp_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    //TODO major_version and minor_version are ignored here, is 0.0 a valid version?
    if (!p_pck_crl_issuer_chain || !pck_crl_issuer_chain_size
        || !p_root_ca_crl || !root_ca_crl_size
        || !p_pck_crl || !pck_crl_size
        || !p_tcb_info_issuer_chain || !tcb_info_issuer_chain_size
        || !p_tcb_info || !tcb_info_size
        || !p_qe_identity_issuer_chain || !qe_identity_issuer_chain_size
        || !p_qe_identity || !qe_identity_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (p_req_header->major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }
    if (p_req_header->minor_version == 0) {
        temp = sizeof(major_version) + sizeof(minor_version) + sizeof(*p_resp);
    } else {
        temp = sizeof(*p_resp);
    }
    temp += pck_crl_issuer_chain_size;
    temp += root_ca_crl_size;
    temp += pck_crl_size;
    temp += tcb_info_issuer_chain_size;
    temp += tcb_info_size;
    temp += qe_identity_issuer_chain_size;
    temp += qe_identity_size;

    if (temp < UINT32_MAX) {
        buf_size = temp & UINT32_MAX;
    } else {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    p_resp = (qgs_msg_get_collateral_resp_t *)calloc(buf_size, sizeof(uint8_t));
    if (!p_resp) {
        ret = QGS_MSG_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    p_resp->header.major_version = QGS_MSG_LIB_MAJOR_VER;
    p_resp->header.minor_version = QGS_MSG_LIB_MINOR_VER;
    p_resp->header.type = GET_COLLATERAL_RESP;
    p_resp->header.size = buf_size;
    p_resp->header.error_code = QGS_MSG_SUCCESS;

    p_resp->major_version = major_version;
    p_resp->minor_version = minor_version;
    p_ptr = p_resp->collaterals;
    if (pck_crl_issuer_chain_size) {
        p_resp->pck_crl_issuer_chain_size = pck_crl_issuer_chain_size;
        memcpy(p_ptr, p_pck_crl_issuer_chain, pck_crl_issuer_chain_size);
        p_ptr += pck_crl_issuer_chain_size;
    }

    if (root_ca_crl_size) {
        p_resp->root_ca_crl_size = root_ca_crl_size;
        memcpy(p_ptr, p_root_ca_crl, root_ca_crl_size);
        p_ptr += root_ca_crl_size;
    }

    if (pck_crl_size) {
        p_resp->pck_crl_size = pck_crl_size;
        memcpy(p_ptr, p_pck_crl, pck_crl_size);
        p_ptr += pck_crl_size;
    }

    if (tcb_info_issuer_chain_size) {
        p_resp->tcb_info_issuer_chain_size = tcb_info_issuer_chain_size;
        memcpy(p_ptr, p_tcb_info_issuer_chain, tcb_info_issuer_chain_size);
        p_ptr += tcb_info_issuer_chain_size;
    }

    if (tcb_info_size) {
        p_resp->tcb_info_size = tcb_info_size;
        memcpy(p_ptr, p_tcb_info, tcb_info_size);
        p_ptr += tcb_info_size;
    }

    if (qe_identity_issuer_chain_size) {
        p_resp->qe_identity_issuer_chain_size = qe_identity_issuer_chain_size;
        memcpy(p_ptr, p_qe_identity_issuer_chain, qe_identity_issuer_chain_size);
        p_ptr += qe_identity_issuer_chain_size;
    }

    if (root_ca_crl_size) {
        p_resp->qe_identity_size = qe_identity_size;
        memcpy(p_ptr, p_qe_identity, qe_identity_size);
    }

    *pp_resp = (uint8_t *)p_resp;
    *p_resp_size = buf_size;
    ret = QGS_MSG_SUCCESS;

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_inflate_get_quote_resp(
    const uint8_t *p_serialized_resp, uint32_t size,
    const uint8_t **pp_selected_id, uint32_t *p_id_size,
    const uint8_t **pp_quote, uint32_t *p_quote_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_quote_resp_t *p_resp = NULL;
    uint64_t temp = 0;

    if (!p_serialized_resp || !size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_selected_id || !p_id_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_quote || !p_quote_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    // sanity check, the size shouldn't smaller than qgs_msg_get_quote_req_t
    if (size < sizeof(qgs_msg_get_quote_resp_t)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_resp = (qgs_msg_get_quote_resp_t *)p_serialized_resp;
    // Only major version is checked, minor change is deemed as compatible.
    if (p_resp->header.major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }

    if (p_resp->header.type != GET_QUOTE_RESP) {
        ret = QGS_MSG_ERROR_INVALID_TYPE;
        goto ret_point;
    }

    if (p_resp->header.size != size) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    temp = sizeof(qgs_msg_get_quote_resp_t);
    temp += p_resp->selected_id_size;
    temp += p_resp->quote_size;
    if (temp >= UINT32_MAX) {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    if (p_resp->header.size != temp) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    if (p_resp->header.error_code == QGS_MSG_SUCCESS) {
        if (!p_resp->quote_size) {
            // It makes no sense to return success and an empty quote
            ret = QGS_MSG_ERROR_INVALID_SIZE;
            goto ret_point;
        }
        if (p_resp->selected_id_size) {
            *pp_selected_id = p_resp->id_quote;
            *p_id_size = p_resp->selected_id_size;
        } else {
            *pp_selected_id = NULL;
            *p_id_size = 0;
        }
        *pp_quote = p_resp->id_quote + p_resp->selected_id_size;
        *p_quote_size = p_resp->quote_size;
    } else if (p_resp->header.error_code < QGS_MSG_ERROR_MAX) {
        if (p_resp->selected_id_size || p_resp->quote_size) {
            ret = QGS_MSG_ERROR_INVALID_SIZE;
            goto ret_point;
        }
        *pp_selected_id = NULL;
        *p_id_size = 0;
        *pp_quote = NULL;
        *p_quote_size = 0;
    } else {
        ret = QGS_MSG_ERROR_INVALID_CODE;
        goto ret_point;
    }

    ret = QGS_MSG_SUCCESS;
ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_inflate_get_collateral_resp(
    const uint8_t *p_serialized_resp, uint32_t size,
    uint16_t *p_major_version, uint16_t *p_minor_version,
    const uint8_t **pp_pck_crl_issuer_chain, uint32_t *p_pck_crl_issuer_chain_size,
    const uint8_t **pp_root_ca_crl, uint32_t *p_root_ca_crl_size,
    const uint8_t **pp_pck_crl, uint32_t *p_pck_crl_size,
    const uint8_t **pp_tcb_info_issuer_chain, uint32_t *p_tcb_info_issuer_chain_size,
    const uint8_t **pp_tcb_info, uint32_t *p_tcb_info_size,
    const uint8_t **pp_qe_identity_issuer_chain, uint32_t *p_qe_identity_issuer_chain_size,
    const uint8_t **pp_qe_identity, uint32_t *p_qe_identity_size) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_collateral_resp_t *p_resp = NULL;
    uint64_t temp = 0;

    if (!p_serialized_resp || !size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!p_major_version || !p_minor_version
        || !pp_pck_crl_issuer_chain || !p_pck_crl_issuer_chain_size
        || !pp_root_ca_crl || !p_root_ca_crl_size
        || !pp_pck_crl || !p_pck_crl_size
        || !pp_tcb_info_issuer_chain || !p_tcb_info_issuer_chain_size
        || !pp_tcb_info || !p_tcb_info_size
        || !pp_qe_identity_issuer_chain || !p_qe_identity_issuer_chain_size
        || !pp_qe_identity || !p_qe_identity_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    // sanity check, the size shouldn't smaller than qgs_msg_get_quote_req_t
    if (size < sizeof(qgs_msg_get_collateral_resp_t)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_resp = (qgs_msg_get_collateral_resp_t *)p_serialized_resp;
    // Only major version is checked, minor change is deemed as compatible.
    if (p_resp->header.major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }

    if (p_resp->header.type != GET_COLLATERAL_RESP) {
        ret = QGS_MSG_ERROR_INVALID_TYPE;
        goto ret_point;
    }

    if (p_resp->header.size != size) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    if (p_resp->header.minor_version == 0) {
        temp = sizeof(*p_resp) + sizeof(p_resp->major_version) + sizeof(p_resp->minor_version);
    } else {
        temp = sizeof(*p_resp);
    }
    temp += p_resp->pck_crl_issuer_chain_size;
    temp += p_resp->root_ca_crl_size;
    temp += p_resp->pck_crl_size;
    temp += p_resp->tcb_info_issuer_chain_size;
    temp += p_resp->tcb_info_size;
    temp += p_resp->qe_identity_issuer_chain_size;
    temp += p_resp->qe_identity_size;

    if (temp >= UINT32_MAX) {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    if (p_resp->header.size != temp) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    if (p_resp->header.error_code == QGS_MSG_SUCCESS) {
        // It makes no sense to return success and empty collaterals
        if (!p_resp->pck_crl_issuer_chain_size
            || !p_resp->root_ca_crl_size
            || !p_resp->pck_crl_size
            || !p_resp->tcb_info_issuer_chain_size
            || !p_resp->tcb_info_size
            || !p_resp->qe_identity_issuer_chain_size
            || !p_resp->qe_identity_size) {
            ret = QGS_MSG_ERROR_INVALID_SIZE;
            goto ret_point;
        }
        *p_major_version = p_resp->major_version;
        *p_minor_version = p_resp->minor_version;

        *pp_pck_crl_issuer_chain = p_resp->collaterals;
        *p_pck_crl_issuer_chain_size = p_resp->pck_crl_issuer_chain_size;

        *pp_root_ca_crl = *pp_pck_crl_issuer_chain + p_resp->pck_crl_issuer_chain_size;
        *p_root_ca_crl_size = p_resp->root_ca_crl_size;

        *pp_pck_crl = *pp_root_ca_crl + p_resp->root_ca_crl_size;
        *p_pck_crl_size = p_resp->pck_crl_size;

        *pp_tcb_info_issuer_chain = *pp_pck_crl + p_resp->pck_crl_size;
        *p_tcb_info_issuer_chain_size = p_resp->tcb_info_issuer_chain_size;

        *pp_tcb_info = *pp_tcb_info_issuer_chain + p_resp->tcb_info_issuer_chain_size;
        *p_tcb_info_size = p_resp->tcb_info_size;

        *pp_qe_identity_issuer_chain = *pp_tcb_info + p_resp->tcb_info_size;
        *p_qe_identity_issuer_chain_size = p_resp->qe_identity_issuer_chain_size;

        *pp_qe_identity = *pp_qe_identity_issuer_chain + p_resp->qe_identity_issuer_chain_size;
        *p_qe_identity_size = p_resp->qe_identity_size;

    } else if (p_resp->header.error_code < QGS_MSG_ERROR_MAX) {
        if (p_resp->pck_crl_issuer_chain_size
            || p_resp->root_ca_crl_size
            || p_resp->pck_crl_size
            || p_resp->tcb_info_issuer_chain_size
            || p_resp->tcb_info_size
            || p_resp->qe_identity_issuer_chain_size
            || p_resp->qe_identity_size) {
            ret = QGS_MSG_ERROR_INVALID_SIZE;
            goto ret_point;
        }
        *p_major_version = 0;
        *p_minor_version = 0;

        *pp_pck_crl_issuer_chain = NULL;
        *p_pck_crl_issuer_chain_size = 0;
        *pp_root_ca_crl = NULL;
        *p_root_ca_crl_size = 0;
        *pp_pck_crl = NULL;
        *p_pck_crl_size = 0;
        *pp_tcb_info_issuer_chain = NULL;
        *p_tcb_info_issuer_chain_size = 0;
        *pp_tcb_info = NULL;
        *p_tcb_info_size = 0;
        *pp_qe_identity_issuer_chain = NULL;
        *p_qe_identity_issuer_chain_size = 0;
        *pp_qe_identity = NULL;
        *p_qe_identity_size = 0;
    } else {
        ret = QGS_MSG_ERROR_INVALID_CODE;
        goto ret_point;
    }

    ret = QGS_MSG_SUCCESS;
ret_point:
    return ret;
}

uint32_t qgs_msg_get_type(const uint8_t *p_serialized_msg, uint32_t size, uint32_t *p_type) {
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    const qgs_msg_header_t *p_header = (const qgs_msg_header_t *)p_serialized_msg;

    if (size < sizeof(qgs_msg_header_t)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (p_header->major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }
    if (p_header->type >= QGS_MSG_TYPE_MAX) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }
    *p_type = p_header->type;
    ret = QGS_MSG_SUCCESS;
ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_gen_get_platform_info_req(
    uint8_t **pp_req, uint32_t *p_req_size)
{
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_platform_info_req_t *p_req = NULL;

    if (!pp_req || !p_req_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_req = (qgs_msg_get_platform_info_req_t *)calloc(sizeof(*p_req), sizeof(uint8_t));
    if (!p_req) {
        ret = QGS_MSG_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    p_req->header.major_version = QGS_MSG_LIB_MAJOR_VER;
    p_req->header.minor_version = QGS_MSG_LIB_MINOR_VER;
    p_req->header.type = GET_PLATFORM_INFO_REQ;
    p_req->header.size = sizeof(*p_req);
    p_req->header.error_code = 0;

    *pp_req = (uint8_t *)p_req;
    *p_req_size = sizeof(*p_req);
    ret = QGS_MSG_SUCCESS;

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_inflate_get_platform_info_req(
    const uint8_t *p_serialized_req, uint32_t size)
{
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_platform_info_req_t *p_req = NULL;

    if (!p_serialized_req || !size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    // sanity check, the size shouldn't smaller than qgs_msg_get_platform_info_req_t
    if (size < sizeof(qgs_msg_get_platform_info_req_t)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_req = (qgs_msg_get_platform_info_req_t *)p_serialized_req;
    // Only major version is checked, minor change is deemed as compatible.
    if (p_req->header.major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }

    if (p_req->header.type != GET_PLATFORM_INFO_REQ) {
        ret = QGS_MSG_ERROR_INVALID_TYPE;
        goto ret_point;
    }

    if (p_req->header.size != size) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    if (p_req->header.error_code != 0) {
        ret = QGS_MSG_ERROR_INVALID_CODE;
        goto ret_point;
    }

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_gen_get_platform_info_resp(
    uint16_t tdqe_isvsvn, uint16_t pce_isvsvn,
    const uint8_t *p_platform_id, uint32_t platform_id_size,
    const uint8_t *p_cpusvn, uint32_t cpusvn_size,
    uint8_t **pp_resp, uint32_t *p_resp_size)
{
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_platform_info_resp_t *p_resp = NULL;
    uint32_t buf_size = 0;
    uint64_t temp = 0;
    uint8_t *p_ptr = NULL;

    if (!pp_resp || !p_resp_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if ((!p_platform_id || !platform_id_size)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!p_cpusvn || !cpusvn_size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    temp = sizeof(tdqe_isvsvn) + sizeof(pce_isvsvn) + sizeof(*p_resp);
    temp += platform_id_size + cpusvn_size;
    if (temp < UINT32_MAX) {
        buf_size = temp & UINT32_MAX;
    } else {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    p_resp = (qgs_msg_get_platform_info_resp_t *)calloc(buf_size, sizeof(uint8_t));
    if (!p_resp) {
        ret = QGS_MSG_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    p_resp->header.major_version = QGS_MSG_LIB_MAJOR_VER;
    p_resp->header.minor_version = QGS_MSG_LIB_MINOR_VER;
    p_resp->header.type = GET_PLATFORM_INFO_RESP;
    p_resp->header.size = buf_size;
    p_resp->header.error_code = QGS_MSG_SUCCESS;

    p_resp->platform_id_size = platform_id_size;
    p_resp->cpusvn_size = cpusvn_size;

    p_resp->tdqe_isvsvn = tdqe_isvsvn;
    p_resp->pce_isvsvn = pce_isvsvn;

    p_ptr = p_resp->platform_id_cpusvn;
    memcpy(p_ptr, p_platform_id, platform_id_size);
    p_ptr += platform_id_size;

    memcpy(p_ptr, p_cpusvn, cpusvn_size);

    *pp_resp = (uint8_t *)p_resp;
    *p_resp_size = buf_size;
    ret = QGS_MSG_SUCCESS;

ret_point:
    return ret;
}

qgs_msg_error_t qgs_msg_inflate_get_platform_info_resp(
    const uint8_t *p_serialized_resp, uint32_t size,
    uint16_t *p_tdqe_isvsvn, uint16_t *p_pce_isvsvn,
    const uint8_t **pp_platform_id, uint32_t *p_platform_id_size,
    const uint8_t **pp_cpusvn, uint32_t *p_cpusvn_size)
{
    qgs_msg_error_t ret = QGS_MSG_SUCCESS;
    qgs_msg_get_platform_info_resp_t *p_resp = NULL;
    uint64_t temp = 0;

    if (!p_serialized_resp || !size) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (!pp_platform_id || !p_platform_id_size
        || !pp_cpusvn  || !p_cpusvn_size
        || !p_tdqe_isvsvn || !p_pce_isvsvn) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    // sanity check, the size shouldn't smaller than qgs_msg_get_quote_req_t
    if (size < sizeof(qgs_msg_get_platform_info_resp_t)) {
        ret = QGS_MSG_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_resp = (qgs_msg_get_platform_info_resp_t *)p_serialized_resp;
    // Only major version is checked, minor change is deemed as compatible.
    if (p_resp->header.major_version != QGS_MSG_LIB_MAJOR_VER) {
        ret = QGS_MSG_ERROR_INVALID_VERSION;
        goto ret_point;
    }

    if (p_resp->header.type != GET_PLATFORM_INFO_RESP) {
        ret = QGS_MSG_ERROR_INVALID_TYPE;
        goto ret_point;
    }

    if (p_resp->header.size != size) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    temp = sizeof(p_resp->tdqe_isvsvn) + sizeof(p_resp->pce_isvsvn) + sizeof(*p_resp);
    temp += p_resp->platform_id_size;
    temp += p_resp->cpusvn_size;
    if (temp >= UINT32_MAX) {
        ret = QGS_MSG_ERROR_UNEXPECTED;
        goto ret_point;
    }
    if (p_resp->header.size != temp) {
        ret = QGS_MSG_ERROR_INVALID_SIZE;
        goto ret_point;
    }

    if (p_resp->header.error_code == QGS_MSG_SUCCESS) {
        // It makes no sense to return success and empty platform info
        if (!p_resp->platform_id_size || !p_resp->cpusvn_size) {
            ret = QGS_MSG_ERROR_INVALID_SIZE;
            goto ret_point;
        }
        *p_tdqe_isvsvn = p_resp->tdqe_isvsvn;
        *p_pce_isvsvn = p_resp->pce_isvsvn;

        *pp_platform_id = p_resp->platform_id_cpusvn;
        *p_platform_id_size = p_resp->platform_id_size;

        *pp_cpusvn = *pp_platform_id + p_resp->platform_id_size;
        *p_cpusvn_size = p_resp->cpusvn_size;

    } else if (p_resp->header.error_code < QGS_MSG_ERROR_MAX) {
        if (p_resp->platform_id_size || p_resp->cpusvn_size) {
            ret = QGS_MSG_ERROR_INVALID_SIZE;
            goto ret_point;
        }
        *p_tdqe_isvsvn = 0;
        *p_pce_isvsvn = 0;

        *pp_platform_id = NULL;
        *p_platform_id_size = 0;

        *pp_cpusvn = NULL;
        *p_cpusvn_size = 0;
    } else {
        ret = QGS_MSG_ERROR_INVALID_CODE;
        goto ret_point;
    }

    ret = QGS_MSG_SUCCESS;
ret_point:
    return ret;
}