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

#ifndef SERVTD_ATTEST

#define _GNU_SOURCE
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include "qgs_msg_lib.h"
#include "tdx_attest.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h> // For strtoul
#include <linux/ioctl.h>
#include <linux/types.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#define TDX_ATTEST_DEV_PATH "/dev/tdx_guest"
#define CFG_FILE_PATH "/etc/tdx-attest.conf"
#define DCAP_TDX_QUOTE_CONFIGFS_PATH_ENV "DCAP_TDX_QUOTE_CONFIGFS_PATH"
#define QUOTE_CONFIGFS_PATH "/sys/kernel/config/tsm/report"
#define DEFAULT_DCAP_TDX_QUOTE_CONFIGFS_PATH QUOTE_CONFIGFS_PATH"/com.intel.dcap"

// TODO: Should include kernel header, but the header file are included by
// different package in differnt distro, and installed in different locations.
// So add these defines here. Need to remove them later when kernel header
// became stable.

#define TDX_CMD_GET_REPORT0 _IOWR('T', 1, struct tdx_report_req)
#ifdef V3_DRIVER
#define TDX_CMD_VERIFY_REPORT _IOWR('T', 2, struct tdx_verify_report_req)
#define TDX_CMD_EXTEND_RTMR _IOW('T', 3, struct tdx_extend_rtmr_req)
#define TDX_CMD_GET_QUOTE _IOWR('T', 4, struct tdx_quote_req)
#else
#define TDX_CMD_VERIFY_REPORT _IOR('T', 2, struct tdx_verify_report_req)
#define TDX_CMD_EXTEND_RTMR _IOR('T', 3, struct tdx_extend_rtmr_req)
#define TDX_CMD_GET_QUOTE _IOR('T', 4, struct tdx_quote_req)
#endif


/* TD Quote status codes */
#define GET_QUOTE_SUCCESS               0
#define GET_QUOTE_IN_FLIGHT             0xffffffffffffffff
#define GET_QUOTE_ERROR                 0x8000000000000000
#define GET_QUOTE_SERVICE_UNAVAILABLE   0x8000000000000001

#define TDX_EXTEND_RTMR_DATA_LEN        48

#ifdef DEBUG
#define TDX_TRACE                                          \
    do {                                                   \
        fprintf(stderr, "\n[%s:%d] ", __FILE__, __LINE__); \
        perror(NULL);                                      \
    }while(0)
#else
#define TDX_TRACE
#endif

struct tdx_report_req {
	__u8 reportdata[TDX_REPORT_DATA_SIZE];
	__u8 tdreport[TDX_REPORT_SIZE];
};

struct tdx_extend_rtmr_req {
	__u8 data[TDX_EXTEND_RTMR_DATA_LEN];
	__u8 index;
};

struct tdx_quote_hdr {
    /* Quote version, filled by TD */
    __u64 version;
    /* Status code of Quote request, filled by VMM */
    __u64 status;
    /* Length of TDREPORT, filled by TD */
    __u32 in_len;
    /* Length of Quote, filled by VMM */
    __u32 out_len;
    /* Actual Quote data or TDREPORT on input */
    __u64 data[0];
};

struct tdx_quote_req {
    __u64 buf;
    __u64 len;
};

static const unsigned HEADER_SIZE = 4;
static const size_t REQ_BUF_SIZE = 4 * 4 * 1024; // 4 pages
static const size_t QUOTE_BUF_SIZE = 8 * 1024; //8K
static const size_t QUOTE_MIN_SIZE = 1020;

static const tdx_uuid_t g_intel_tdqe_uuid = {TDX_SGX_ECDSA_ATTESTATION_ID};

static unsigned int get_vsock_port(void)
{
    FILE *p_config_fd = NULL;
    char *p_line = NULL;
    char *p = NULL;
    size_t line_len = 0;
    long long_num = 0;
    unsigned int port = 0;

    p_config_fd = fopen(CFG_FILE_PATH, "r");
    if (NULL == p_config_fd) {
        TDX_TRACE;
        return 0;
    }
    while(-1 != getline(&p_line, &line_len, p_config_fd)) {
        char temp[11] = {0};
        int number = 0;
        int ret = sscanf(p_line, " %10[#]", temp);
        if (ret == 1) {
            continue;
        }
        /* leading or trailing white space are ignored, white space around '='
           are also ignored. The number should no longer than 10 characters.
           Trailing non-whitespace are not allowed. */
        ret = sscanf(p_line, " port = %10[0-9] %n", temp, &number);
        /* Make sure number is positive then make the cast. It's not likely to
           have a negtive value, just a defense-in-depth. The cast is used to
           suppress the -Wsign-compare warning. */
        if (ret == 1 && number > 0 && ((size_t)number < line_len)
            && !p_line[number]) {
            errno = 0;
            long_num = strtol(temp, &p, 10);
            if (p == temp) {
                TDX_TRACE;
                port = 0;
                break;
            }

            // make sure that no range error occurred
            if (errno == ERANGE || long_num > UINT_MAX) {
                TDX_TRACE;
                port = 0;
                break;
            }

            // range is ok, so we can convert to int
            port = (unsigned int)long_num & 0xFFFFFFFF;
#ifdef DEBUG
            fprintf(stdout, "\nGet the vsock port number [%u]\n", port);
#endif
            break;
        }
    }

    /* p_line is allocated by sscanf */
    free(p_line);
    fclose(p_config_fd);

    return port;
}

static tdx_attest_error_t get_tdx_report(
    int devfd,
    const tdx_report_data_t *p_tdx_report_data,
    tdx_report_t *p_tdx_report)
{
    if (-1 == devfd) {
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }
    if (!p_tdx_report) {
        fprintf(stderr, "\nNeed to input TDX report.");
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (!p_tdx_report_data) {
        fprintf(stderr, "\nNeed to input TDX report data.");
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    struct tdx_report_req req = {0};
    memcpy(req.reportdata, p_tdx_report_data->d, sizeof(req.reportdata));

    if (-1 == ioctl(devfd, TDX_CMD_GET_REPORT0, &req)) {
        TDX_TRACE;
        return TDX_ATTEST_ERROR_REPORT_FAILURE;
    }
    memcpy(p_tdx_report->d, req.tdreport, sizeof(p_tdx_report->d));
    return TDX_ATTEST_SUCCESS;
}

#define MAX_PATH 260

static int b_mkdir = 1;
pthread_mutex_t mkdir_mutex;

void __attribute__((constructor)) init_mutex(void) { pthread_mutex_init(&mkdir_mutex, NULL); }
void __attribute__((destructor)) destroy_mutex(void) { pthread_mutex_destroy(&mkdir_mutex); }

static tdx_attest_error_t prepare_configfs(char **p_configfs_path) {
    int ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
    char *configfs_path = NULL;
    do {
        // Retrive DCAP TDX quote configFS path from environment
        configfs_path = secure_getenv(DCAP_TDX_QUOTE_CONFIGFS_PATH_ENV);
        if (configfs_path == NULL) {
            syslog(LOG_INFO, "libtdx_attest: env '%s' is not provided - try default path.",
                   DCAP_TDX_QUOTE_CONFIGFS_PATH_ENV);
            break;
        }
        if (strnlen(configfs_path, MAX_PATH) >= MAX_PATH - 20) {
            syslog(LOG_ERR, "libtdx_attest: env '%s' is too long.", DCAP_TDX_QUOTE_CONFIGFS_PATH_ENV);
            return ret;
        }

        // Check whether the configFS directory exists
        DIR *dir = opendir(configfs_path);
        if (dir == NULL) {
            syslog(LOG_ERR, "libtdx_attest: env '%s' is not valid directory.",
                   DCAP_TDX_QUOTE_CONFIGFS_PATH_ENV);
            return ret;
        }
        closedir(dir);
        ret = TDX_ATTEST_SUCCESS;
    } while (0);

    while (ret != TDX_ATTEST_SUCCESS) {
        // Default DCAP TDX quote configFS path
        ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
        configfs_path = DEFAULT_DCAP_TDX_QUOTE_CONFIGFS_PATH;
        pthread_mutex_lock(&mkdir_mutex);
        DIR *dir = opendir(configfs_path);
        if (dir != NULL) {
            pthread_mutex_unlock(&mkdir_mutex);
            ret = TDX_ATTEST_SUCCESS;
            closedir(dir);
            break;
        }
        if (errno != ENOENT) {
            pthread_mutex_unlock(&mkdir_mutex);
            syslog(LOG_INFO, "libtdx_attest: default DCAP configFS not supported - fallback to vsock mode.");
            break;
        }

        // Create default DCAP TDX quote configFS path only once
        if (!b_mkdir) {
            pthread_mutex_unlock(&mkdir_mutex);
            syslog(LOG_INFO, "libtdx_attest: default DCAP configFS not supported - fallback to vsock mode.");
            break;
        }
        b_mkdir = 0;

        dir = opendir(QUOTE_CONFIGFS_PATH);
        if (dir == NULL) {
            pthread_mutex_unlock(&mkdir_mutex);
            syslog(LOG_INFO, "libtdx_attest: configFS not supported - fallback to vsock mode.");
                break;
        }
        closedir(dir);

        if (mkdir(configfs_path, S_IRWXU | S_IRWXG)) {                    
            pthread_mutex_unlock(&mkdir_mutex);
            if (errno == EEXIST && (dir = opendir(configfs_path)) != NULL) {
                // Another process has just created configfs_path
                ret = TDX_ATTEST_SUCCESS;
                closedir(dir);
                break;
            }
            syslog(LOG_INFO, "libtdx_attest: cannot create default configFS - fallback to vsock mode.");
            break;
        }
        char provider_path[MAX_PATH];
        snprintf(provider_path, sizeof(provider_path), "%s/provider", configfs_path);
        for (size_t retry = 0; retry < 5; retry++) {
            // Linux kernel will create provider, generation, inblob, outblob in configfs_path
            // after configfs_path direcotry created.
            if (access(provider_path, F_OK) == 0) {
                pthread_mutex_unlock(&mkdir_mutex);
                ret = TDX_ATTEST_SUCCESS;
                break;
            }
            usleep((useconds_t)retry);
        }
        pthread_mutex_unlock(&mkdir_mutex);
        syslog(LOG_INFO, "libtdx_attest: unavailable default configFS - fallback to vsock mode.");
        break;
    }

    if (ret != TDX_ATTEST_SUCCESS) {
        //Both configfs path are unavailable
        return ret;
    }

    // For Intel TDX, provider is "tdx_guest"
    char provider_path[MAX_PATH];
    snprintf(provider_path, sizeof(provider_path), "%s/provider", configfs_path);
    int fd = open(provider_path, O_RDONLY);
    if (-1 == fd) {
        TDX_TRACE;
        syslog(LOG_ERR, "libtdx_attest: cannot open configFS `%s`.", provider_path);
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }

    // Read the entire file in one shot
    char provider[16] = {0};
    ssize_t byte_size = read(fd, provider, 15);
    close(fd);

    if (byte_size == -1 || byte_size == 0 ||
        strncmp(provider, "tdx_guest", sizeof("tdx_guest") - 1)) {
        syslog(LOG_ERR, "libtdx_attest: configFS unsupported provider.");
        return TDX_ATTEST_ERROR_NOT_SUPPORTED;
    }
    *p_configfs_path = configfs_path;
    return TDX_ATTEST_SUCCESS;
}

static tdx_attest_error_t read_configfs_generation(char *generation_path, long* p_generation)
{
    int fd = open(generation_path, O_RDONLY);
    if (-1 == fd) {
        TDX_TRACE;
        syslog(LOG_ERR, "libtdx_attest: failed to open configFS generation.");
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }
#ifdef DEBUG
    fprintf(stdout, "\nstart to read generation\n");
#endif
    #define GENERATION_MAX_LENGTH 20
    char str_generation[GENERATION_MAX_LENGTH] = {0};
    ssize_t byte_size = read(fd, str_generation, GENERATION_MAX_LENGTH);
    if (byte_size == -1) {
        TDX_TRACE;
        close(fd);
        syslog(LOG_ERR, "libtdx_attest: failed to read configFS generation.");
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }
    close(fd);
    if (byte_size == 0) {
        syslog(LOG_ERR, "libtdx_attest: no content of configFS generation.");
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }
    if (byte_size >= GENERATION_MAX_LENGTH) {
        syslog(LOG_ERR, "libtdx_attest: too large configFS generation.");
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }

    errno = 0;
    long generation = strtol(str_generation, NULL, 10);
    if (errno != 0) {
        TDX_TRACE;
        syslog(LOG_ERR, "libtdx_attest: cannot parse configFS generation.");
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }
    *p_generation = generation;

#ifdef DEBUG
    fprintf(stdout, "\ngeneration: %ld\n", generation);
#endif
    return TDX_ATTEST_SUCCESS;
}

#define RETRY_WAIT_TIME_USEC 10000000

tdx_attest_error_t tdx_att_get_quote(
    const tdx_report_data_t *p_tdx_report_data,
    const tdx_uuid_t *p_att_key_id_list,
    uint32_t list_size,
    tdx_uuid_t *p_att_key_id,
    uint8_t **pp_quote,
    uint32_t *p_quote_size,
    uint32_t flags)
{
    int s = -1;
    int devfd = -1;

    const uint8_t *p_quote = NULL;
    uint32_t quote_size = 0;
    tdx_attest_error_t ret = TDX_ATTEST_ERROR_UNEXPECTED;
    uint8_t *p_blob_payload = NULL;

    if ((!p_att_key_id_list && list_size) ||
        (p_att_key_id_list && !list_size)) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (!pp_quote) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (flags) {
        //TODO: I think we need to have a runtime version to make this flag usable.
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }

    // Currently only intel TDQE are supported
    if (1 < list_size) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_att_key_id_list && memcmp(p_att_key_id_list, &g_intel_tdqe_uuid,
                    sizeof(g_intel_tdqe_uuid))) {
        return TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID;
    }

    *pp_quote = NULL;

    do {
        char *configfs_path = NULL;
        if (prepare_configfs(&configfs_path) != TDX_ATTEST_SUCCESS)
            break;

        char inblob_path[MAX_PATH];
        snprintf(inblob_path, sizeof(inblob_path), "%s/inblob", configfs_path);

        // Lock `inblob` to avoid other processes accessing it using libtdx_attest
        // Will unlock it via close()
        int fd_lock = open(inblob_path, O_WRONLY | O_CLOEXEC);
        if (-1 == fd_lock) {
            TDX_TRACE;
            syslog(LOG_ERR, "libtdx_attest: failed to open configFS inblob.");
            return TDX_ATTEST_ERROR_UNEXPECTED;
        }
        if (flock(fd_lock, LOCK_EX)) {
            TDX_TRACE;
            close(fd_lock);
            syslog(LOG_ERR, "libtdx_attest: failed to lock configFS inblob.");
            return TDX_ATTEST_ERROR_UNEXPECTED;
        }

        /* Read and check generation value before writing inblob, after writing inblob and after
           reading outblob to make sure that outblob matches inblob */
        char generation_path[MAX_PATH];
        snprintf(generation_path, sizeof(generation_path), "%s/generation", configfs_path);
        long generation1;
        ret = read_configfs_generation(generation_path, &generation1);
        if (ret) {
            close(fd_lock);
            return ret;
        }

        // Write TDX report data to inblob
        int fd_inblob = open(inblob_path, O_WRONLY);
        if (-1 == fd_inblob) {
            TDX_TRACE;
            close(fd_lock);
            syslog(LOG_ERR, "libtdx_attest: failed to open configFS inblob.");
            return TDX_ATTEST_ERROR_UNEXPECTED;
        }

        ssize_t byte_size = 0;
        // Wait and retry when EBUSY; other TDX Quotes are being generating
        for (int retry = 0; retry < 3; retry++) {
            errno = 0;
            byte_size = write(fd_inblob, p_tdx_report_data, sizeof(*p_tdx_report_data));
            if (errno != EBUSY)
                break;
            usleep(RETRY_WAIT_TIME_USEC);
        }
        if (byte_size != sizeof(*p_tdx_report_data)) {
            if (errno == EBUSY) {
                TDX_TRACE;
                ret = TDX_ATTEST_ERROR_BUSY;
            } else {
                TDX_TRACE;
                ret = TDX_ATTEST_ERROR_UNEXPECTED;
            }
            close(fd_lock);
            close(fd_inblob);
            syslog(LOG_ERR, "libtdx_attest: failed to write configFS inblob.");
            return ret;
        }
        close(fd_inblob);

        long generation2;
        do {
            ret = read_configfs_generation(generation_path, &generation2);
            if (ret) {
                close(fd_lock);
                return ret;
            }
        // In rare cases, generation is not updated
        } while (generation2 == generation1 && !usleep(0));
        if (generation2 != generation1 + 1) {
            // Another TDX quote generation has been triggered
            close(fd_lock);
            return TDX_ATTEST_ERROR_BUSY;
        }

        // Read TDX quote from outblob
        char outblob_path[MAX_PATH];
        snprintf(outblob_path, sizeof(outblob_path), "%s/outblob", configfs_path);
        int fd = open(outblob_path, O_RDONLY);
        if (-1 == fd) {
            TDX_TRACE;
            syslog(LOG_ERR, "libtdx_attest: failed to open configFS outblob.");
            close(fd_lock);
            return TDX_ATTEST_ERROR_UNEXPECTED;
        }

        // Allocate memory for the entire file content
        p_blob_payload = malloc(QUOTE_BUF_SIZE);
        if (p_blob_payload == NULL) {
            close(fd_lock);
            close(fd);
            return TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        }
#ifdef DEBUG
        fprintf(stdout, "\nstart to read outblob\n");
#endif
        // Read the entire file in one shot
        for (int retry = 0; retry < 3; retry++) {
            errno = 0;
            byte_size = read(fd, p_blob_payload, QUOTE_BUF_SIZE);
            if (errno == EBUSY) {
                usleep(RETRY_WAIT_TIME_USEC);
            } else if (errno != EINTR && errno != ETIMEDOUT)
                break;
        }
        if (byte_size == -1 || byte_size == 0) {
            if (errno == EBUSY || errno == EINTR || errno == ETIMEDOUT) {
                TDX_TRACE;
                ret = TDX_ATTEST_ERROR_BUSY;
            } else
                ret = TDX_ATTEST_ERROR_QUOTE_FAILURE;
            close(fd_lock);
            close(fd);
            free(p_blob_payload);
            syslog(LOG_ERR, "libtdx_attest: failed to read outblob.");
            return ret;
        }
        close(fd);

        quote_size = (uint32_t)byte_size;
#ifdef DEBUG
        fprintf(stdout, "\nquote size: %d\n", quote_size);
#endif
        if (quote_size <= QUOTE_MIN_SIZE || quote_size == QUOTE_BUF_SIZE) {
            close(fd_lock);
            free(p_blob_payload);
            return TDX_ATTEST_ERROR_QUOTE_FAILURE;
        }

        long generation3;
        ret = read_configfs_generation(generation_path, &generation3);
        close(fd_lock);
        if (ret) {
            free(p_blob_payload);
            return ret;
        }
        // Another TDX quote generation is triggered
        if (generation3 != generation2) {
            free(p_blob_payload);
            return TDX_ATTEST_ERROR_BUSY;
        }

        void* tmp_p = realloc(p_blob_payload, quote_size);
        if (tmp_p == NULL) {
            free(p_blob_payload);
            return TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        }
        *pp_quote = tmp_p;

        if (p_quote_size) {
            *p_quote_size = quote_size;
        }
        if (p_att_key_id) {
            *p_att_key_id = g_intel_tdqe_uuid;
        }
        return TDX_ATTEST_SUCCESS;
    } while (0);

#ifdef DEBUG
    fprintf(stdout, "\ngoto legacy logic\n");
#endif

    uint32_t recieved_bytes = 0;
    uint32_t in_msg_size = 0;
    unsigned int vsock_port = 0;
    uint32_t msg_size = 0;
    qgs_msg_error_t qgs_msg_ret = QGS_MSG_SUCCESS;
    qgs_msg_header_t *p_header = NULL;
    uint8_t *p_req = NULL;
    const uint8_t *p_selected_id = NULL;
    uint32_t id_size = 0;

    tdx_report_t tdx_report;
    memset(&tdx_report, 0, sizeof(tdx_report));

    struct tdx_quote_hdr *p_get_quote_blob = malloc(REQ_BUF_SIZE);
    if (!p_get_quote_blob) {
        ret = TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd) {
        TDX_TRACE;
        ret = TDX_ATTEST_ERROR_DEVICE_FAILURE;
        goto ret_point;
    }

    ret = get_tdx_report(devfd, p_tdx_report_data, &tdx_report);
    if (TDX_ATTEST_SUCCESS != ret) {
        goto ret_point;
    }

    qgs_msg_ret = qgs_msg_gen_get_quote_req(tdx_report.d, sizeof(tdx_report.d),
        NULL, 0, &p_req, &msg_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
#ifdef DEBUG
        fprintf(stdout, "\nqgs_msg_gen_get_quote_req return 0x%x\n", qgs_msg_ret);
#endif
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    if (msg_size > REQ_BUF_SIZE - sizeof(struct tdx_quote_hdr) - HEADER_SIZE) {
#ifdef DEBUG
        fprintf(stdout, "\nqmsg_size[%d] is too big\n", msg_size);
        #endif
        ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
        goto ret_point;
    }

    p_blob_payload = (uint8_t *)&p_get_quote_blob->data;
    p_blob_payload[0] = (uint8_t)((msg_size >> 24) & 0xFF);
    p_blob_payload[1] = (uint8_t)((msg_size >> 16) & 0xFF);
    p_blob_payload[2] = (uint8_t)((msg_size >> 8) & 0xFF);
    p_blob_payload[3] = (uint8_t)(msg_size & 0xFF);

    memcpy(p_blob_payload + HEADER_SIZE, p_req, msg_size);

    do {
        vsock_port = get_vsock_port();
        if (!vsock_port) {
            syslog(LOG_INFO, "libtdx_attest: cannot parse sock port - fallback to tdvmcall mode.");
            break;
        }
        s = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (-1 == s) {
            syslog(LOG_INFO, "libtdx_attest: cannot create socket - fallback to tdvmcall mode.");
            break;
        }
        struct sockaddr_vm vm_addr;
        memset(&vm_addr, 0, sizeof(vm_addr));
        vm_addr.svm_family = AF_VSOCK;
        vm_addr.svm_reserved1 = 0;
        vm_addr.svm_port = vsock_port;
        vm_addr.svm_cid = VMADDR_CID_HOST;
        if (connect(s, (struct sockaddr *)&vm_addr, sizeof(vm_addr))) {
            syslog(LOG_INFO, "libtdx_attest: cannot connect - fallback to tdvmcall mode.");
            break;
        }

        // Write to socket
        if (HEADER_SIZE + msg_size != send(s, p_blob_payload,
            HEADER_SIZE + msg_size, 0)) {
            TDX_TRACE;
            ret = TDX_ATTEST_ERROR_VSOCK_FAILURE;
            goto ret_point;
        }

        // Read the response size header
        if (HEADER_SIZE != recv(s, p_blob_payload,
            HEADER_SIZE, 0)) {
            TDX_TRACE;
            ret = TDX_ATTEST_ERROR_VSOCK_FAILURE;
            goto ret_point;
        }

        // decode the size
        for (unsigned i = 0; i < HEADER_SIZE; ++i) {
            in_msg_size = in_msg_size * 256 + ((p_blob_payload[i]) & 0xFF);
        }

        // prepare the buffer and read the reply body
        #ifdef DEBUG
        fprintf(stdout, "\nReply message body is %u bytes", in_msg_size);
        #endif

        if (REQ_BUF_SIZE - sizeof(struct tdx_quote_hdr) - HEADER_SIZE < in_msg_size) {
            #ifdef DEBUG
            fprintf(stdout, "\nReply message body is too big");
            #endif
            ret = TDX_ATTEST_ERROR_UNEXPECTED;
            goto ret_point;
        }
        while( recieved_bytes < in_msg_size) {
            int recv_ret = (int)recv(s, p_blob_payload + HEADER_SIZE + recieved_bytes,
                                     in_msg_size - recieved_bytes, 0);
            if (recv_ret < 0) {
                ret = TDX_ATTEST_ERROR_VSOCK_FAILURE;
                goto ret_point;
            }
            recieved_bytes += (uint32_t)recv_ret;
        }
        #ifdef DEBUG
        fprintf(stdout, "\nGet %u bytes response from vsock", recieved_bytes);
        #endif

        goto done;
    } while (0);

    int ioctl_ret;
    struct tdx_quote_req arg;
    p_get_quote_blob->version = 1;
    p_get_quote_blob->status = 0;
    p_get_quote_blob->in_len = HEADER_SIZE + msg_size;
    p_get_quote_blob->out_len = 0;
    arg.buf = (__u64)p_get_quote_blob;
    arg.len = REQ_BUF_SIZE;

    ioctl_ret = ioctl(devfd, TDX_CMD_GET_QUOTE, &arg);
    if (EBUSY == ioctl_ret) {
        TDX_TRACE;
        ret = TDX_ATTEST_ERROR_BUSY;
        goto ret_point;
    } else if (ioctl_ret) {
        TDX_TRACE;
        ret = TDX_ATTEST_ERROR_QUOTE_FAILURE;
        goto ret_point;
    }
    if (p_get_quote_blob->status
        || p_get_quote_blob->out_len <= HEADER_SIZE) {
        TDX_TRACE;
        if (GET_QUOTE_IN_FLIGHT == p_get_quote_blob->status) {
            ret = TDX_ATTEST_ERROR_BUSY;
        } else if (GET_QUOTE_SERVICE_UNAVAILABLE == p_get_quote_blob->status) {
            ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
        } else {
            ret = TDX_ATTEST_ERROR_UNEXPECTED;
        }
        goto ret_point;
    }

    //in_msg_size is the size of serialized response
    for (unsigned i = 0; i < HEADER_SIZE; ++i) {
        in_msg_size = in_msg_size * 256 + ((p_blob_payload[i]) & 0xFF);
    }
    if (in_msg_size != p_get_quote_blob->out_len - HEADER_SIZE) {
        TDX_TRACE;
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }
    #ifdef DEBUG
    fprintf(stdout, "\nGet %u bytes response from tdvmcall", in_msg_size);
    #endif

done:
    qgs_msg_ret = qgs_msg_inflate_get_quote_resp(
        p_blob_payload + HEADER_SIZE, in_msg_size,
        &p_selected_id, &id_size,
        &p_quote, &quote_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        #ifdef DEBUG
        fprintf(stdout, "\nqgs_msg_inflate_get_quote_resp return 0x%x", qgs_msg_ret);
        #endif
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    // We've called qgs_msg_inflate_get_quote_resp, the message type should be GET_QUOTE_RESP
    p_header = (qgs_msg_header_t *)(p_blob_payload + HEADER_SIZE);
    if (p_header->error_code != 0) {
        #ifdef DEBUG
        fprintf(stdout, "\nerror code in resp msg is 0x%x", p_header->error_code);
        #endif
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }
    *pp_quote = malloc(quote_size);
    if (!*pp_quote) {
        ret = TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    memcpy(*pp_quote, p_quote, quote_size);
    if (p_quote_size) {
        *p_quote_size = quote_size;
    }
    if (p_att_key_id) {
        *p_att_key_id = g_intel_tdqe_uuid;
    }
    ret = TDX_ATTEST_SUCCESS;

ret_point:
    if (s >= 0) {
        close(s);
    }
    if (-1 != devfd) {
        close(devfd);
    }
    qgs_msg_free(p_req);
    free(p_get_quote_blob);

    return ret;
}

tdx_attest_error_t tdx_att_free_quote(
    uint8_t *p_quote)
{
    free(p_quote);
    return TDX_ATTEST_SUCCESS;
}

tdx_attest_error_t tdx_att_get_report(
    const tdx_report_data_t *p_tdx_report_data,
    tdx_report_t *p_tdx_report)
{
    int devfd;
    tdx_attest_error_t ret = TDX_ATTEST_SUCCESS;

    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd) {
        TDX_TRACE;
        return TDX_ATTEST_ERROR_DEVICE_FAILURE;
    }

    ret = get_tdx_report(devfd, p_tdx_report_data, p_tdx_report);

    close(devfd);
    return ret;
}

tdx_attest_error_t tdx_att_get_supported_att_key_ids(
        tdx_uuid_t *p_att_key_id_list,
        uint32_t *p_list_size)
{
    if (!p_list_size) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_att_key_id_list && !*p_list_size) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (!p_att_key_id_list && *p_list_size) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_att_key_id_list) {
        p_att_key_id_list[0] = g_intel_tdqe_uuid;
    }
    *p_list_size = 1;
    return TDX_ATTEST_SUCCESS;
}

tdx_attest_error_t tdx_att_extend(
    const tdx_rtmr_event_t *p_rtmr_event)
{
#ifdef TDX_CMD_EXTEND_RTMR
    int devfd = -1;
    struct tdx_extend_rtmr_req req;
    if (!p_rtmr_event || p_rtmr_event->version != 1) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    if (p_rtmr_event->event_data_size) {
        return TDX_ATTEST_ERROR_NOT_SUPPORTED;
    }
    if (p_rtmr_event->rtmr_index > 3) {
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }

    devfd = open(TDX_ATTEST_DEV_PATH, O_RDWR | O_SYNC);
    if (-1 == devfd) {
        TDX_TRACE;
        return TDX_ATTEST_ERROR_DEVICE_FAILURE;
    }

    static_assert(TDX_EXTEND_RTMR_DATA_LEN == sizeof(p_rtmr_event->extend_data),
                  "rtmr extend size mismatch!");
    req.index = (uint8_t)p_rtmr_event->rtmr_index;
    memcpy(req.data, p_rtmr_event->extend_data, TDX_EXTEND_RTMR_DATA_LEN);
    if (-1 == ioctl(devfd, TDX_CMD_EXTEND_RTMR, &req)) {
        TDX_TRACE;
        close(devfd);
        if (EINVAL == errno) {
            return TDX_ATTEST_ERROR_INVALID_RTMR_INDEX;
        }
        return TDX_ATTEST_ERROR_EXTEND_FAILURE;
    }
    close(devfd);
    return TDX_ATTEST_SUCCESS;
#else
    (void)p_rtmr_event;
    return TDX_ATTEST_ERROR_NOT_SUPPORTED;
#endif
}

#else

#include "tdx_attest.h"
#include "servtd_com.h"
#include "servtd_external.h"
#include "qgs_msg_lib.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__ ((visibility("default"))) tdx_attest_error_t tdx_att_get_quote_by_report (
               const void *p_tdx_report,
               uint32_t tdx_report_size,
               void *p_quote,
               uint32_t *p_quote_size)
{
    uint32_t quote_size = 0;
    uint32_t in_msg_size = 0;
    tdx_attest_error_t ret = TDX_ATTEST_ERROR_UNEXPECTED;
    struct servtd_tdx_quote_hdr *p_get_quote_blob = NULL;
    uint8_t *p_blob_payload = NULL;
    uint32_t msg_size = 0;
    int servtd_get_quote_ret = 0;
    const uint8_t *tmp_p_quote = NULL;
    const uint8_t *p_selected_id = NULL;
    uint32_t id_size = 0;
    qgs_msg_error_t qgs_msg_ret = QGS_MSG_SUCCESS;
    qgs_msg_header_t *p_header = NULL;
    uint8_t *p_req = NULL;

    if (NULL == p_tdx_report || TDX_REPORT_SIZE != tdx_report_size) {
        ret = TDX_ATTEST_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    if (NULL == p_quote || NULL == p_quote_size || 0 == *p_quote_size) {
        ret = TDX_ATTEST_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }

    p_get_quote_blob = (struct servtd_tdx_quote_hdr *)malloc(SERVTD_REQ_BUF_SIZE);
    if (!p_get_quote_blob) {
        ret = TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }

    qgs_msg_ret = qgs_msg_gen_get_quote_req(p_tdx_report, tdx_report_size,
        NULL, 0, &p_req, &msg_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    if (msg_size > SERVTD_REQ_BUF_SIZE - sizeof(struct servtd_tdx_quote_hdr) - SERVTD_HEADER_SIZE) {
        ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
        goto ret_point;
    }

    p_blob_payload = (uint8_t *)&p_get_quote_blob->data;
    p_blob_payload[0] = (uint8_t)((msg_size >> 24) & 0xFF);
    p_blob_payload[1] = (uint8_t)((msg_size >> 16) & 0xFF);
    p_blob_payload[2] = (uint8_t)((msg_size >> 8) & 0xFF);
    p_blob_payload[3] = (uint8_t)(msg_size & 0xFF);

    // Serialization
    memcpy(p_blob_payload + SERVTD_HEADER_SIZE, p_req, msg_size);

    p_get_quote_blob->version = 1;
    p_get_quote_blob->status = 0;
    p_get_quote_blob->in_len = SERVTD_HEADER_SIZE + msg_size;
    p_get_quote_blob->out_len = 0;

    servtd_get_quote_ret = servtd_get_quote(p_get_quote_blob, SERVTD_REQ_BUF_SIZE);
    if (servtd_get_quote_ret) {
        ret = TDX_ATTEST_ERROR_QUOTE_FAILURE;
        goto ret_point;
    }

    if (p_get_quote_blob->status
        || p_get_quote_blob->out_len <= SERVTD_HEADER_SIZE) {
        if (GET_QUOTE_IN_FLIGHT == p_get_quote_blob->status) {
            ret = TDX_ATTEST_ERROR_BUSY;
        } else if (GET_QUOTE_SERVICE_UNAVAILABLE == p_get_quote_blob->status) {
            ret = TDX_ATTEST_ERROR_NOT_SUPPORTED;
        } else {
            ret = TDX_ATTEST_ERROR_UNEXPECTED;
        }
        goto ret_point;
    }

    //in_msg_size is the size of serialized response, remove 4bytes header
    for (unsigned i = 0; i < SERVTD_HEADER_SIZE; ++i) {
        in_msg_size = in_msg_size * 256 + ((p_blob_payload[i]) & 0xFF);
    }
    if (in_msg_size != p_get_quote_blob->out_len - SERVTD_HEADER_SIZE) {
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    qgs_msg_ret = qgs_msg_inflate_get_quote_resp(
        p_blob_payload + SERVTD_HEADER_SIZE, in_msg_size,
        &p_selected_id, &id_size,
        (const uint8_t **)&tmp_p_quote, &quote_size);
    if (QGS_MSG_SUCCESS != qgs_msg_ret) {
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    // We've called qgs_msg_inflate_get_quote_resp, the message type should be GET_QUOTE_RESP
    p_header = (qgs_msg_header_t *)(p_blob_payload + SERVTD_HEADER_SIZE);
    if (p_header->error_code != 0) {
        ret = TDX_ATTEST_ERROR_UNEXPECTED;
        goto ret_point;
    }

    if (quote_size > *p_quote_size) {
        ret = TDX_ATTEST_ERROR_OUT_OF_MEMORY;
        goto ret_point;
    }
    memcpy(p_quote, tmp_p_quote, quote_size);

    *p_quote_size = quote_size;
    ret = TDX_ATTEST_SUCCESS;

ret_point:
    qgs_msg_free(p_req);
    SAFE_FREE(p_get_quote_blob);
    return ret;
}

#endif
