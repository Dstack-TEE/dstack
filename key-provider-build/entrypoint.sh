#!/bin/sh
rsyslogd
AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service

echo "Enclave info:"
gramine-sgx-sigstruct-view --output-format json gramine-sealing-key-provider.sig

echo "Starting Gramine Sealing Key Provider"
make SGX=1 run-provider
