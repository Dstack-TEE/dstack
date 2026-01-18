#!/bin/sh
# SPDX-FileCopyrightText: 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# E2E test script for dstack-gateway certbot functionality
# This script runs inside the test-runner container

set -e

# ==================== Configuration ====================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Gateway endpoints
GATEWAY_PROXIES="gateway-1:9014 gateway-2:9014 gateway-3:9014"
GATEWAY_DEBUG_URLS="http://gateway-1:9015 http://gateway-2:9015 http://gateway-3:9015"
GATEWAY_ADMIN="http://gateway-1:9016"

# External services
MOCK_CF_API="http://mock-cf-dns-api:8080"
PEBBLE_DIR="http://pebble:14000/dir"

# Certificate domains to test
CERT_DOMAINS="*.test0.local *.test1.local *.test2.local"

# Cloudflare mock settings
CF_API_TOKEN="test-token"
CF_API_URL="http://mock-cf-dns-api:8080/client/v4"
ACME_URL="http://pebble:14000/dir"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# ==================== Logging ====================

log_info()    { printf "${BLUE}[INFO]${NC} %s\n" "$1"; }
log_warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
log_error()   { printf "${RED}[ERROR]${NC} %s\n" "$1"; }
log_success() { printf "${GREEN}[PASS]${NC} %s\n" "$1"; }
log_fail()    { printf "${RED}[FAIL]${NC} %s\n" "$1"; }

log_section() {
    printf "\n"
    log_info "=========================================="
    log_info "$1"
    log_info "=========================================="
}

log_phase() {
    printf "\n"
    log_info "Phase $1: $2"
    log_info "------------------------------------------"
}

# ==================== Test Utilities ====================

# Run a test and record result
run_test() {
    local name="$1"
    local result="$2"

    if [ "$result" = "0" ]; then
        log_success "$name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "$name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Wait for HTTP service to respond
wait_for_service() {
    local url="$1"
    local name="$2"
    local max_wait="${3:-60}"
    local waited=0

    log_info "Waiting for $name..."
    while [ $waited -lt $max_wait ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            log_info "$name is ready"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    log_error "$name failed to become ready within ${max_wait}s"
    return 1
}

# ==================== Domain Helpers ====================

# Extract base domain: *.test0.local -> test0.local
get_base_domain() {
    echo "$1" | sed 's/^\*\.//'
}

# Convert wildcard to test SNI: *.test0.local -> gateway.test0.local
# Uses "gateway" as it's a special app_id that proxies to gateway's own endpoints
get_test_sni() {
    local base=$(get_base_domain "$1")
    echo "gateway.${base}"
}

# ==================== Certificate Helpers ====================

# Get certificate via openssl s_client
get_cert_pem() {
    local host="$1"
    local sni="$2"
    echo | timeout 5 openssl s_client -connect "$host" -servername "$sni" 2>/dev/null
}

get_cert_serial() {
    get_cert_pem "$1" "$2" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}

get_cert_issuer() {
    get_cert_pem "$1" "$2" | openssl x509 -noout -issuer 2>/dev/null
}

get_cert_san() {
    get_cert_pem "$1" "$2" | openssl x509 -noout -ext subjectAltName 2>/dev/null
}

# ==================== Test Functions ====================

test_http_health() {
    curl -sf "$1" > /dev/null
}

test_certificate_issued() {
    local host="$1"
    local sni="$2"
    [ -n "$(get_cert_serial "$host" "$sni")" ]
}

test_certificates_match() {
    local sni="$1"
    local serial1="" serial2="" serial3=""
    local i=1

    for proxy in $GATEWAY_PROXIES; do
        eval "serial${i}=\"\$(get_cert_serial \"\$proxy\" \"\$sni\")\""
        log_info "Gateway $i cert serial ($sni): $(eval echo \$serial$i)" >&2
        i=$((i + 1))
    done

    [ "$serial1" = "$serial2" ] && [ "$serial2" = "$serial3" ] && [ -n "$serial1" ]
}

test_certificate_from_pebble() {
    local sni="$1"
    local proxy=$(echo "$GATEWAY_PROXIES" | cut -d' ' -f1)
    get_cert_issuer "$proxy" "$sni" | grep -qi "pebble"
}

test_sni_cert_selection() {
    local host="$1"
    local sni="$2"
    local expected_wildcard="$3"
    get_cert_san "$host" "$sni" | grep -q "$expected_wildcard"
}

test_proxy_tls_health() {
    local host="$1"
    local gateway_sni="$2"
    curl -sf --connect-to "${gateway_sni}:9014:${host}" -k "https://${gateway_sni}:9014/health" > /dev/null 2>&1
}

# ==================== Setup ====================

setup_certbot_config() {
    log_info "Configuring certbot via Admin API..."

    # Set ACME URL
    log_info "Setting ACME URL: ${ACME_URL}"
    if ! curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.SetCertbotConfig" \
        -H "Content-Type: application/json" \
        -d '{"acme_url": "'"${ACME_URL}"'"}' > /dev/null; then
        log_error "Failed to set certbot config"
        return 1
    fi

    # Create DNS credential
    log_info "Creating DNS credential..."
    if ! curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.CreateDnsCredential" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "test-cloudflare",
            "provider_type": "cloudflare",
            "cf_api_token": "'"${CF_API_TOKEN}"'",
            "cf_api_url": "'"${CF_API_URL}"'",
            "set_as_default": true,
            "dns_txt_ttl": 1,
            "max_dns_wait": 0
        }' > /dev/null; then
        log_error "Failed to create DNS credential"
        return 1
    fi

    # Add domains and trigger renewal
    for domain in $CERT_DOMAINS; do
        log_info "Adding domain: $domain"
        curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.AddZtDomain" \
            -H "Content-Type: application/json" \
            -d '{"domain": "'"${domain}"'"}' > /dev/null || true

        log_info "Triggering renewal for: $domain"
        curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.RenewZtDomainCert" \
            -H "Content-Type: application/json" \
            -d '{"domain": "'"${domain}"'", "force": true}' > /dev/null || \
            log_warn "Renewal request failed for $domain (may retry)"
    done

    return 0
}

# ==================== Main ====================

main() {
    log_section "dstack-gateway Certbot E2E Test"

    # Phase 1: Mock services
    log_phase 1 "Verify mock services"
    run_test "Mock CF DNS API health" "$(test_http_health "${MOCK_CF_API}/health"; echo $?)"
    run_test "Pebble ACME directory" "$(test_http_health "${PEBBLE_DIR}"; echo $?)"

    # Phase 2: Gateway cluster
    log_phase 2 "Verify gateway cluster"
    local i=1
    for url in $GATEWAY_DEBUG_URLS; do
        run_test "Gateway $i health" "$(test_http_health "${url}/health"; echo $?)"
        i=$((i + 1))
    done

    # Phase 3: Configure certbot
    log_phase 3 "Configure certbot"
    if ! setup_certbot_config; then
        log_error "Failed to setup certbot configuration"
    fi

    # Phase 4: Certificate issuance
    log_phase 4 "Certificate issuance"
    local first_domain=$(echo "$CERT_DOMAINS" | cut -d' ' -f1)
    local first_sni=$(get_test_sni "$first_domain")
    local first_proxy=$(echo "$GATEWAY_PROXIES" | cut -d' ' -f1)

    log_info "Waiting for certificates (up to 120s)..."
    local waited=0
    while [ $waited -lt 120 ]; do
        if test_certificate_issued "$first_proxy" "$first_sni"; then
            log_info "Certificate detected for $first_sni"
            break
        fi
        sleep 5
        waited=$((waited + 5))
        log_info "Waiting... (${waited}s)"
    done

    for domain in $CERT_DOMAINS; do
        local sni=$(get_test_sni "$domain")
        run_test "Certificate issued for $domain" \
            "$(test_certificate_issued "$first_proxy" "$sni"; echo $?)"
    done

    log_info "Waiting 20s for cluster sync..."
    sleep 20

    # Phase 5: Certificate consistency
    log_phase 5 "Certificate consistency"
    for domain in $CERT_DOMAINS; do
        local sni=$(get_test_sni "$domain")
        run_test "All gateways have same cert for $domain" \
            "$(test_certificates_match "$sni"; echo $?)"
        run_test "Cert for $domain issued by Pebble" \
            "$(test_certificate_from_pebble "$sni"; echo $?)"
    done

    # Phase 6: SNI-based selection
    log_phase 6 "SNI-based certificate selection"
    for domain in $CERT_DOMAINS; do
        local sni=$(get_test_sni "$domain")
        run_test "SNI $sni returns $domain cert" \
            "$(test_sni_cert_selection "$first_proxy" "$sni" "$domain"; echo $?)"
    done

    # Phase 7: Proxy TLS health
    log_phase 7 "Proxy TLS health endpoint"
    for domain in $CERT_DOMAINS; do
        local sni=$(get_test_sni "$domain")
        local i=1
        for proxy in $GATEWAY_PROXIES; do
            run_test "Gateway $i TLS health ($sni)" \
                "$(test_proxy_tls_health "$proxy" "$sni"; echo $?)"
            i=$((i + 1))
        done
    done

    # Phase 8: DNS records (informational)
    log_phase 8 "DNS-01 challenge records"
    local records=$(curl -sf "${MOCK_CF_API}/api/records" 2>/dev/null || echo "")
    if echo "$records" | grep -q "TXT"; then
        log_success "DNS TXT records found"
    else
        log_info "No DNS TXT records (expected if certs cached)"
    fi

    # Summary
    log_section "Test Summary"
    log_info "Passed: $TESTS_PASSED"
    log_info "Failed: $TESTS_FAILED"
    log_info "Domains: $(echo "$CERT_DOMAINS" | wc -w)"

    if [ $TESTS_FAILED -eq 0 ]; then
        log_success "All tests passed!"
        exit 0
    else
        log_fail "Some tests failed!"
        exit 1
    fi
}

main
