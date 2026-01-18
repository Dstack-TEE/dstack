#!/bin/sh
# SPDX-FileCopyrightText: 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# E2E test script for dstack-gateway certbot functionality
# This script runs inside the test-runner container

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo "${RED}[ERROR]${NC} $1"; }
log_success() { echo "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo "${RED}[FAIL]${NC} $1"; }

# Test endpoints
MOCK_CF_API="http://mock-cf-dns-api:8080"
PEBBLE_MGMT="https://pebble:15000"
GATEWAY_1_DEBUG="http://gateway-1:9015"
GATEWAY_2_DEBUG="http://gateway-2:9015"
GATEWAY_3_DEBUG="http://gateway-3:9015"
GATEWAY_1_ADMIN="http://gateway-1:9016"
GATEWAY_1_PROXY="gateway-1:9014"
GATEWAY_2_PROXY="gateway-2:9014"
GATEWAY_3_PROXY="gateway-3:9014"

# Certificate config - Multiple wildcard domains
# Each domain gets its own certificate: *.test0.local, *.test1.local, *.test2.local
CERT_DOMAINS="*.test0.local *.test1.local *.test2.local"
CF_API_TOKEN="test-token"
CF_API_URL="http://mock-cf-dns-api:8080/client/v4"
ACME_URL="http://pebble:14000/dir"

# Test state
TESTS_PASSED=0
TESTS_FAILED=0

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

# Wait for a service to be ready
wait_for_service() {
    local url="$1"
    local name="$2"
    local max_wait="${3:-60}"
    local waited=0

    log_info "Waiting for $name to be ready..."
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

# Convert wildcard domain to test SNI: *.test0.local -> app.test0.local
wildcard_to_sni() {
    local wildcard="$1"
    echo "$wildcard" | sed 's/\*\./app./'
}

# Get certificate info from proxy via TLS with specific SNI
get_cert_serial() {
    local host="$1"
    local sni="$2"
    echo | timeout 5 openssl s_client -connect "$host" -servername "$sni" 2>/dev/null | \
        openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}

get_cert_issuer() {
    local host="$1"
    local sni="$2"
    echo | timeout 5 openssl s_client -connect "$host" -servername "$sni" 2>/dev/null | \
        openssl x509 -noout -issuer 2>/dev/null
}

get_cert_subject() {
    local host="$1"
    local sni="$2"
    echo | timeout 5 openssl s_client -connect "$host" -servername "$sni" 2>/dev/null | \
        openssl x509 -noout -subject 2>/dev/null
}

get_cert_san() {
    local host="$1"
    local sni="$2"
    echo | timeout 5 openssl s_client -connect "$host" -servername "$sni" 2>/dev/null | \
        openssl x509 -noout -ext subjectAltName 2>/dev/null
}

# Test TLS health endpoint on proxy port
test_proxy_tls_health() {
    local host="$1"
    local sni="$2"
    # Use --connect-to instead of --resolve since we have hostnames not IPs
    curl -sf --connect-to "${sni}:9014:${host}" -k "https://${sni}:9014/health" > /dev/null 2>&1
}

# ==================== Setup ====================

# Configure DNS credential and domain certs via Admin RPC
setup_certbot_config() {
    log_info "Setting up DNS credential and domain cert configs..."

    # Set global ACME URL
    log_info "Setting global ACME URL..."
    local acme_response=$(curl -sf -X POST "${GATEWAY_1_ADMIN}/prpc/Admin.SetGlobalAcmeUrl" \
        -H "Content-Type: application/json" \
        -d '{
            "acme_url": "'"${ACME_URL}"'"
        }' 2>&1)

    if [ $? -ne 0 ]; then
        log_error "Failed to set global ACME URL: $acme_response"
        return 1
    fi
    log_info "Global ACME URL set: $acme_response"

    # Create DNS credential
    log_info "Creating DNS credential..."
    local cred_response=$(curl -sf -X POST "${GATEWAY_1_ADMIN}/prpc/Admin.CreateDnsCredential" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "test-cloudflare",
            "provider_type": "cloudflare",
            "cf_api_token": "'"${CF_API_TOKEN}"'",
            "cf_api_url": "'"${CF_API_URL}"'",
            "set_as_default": true,
            "dns_txt_ttl": 1,
            "max_dns_wait": 0
        }' 2>&1)

    if [ $? -ne 0 ]; then
        log_error "Failed to create DNS credential: $cred_response"
        return 1
    fi
    log_info "DNS credential created: $cred_response"

    # Add domain cert config for each domain (no acme_url needed - uses global)
    for domain in $CERT_DOMAINS; do
        log_info "Adding domain cert config for: $domain"
        local domain_response=$(curl -sf -X POST "${GATEWAY_1_ADMIN}/prpc/Admin.AddDomainCert" \
            -H "Content-Type: application/json" \
            -d '{
                "domain": "'"${domain}"'",
                "enabled": true
            }' 2>&1)

        if [ $? -ne 0 ]; then
            log_error "Failed to add domain cert config for $domain: $domain_response"
            return 1
        fi
        log_info "Domain cert config added: $domain_response"
    done

    # Trigger certificate renewal for each domain
    for domain in $CERT_DOMAINS; do
        log_info "Triggering certificate renewal for: $domain"
        local renew_response=$(curl -sf -X POST "${GATEWAY_1_ADMIN}/prpc/Admin.RenewDomainCert" \
            -H "Content-Type: application/json" \
            -d '{
                "domain": "'"${domain}"'",
                "force": true
            }' 2>&1)

        if [ $? -ne 0 ]; then
            log_warn "RenewCert failed for $domain (may retry): $renew_response"
        else
            log_info "RenewCert triggered for $domain: $renew_response"
        fi
    done

    return 0
}

# ==================== Tests ====================

test_mock_cf_api_health() {
    curl -sf "${MOCK_CF_API}/health" > /dev/null
}

test_pebble_directory() {
    curl -sf "http://pebble:14000/dir" > /dev/null
}

test_gateway_health() {
    local node="$1"
    local url="$2"
    curl -sf "${url}/health" > /dev/null
}

test_dns_record_created() {
    # Check if any TXT records were created in mock CF API
    local records=$(curl -sf "${MOCK_CF_API}/api/records" 2>/dev/null)
    if echo "$records" | grep -q "TXT"; then
        return 0
    fi
    return 1
}

test_certificate_issued() {
    local host="$1"
    local sni="$2"
    local serial=$(get_cert_serial "$host" "$sni")
    if [ -n "$serial" ]; then
        return 0
    fi
    return 1
}

test_certificates_match() {
    local sni="$1"
    local serial1=$(get_cert_serial "$GATEWAY_1_PROXY" "$sni")
    local serial2=$(get_cert_serial "$GATEWAY_2_PROXY" "$sni")
    local serial3=$(get_cert_serial "$GATEWAY_3_PROXY" "$sni")

    # Use >&2 to output to stderr so it doesn't affect the return code capture
    log_info "Gateway 1 cert serial ($sni): $serial1" >&2
    log_info "Gateway 2 cert serial ($sni): $serial2" >&2
    log_info "Gateway 3 cert serial ($sni): $serial3" >&2

    if [ "$serial1" = "$serial2" ] && [ "$serial2" = "$serial3" ] && [ -n "$serial1" ]; then
        return 0
    fi
    return 1
}

test_certificate_from_pebble() {
    local sni="$1"
    local issuer=$(get_cert_issuer "$GATEWAY_1_PROXY" "$sni")
    if echo "$issuer" | grep -qi "pebble"; then
        return 0
    fi
    return 1
}

# Test SNI-based certificate selection - verify correct wildcard cert is returned
test_sni_cert_selection() {
    local host="$1"
    local sni="$2"
    local expected_wildcard="$3"  # e.g., "*.test0.local"

    local san=$(get_cert_san "$host" "$sni")
    if echo "$san" | grep -q "$expected_wildcard"; then
        return 0
    fi
    return 1
}

# ==================== Main ====================

main() {
    log_info "=========================================="
    log_info "dstack-gateway Certbot E2E Test"
    log_info "=========================================="
    echo ""

    # Phase 1: Check mock services
    log_info "Phase 1: Verify mock services"
    log_info "------------------------------------------"

    run_test "Mock CF DNS API health" "$(test_mock_cf_api_health; echo $?)"
    run_test "Pebble ACME directory" "$(test_pebble_directory; echo $?)"

    echo ""

    # Phase 2: Check gateway cluster
    log_info "Phase 2: Verify gateway cluster"
    log_info "------------------------------------------"

    run_test "Gateway 1 health" "$(test_gateway_health 1 "$GATEWAY_1_DEBUG"; echo $?)"
    run_test "Gateway 2 health" "$(test_gateway_health 2 "$GATEWAY_2_DEBUG"; echo $?)"
    run_test "Gateway 3 health" "$(test_gateway_health 3 "$GATEWAY_3_DEBUG"; echo $?)"

    echo ""

    # Phase 2.5: Configure certbot via Admin API
    log_info "Phase 2.5: Configure certbot"
    log_info "------------------------------------------"

    if ! setup_certbot_config; then
        log_error "Failed to setup certbot configuration"
    fi

    echo ""

    # Phase 3: Wait for certificate issuance
    log_info "Phase 3: Certificate issuance (multi-domain)"
    log_info "------------------------------------------"

    # Wait for first certificate to be issued
    local first_domain=$(echo "$CERT_DOMAINS" | cut -d' ' -f1)
    local first_sni=$(wildcard_to_sni "$first_domain")
    log_info "Waiting for certificate to be issued (up to 120s)..."
    log_info "First domain: $first_domain, SNI: $first_sni"
    local waited=0
    local max_wait=120

    while [ $waited -lt $max_wait ]; do
        if test_certificate_issued "$GATEWAY_1_PROXY" "$first_sni"; then
            log_info "Certificate detected on Gateway 1 for $first_sni!"
            break
        fi
        sleep 5
        waited=$((waited + 5))
        log_info "Waiting... (${waited}s)"
    done

    # Test certificate issuance for each domain
    for domain in $CERT_DOMAINS; do
        local test_sni=$(wildcard_to_sni "$domain")
        run_test "Certificate issued for $domain (SNI: $test_sni)" \
            "$(test_certificate_issued "$GATEWAY_1_PROXY" "$test_sni"; echo $?)"
    done

    # Give time for sync
    log_info "Waiting 20s for certificate sync across cluster..."
    sleep 20

    echo ""

    # Phase 4: Verify certificate consistency across cluster
    log_info "Phase 4: Certificate consistency (multi-domain)"
    log_info "------------------------------------------"

    for domain in $CERT_DOMAINS; do
        local test_sni=$(wildcard_to_sni "$domain")
        run_test "All gateways have same cert for $domain" \
            "$(test_certificates_match "$test_sni"; echo $?)"
        run_test "Cert for $domain issued by Pebble" \
            "$(test_certificate_from_pebble "$test_sni"; echo $?)"
    done

    echo ""

    # Phase 5: Test SNI-based certificate selection
    log_info "Phase 5: SNI-based certificate selection"
    log_info "------------------------------------------"

    for domain in $CERT_DOMAINS; do
        local test_sni=$(wildcard_to_sni "$domain")
        run_test "SNI $test_sni returns $domain cert" \
            "$(test_sni_cert_selection "$GATEWAY_1_PROXY" "$test_sni" "$domain"; echo $?)"
    done

    echo ""

    # Phase 6: Test proxy TLS health endpoint
    log_info "Phase 6: Proxy TLS health endpoint"
    log_info "------------------------------------------"

    for domain in $CERT_DOMAINS; do
        local test_sni=$(wildcard_to_sni "$domain")
        run_test "Gateway 1 proxy health via TLS ($test_sni)" \
            "$(test_proxy_tls_health "$GATEWAY_1_PROXY" "$test_sni"; echo $?)"
        run_test "Gateway 2 proxy health via TLS ($test_sni)" \
            "$(test_proxy_tls_health "$GATEWAY_2_PROXY" "$test_sni"; echo $?)"
        run_test "Gateway 3 proxy health via TLS ($test_sni)" \
            "$(test_proxy_tls_health "$GATEWAY_3_PROXY" "$test_sni"; echo $?)"
    done

    echo ""

    # Phase 7: Check DNS records (optional - records only created for fresh cert issuance)
    log_info "Phase 7: DNS-01 challenge records (informational)"
    log_info "------------------------------------------"

    if test_dns_record_created; then
        log_success "DNS TXT records found in mock API"
    else
        log_info "No DNS TXT records found (expected if certs were reused from cache)"
    fi

    # Show DNS records for debugging
    log_info "DNS records in mock API:"
    curl -sf "${MOCK_CF_API}/api/records" 2>/dev/null | head -100 || true

    echo ""

    # Summary
    log_info "=========================================="
    log_info "Test Summary"
    log_info "=========================================="
    log_info "Passed: $TESTS_PASSED"
    log_info "Failed: $TESTS_FAILED"
    log_info "Domains tested: $(echo "$CERT_DOMAINS" | wc -w)"
    log_info "Certificates: $CERT_DOMAINS"

    if [ $TESTS_FAILED -eq 0 ]; then
        log_success "All tests passed!"
        exit 0
    else
        log_fail "Some tests failed!"
        exit 1
    fi
}

# Run main
main
