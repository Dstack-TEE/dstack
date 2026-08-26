#!/bin/bash
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

# Must match `auth_token` in configs/gateway-*.toml
ADMIN_TOKEN="e2e-admin-token"
ADMIN_AUTH_HEADER="Authorization: Bearer ${ADMIN_TOKEN}"

# External services
MOCK_CF_API="http://mock-cf-dns-api:8080"
PEBBLE_DIR="http://pebble:14000/dir"

# Certificate domains to test (base domains, certs will be issued for *.domain)
CERT_DOMAINS="test0.local test1.local test2.local"

# A dns-persist-01 domain. Kept out of CERT_DOMAINS because the certificate
# phases check TLS through the proxy, which needs an app behind the domain;
# here the certificate is checked through the admin API instead.
PERSIST_DOMAIN="persist0.local"

# Mock zone ID, as server.py derives it from the zone name.
PERSIST_ZONE_ID="zone-persist0-local"

# Pebble answers to this name, not to letsencrypt.org, and a validation record
# naming a CA the challenge does not list is ignored.
PERSIST_ISSUER="pebble.letsencrypt.org"

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

# ==================== Domain Helpers ====================

# Convert base domain to test SNI: test0.local -> gateway.test0.local
# Uses "gateway" as it's a special app_id that proxies to gateway's own endpoints
get_test_sni() {
    echo "gateway.${1}"
}

# Convert base domain to wildcard format for certificate SAN check
get_wildcard_domain() {
    echo "*.${1}"
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

# ==================== dns-persist-01 Helpers ====================

admin_post() {
    curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.$1" \
        -H "${ADMIN_AUTH_HEADER}" \
        -H "Content-Type: application/json" \
        -d "$2"
}

# A dns-persist-01 domain must be accepted without any DNS credential: holding
# none is the entire point of the challenge.
test_persist_domain_needs_no_credential() {
    # Idempotent: the KV store outlives a run, and an "already exists" rejection
    # would mask whether the add is accepted at all.
    admin_post DeleteZtDomain '{"domain": "'"${PERSIST_DOMAIN}"'"}' > /dev/null 2>&1 || true
    admin_post AddZtDomain \
        '{"domain": "'"${PERSIST_DOMAIN}"'", "port": 443, "challenge": "dns-persist-01"}' \
        > /dev/null
}

# The record is the setup under this challenge, so the API has to render it.
test_persist_domain_reports_its_record() {
    local info
    info=$(admin_post GetZtDomain '{"domain": "'"${PERSIST_DOMAIN}"'"}') || return 1
    # Fixed strings throughout: as a regex, "_validation-persist.*.domain"
    # matches the very name it is meant to rule out.
    #
    # The record sits on the base name. ACME strips the wildcard before it
    # creates the authorization, so a record published under the "*." form is
    # never read.
    if echo "$info" | grep -qF "_validation-persist.*.${PERSIST_DOMAIN}"; then
        return 1
    fi
    echo "$info" | grep -qF "_validation-persist.${PERSIST_DOMAIN}. IN TXT" || return 1
    echo "$info" | grep -qF "accounturi=" || return 1
    # policy=wildcard, because the gateway only ever orders *.{domain}.
    echo "$info" | grep -qF "policy=wildcard"
}

# UpdateZtDomain replaces the whole record, and `challenge` is optional so that
# a caller which does not know the field leaves it alone. A client that predates
# it -- a cached dashboard bundle, a script, an older SDK -- must not be able to
# downgrade the domain to dns-01, which its published CAA would then refuse.
test_persist_challenge_survives_an_edit() {
    admin_post UpdateZtDomain \
        '{"domain": "'"${PERSIST_DOMAIN}"'", "port": 443, "priority": 5}' > /dev/null || return 1
    local info
    info=$(admin_post GetZtDomain '{"domain": "'"${PERSIST_DOMAIN}"'"}') || return 1
    echo "$info" | grep -q '"priority":5' || return 1
    echo "$info" | grep -q "dns-persist-01"
}

# Publish the validation record the way a zone owner would: once, by hand,
# before the first order. certbot never writes it -- that is the whole point --
# so the harness stands in for the operator here.
#
# The record has to be the one the gateway reports, byte for byte, because that
# is what Pebble parses as an RFC 8659 issue-value and matches against its own
# issuer name and the requesting account.
publish_persist_record() {
    local info rdata
    info=$(admin_post GetZtDomain '{"domain": "'"${PERSIST_DOMAIN}"'"}') || return 1
    # "_validation-persist.<domain>. IN TXT \"<rdata>\"" -> <rdata>
    rdata=$(echo "$info" \
        | tr ',' '\n' \
        | grep -F "_validation-persist.${PERSIST_DOMAIN}. IN TXT" \
        | sed -e 's/.*IN TXT \\"//' -e 's/\\".*//')
    if [ -z "$rdata" ]; then
        log_error "no validation record reported for ${PERSIST_DOMAIN}" >&2
        return 1
    fi
    # stderr, not stdout: run_test captures the function's stdout and compares
    # the whole of it against "0".
    log_info "Publishing: _validation-persist.${PERSIST_DOMAIN} TXT ${rdata}" >&2
    curl -sf -X POST "${MOCK_CF_API}/client/v4/zones/${PERSIST_ZONE_ID}/dns_records" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "type": "TXT",
            "name": "_validation-persist.'"${PERSIST_DOMAIN}"'",
            "content": "'"${rdata}"'",
            "ttl": 1
        }' > /dev/null
}

# The point of the whole exercise: a certificate is issued for a domain the
# gateway holds no credential for, and the CA validates the published record
# rather than being told to skip it -- Pebble runs without
# PEBBLE_VA_ALWAYS_VALID here.
test_persist_domain_issues_a_certificate() {
    admin_post RenewZtDomainCert \
        '{"domain": "'"${PERSIST_DOMAIN}"'", "force": true}' > /dev/null 2>&1 || true

    # The renewal outlives the request that triggered it, and spends the
    # advisory DNS wait -- half of renew_timeout -- before it reaches the CA.
    local i=0
    while [ $i -lt 60 ]; do
        if admin_post GetZtDomain '{"domain": "'"${PERSIST_DOMAIN}"'"}' \
            | grep -q '"has_cert":true'; then
            return 0
        fi
        sleep 2
        i=$((i + 1))
    done
    return 1
}

# The claim the whole challenge exists for: certbot reads DNS and never writes
# it. Scoped to the record certbot would have written -- the zone is not empty,
# because the harness published the validation record above standing in for the
# operator, and that one is the point rather than a violation.
test_persist_domain_never_touches_the_provider() {
    local records
    records=$(curl -sf "${MOCK_CF_API}/api/records" 2>/dev/null || echo "[]")
    ! echo "$records" | grep -qF "_acme-challenge.${PERSIST_DOMAIN}"
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
    local proxy
    proxy=$(echo "$GATEWAY_PROXIES" | cut -d' ' -f1)
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

    # Set ACME URL and the name this CA is known by. The issuer name is what a
    # dns-persist-01 record has to carry, and it is also what CAA names for
    # dns-01, so it is one setting for the whole deployment.
    # renew_timeout also bounds the pre-order DNS self-check, which is capped at
    # half of it. The default 300s would have a dns-persist-01 order sit for
    # 150s waiting on a record this harness never publishes.
    log_info "Setting ACME URL: ${ACME_URL} (issuer ${PERSIST_ISSUER})"
    if ! curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.SetCertbotConfig" \
        -H "${ADMIN_AUTH_HEADER}" \
        -H "Content-Type: application/json" \
        -d '{
            "acme_url": "'"${ACME_URL}"'",
            "issuer_domain_name": "'"${PERSIST_ISSUER}"'",
            "renew_timeout_secs": 60
        }' > /dev/null; then
        log_error "Failed to set certbot config"
        return 1
    fi

    # Create DNS credential
    log_info "Creating DNS credential..."
    if ! curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.CreateDnsCredential" \
        -H "${ADMIN_AUTH_HEADER}" \
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
            -H "${ADMIN_AUTH_HEADER}" \
            -H "Content-Type: application/json" \
            -d '{"domain": "'"${domain}"'"}' > /dev/null || true

        log_info "Triggering renewal for: $domain"
        curl -sf -X POST "${GATEWAY_ADMIN}/prpc/Admin.RenewZtDomainCert" \
            -H "${ADMIN_AUTH_HEADER}" \
            -H "Content-Type: application/json" \
            -d '{"domain": "'"${domain}"'", "force": true}' > /dev/null || \
            log_warn "Renewal request failed for $domain (may retry)"
    done

    return 0
}

# Returns 0 if HTTP status code from $1 args equals $2.
http_status_eq() {
    local expected="$1"
    shift
    local actual
    actual=$(curl -s -o /dev/null -w '%{http_code}' "$@")
    [ "$actual" = "$expected" ]
}

# Returns 0 if all three admin auth checks pass: missing 401, wrong 401, right 200.
test_admin_auth() {
    log_info "checking admin auth on ${GATEWAY_ADMIN}"
    # Missing token → 401
    http_status_eq 401 "${GATEWAY_ADMIN}/prpc/Admin.Status" \
        || { log_error "no-token request did not return 401"; return 1; }
    # Wrong token → 401
    http_status_eq 401 "${GATEWAY_ADMIN}/prpc/Admin.Status" \
        -H "Authorization: Bearer wrong-token" \
        || { log_error "wrong-token request did not return 401"; return 1; }
    # Correct token → 200
    http_status_eq 200 "${GATEWAY_ADMIN}/prpc/Admin.Status" \
        -H "${ADMIN_AUTH_HEADER}" \
        || { log_error "valid-token request did not return 200"; return 1; }
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

    # Phase 3: Admin auth gating
    log_phase 3 "Admin token auth"
    run_test "Admin endpoint accepts valid token and rejects missing/wrong" \
        "$(test_admin_auth; echo $?)"

    # Phase 4: Configure certbot
    log_phase 4 "Configure certbot"
    if ! setup_certbot_config; then
        log_error "Failed to setup certbot configuration"
    fi

    # Phase 5: Certificate issuance
    log_phase 5 "Certificate issuance"
    local first_domain first_sni first_proxy
    first_domain=$(echo "$CERT_DOMAINS" | cut -d' ' -f1)
    first_sni=$(get_test_sni "$first_domain")
    first_proxy=$(echo "$GATEWAY_PROXIES" | cut -d' ' -f1)

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

    local sni wildcard
    for domain in $CERT_DOMAINS; do
        sni=$(get_test_sni "$domain")
        run_test "Certificate issued for $domain" \
            "$(test_certificate_issued "$first_proxy" "$sni"; echo $?)"
    done

    log_info "Waiting 20s for cluster sync..."
    sleep 20

    # Phase 6: Certificate consistency
    log_phase 6 "Certificate consistency"
    for domain in $CERT_DOMAINS; do
        sni=$(get_test_sni "$domain")
        run_test "All gateways have same cert for $domain" \
            "$(test_certificates_match "$sni"; echo $?)"
        run_test "Cert for $domain issued by Pebble" \
            "$(test_certificate_from_pebble "$sni"; echo $?)"
    done

    # Phase 7: SNI-based selection
    log_phase 7 "SNI-based certificate selection"
    for domain in $CERT_DOMAINS; do
        sni=$(get_test_sni "$domain")
        wildcard=$(get_wildcard_domain "$domain")
        run_test "SNI $sni returns $wildcard cert" \
            "$(test_sni_cert_selection "$first_proxy" "$sni" "$wildcard"; echo $?)"
    done

    # Phase 8: Proxy TLS health
    log_phase 8 "Proxy TLS health endpoint"
    local i
    for domain in $CERT_DOMAINS; do
        sni=$(get_test_sni "$domain")
        i=1
        for proxy in $GATEWAY_PROXIES; do
            run_test "Gateway $i TLS health ($sni)" \
                "$(test_proxy_tls_health "$proxy" "$sni"; echo $?)"
            i=$((i + 1))
        done
    done

    # Phase 9: DNS records (informational)
    log_phase 9 "DNS-01 challenge records"
    local records
    records=$(curl -sf "${MOCK_CF_API}/api/records" 2>/dev/null || echo "")
    if echo "$records" | grep -q "TXT"; then
        log_success "DNS TXT records found"
    else
        log_info "No DNS TXT records (expected if certs cached)"
    fi

    # Phase 10: dns-persist-01 plumbing, up to but not including the CA
    log_phase 10 "dns-persist-01 without a DNS credential"
    run_test "Domain accepted with no DNS credential" \
        "$(test_persist_domain_needs_no_credential; echo $?)"
    run_test "Challenge survives an edit that omits it" \
        "$(test_persist_challenge_survives_an_edit; echo $?)"
    # The record names the ACME account, so it can only be rendered -- and
    # published -- once one exists. Registering is what the first order does.
    run_test "Required validation record is reported" \
        "$(test_persist_domain_reports_its_record; echo $?)"
    run_test "Validation record publishes" \
        "$(publish_persist_record; echo $?)"
    run_test "Certificate issues without a DNS credential" \
        "$(test_persist_domain_issues_a_certificate; echo $?)"
    run_test "No DNS record is ever written for it" \
        "$(test_persist_domain_never_touches_the_provider; echo $?)"

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
