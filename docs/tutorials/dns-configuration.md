---
title: "DNS Configuration"
description: "Configure Cloudflare DNS with wildcard domain support for dstack gateway deployment"
section: "Prerequisites"
stepNumber: 1
totalSteps: 7
lastUpdated: 2025-11-01

tags:
  - dns
  - cloudflare
  - prerequisites
difficulty: beginner
estimatedTime: "30 minutes"
---

# DNS Configuration

In this tutorial, you'll configure DNS for your dstack deployment using Cloudflare. The dstack gateway requires a wildcard domain to automatically provision subdomains for deployed applications with TLS certificates.

## Why Cloudflare?

The dstack gateway is designed to work with Cloudflare's DNS API for automatic TLS certificate provisioning. While you can use other DNS providers, Cloudflare integration provides:

- **Automatic TLS**: Gateway provisions Let's Encrypt certificates via DNS-01 challenge
- **Free tier**: No cost for DNS and CDN services
- **Fast propagation**: DNS changes typically propagate within minutes
- **API access**: Programmatic DNS management for automation

## Prerequisites

Before starting, ensure you have:

- A registered domain name (example: `yourdomain.com`)
- Access to your domain registrar's DNS settings
- A Cloudflare account (sign up at https://cloudflare.com if needed)

## Step 1: Add Domain to Cloudflare

### 1.1 Log into Cloudflare Dashboard

Visit https://dash.cloudflare.com and log into your account.

### 1.2 Add Your Domain

1. Click **"+ Add"** in the top right navigation
2. Click **"Connect a domain"** in the submenu
3. Enter your domain name (e.g., `yourdomain.com`) and fill out the rest of the form according to your preferences
4. Click **"Continue"**
5. Select the **Free** plan (unless you need paid features)

### 1.3 Update Nameservers at Your Registrar

Cloudflare will display two nameservers (e.g., `aden.ns.cloudflare.com` and `olga.ns.cloudflare.com`) and instructions for updating your domain. For ease, these steps are:

1. Log into your DNS provider (most likely your registrar)
2. Make sure DNSSEC is off
3. Replace your current nameservers with Cloudflare nameservers
4. Use the **"Check nameservers now"** button to confirm completion

**Note:** Nameserver changes can take 24-48 hours to fully propagate, but often complete within a few hours.

## Step 2: Configure DNS Records

Once your domain is active on Cloudflare, configure the DNS records for dstack.

### 2.1 Add A Record for Host

Create an A record pointing your subdomain to the dstack host server:

1. In Cloudflare dashboard, click on your domain
2. Navigate to **DNS** → **Records**
3. Click **"Add record"**
4. Configure:
   - **Type**: A
   - **Name**: `dstack` (or your preferred subdomain)
   - **IPv4 address**: Your server IP (e.g., `173.231.234.133`)
   - **Proxy status**: DNS only (gray cloud) - **Important!**
   - **TTL**: Auto
5. Click **"Save"**

**Why DNS only?** Cloudflare's proxy (orange cloud) would route traffic through their CDN, breaking TDX attestation. Use **gray cloud (DNS only)** to direct traffic straight to your server.

### 2.2 Add A Record for Docker Registry

Create an A record for the local Docker registry:

1. Click **"Add record"**
2. Configure:
   - **Type**: A
   - **Name**: `registry`
   - **IPv4 address**: Same server IP as above
   - **Proxy status**: DNS only (gray cloud)
   - **TTL**: Auto
3. Click **"Save"**

This creates `registry.yourdomain.com` which is used by the local Docker registry for SSL certificates.

### 2.3 Add Wildcard DNS Record

Create a wildcard A record for application subdomains:

1. Click **"Add record"** again
2. Configure:
   - **Type**: A
   - **Name**: `*.dstack` (wildcard under your subdomain)
   - **IPv4 address**: Same server IP as above
   - **Proxy status**: DNS only (gray cloud)
   - **TTL**: Auto
3. Click **"Save"**

This allows the gateway to automatically provision subdomains like:
- `app1.dstack.yourdomain.com`
- `app2.dstack.yourdomain.com`
- `custom-name.dstack.yourdomain.com`

### 2.4 Add CAA Records (Optional but Recommended)

CAA records restrict which Certificate Authorities can issue certificates for your domain:

1. Click **"Add record"**
2. Configure:
   - **Type**: CAA
   - **Name**: `@` (for root domain, or use `dstack` for subdomain only)
   - **Flags**: `0`
   - **Tag**: Select **"Only allow specific hostnames"** from dropdown
   - **CA domain name**: `letsencrypt.org`
   - **TTL**: Auto
3. Click **"Save"**

Repeat for wildcard subdomain:
1. Click **"Add record"**
2. Configure:
   - **Type**: CAA
   - **Name**: `*.dstack`
   - **Flags**: `0`
   - **Tag**: Select **"Only allow specific hostnames"** from dropdown
   - **CA domain name**: `letsencrypt.org`
   - **TTL**: Auto
3. Click **"Save"**

**Note:** The "Only allow specific hostnames" tag option corresponds to the `issue` tag in CAA record syntax. This ensures only Let's Encrypt can issue certificates for your domain, improving security.

## Step 3: Generate Cloudflare API Token

The dstack gateway needs API access to manage DNS records for TLS certificate provisioning.

### 3.1 Create API Token

1. In Cloudflare dashboard, click your profile icon (top right)
2. Select **"My Profile"**
3. Navigate to **API Tokens** tab
4. Click **"Create Token"**
5. Use the **"Edit zone DNS"** template
6. Configure:
   - **Permissions**:
     - Zone → DNS → Edit
   - **Zone Resources**:
     - Include → Specific zone → Select your domain
   - **TTL**: Not set (token doesn't expire, or set expiration if preferred)
7. Click **"Continue to summary"**
8. Review permissions
9. Click **"Create Token"**

### 3.2 Save API Token Securely

**IMPORTANT:** Copy the API token immediately and save it securely. You'll need this for gateway configuration.

The token will look like: `abcdef123456789_example_token_xyz`

**Store this token securely** - you won't be able to see it again in Cloudflare dashboard. Consider using:
- Password manager
- Encrypted file
- Secret management system (if deploying in production)

### 3.3 Test API Token

Verify the token works with a simple API test:

```bash
# Replace TOKEN with your actual API token
# Replace ZONE_ID with your Cloudflare zone ID (found in domain Overview)
curl -X GET "https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"
```

Expected response: JSON with `"success": true` and list of your DNS records.

NOTE: You can find the zone id on the right site of your domains overview page, under the API section. You may need to scroll to find it.

## Step 4: Test DNS Resolution

Verify your DNS configuration is working correctly.

### 4.1 Test Base Domain

```bash
# Replace with your actual subdomain
dig dstack.yourdomain.com

# Should return your server IP in the ANSWER section
# Example output:
# dstack.yourdomain.com.  300  IN  A  173.231.234.133
```

### 4.2 Test Registry Domain

```bash
dig registry.yourdomain.com

# Should return your server IP
```

### 4.3 Test Wildcard Domain

```bash
# Test a random subdomain under wildcard
dig test.dstack.yourdomain.com
dig app.dstack.yourdomain.com
dig anything.dstack.yourdomain.com

# All should return your server IP
```

### 4.4 Verify from Multiple Locations

DNS propagation can vary by location. Test from different DNS resolvers:

```bash
# Google DNS
dig @8.8.8.8 dstack.yourdomain.com

# Cloudflare DNS
dig @1.1.1.1 dstack.yourdomain.com

# Your local DNS (no @)
dig dstack.yourdomain.com
```

All should return your server IP.

## Step 5: Personalize Tutorial Commands

The tutorials throughout this site use `yourdomain.com` as a placeholder domain. Now that your DNS is configured, you can replace all placeholders at once to avoid copy-paste errors.

### Set Your Domains

```bash
# Set your actual domains
export BASE_DOMAIN="yourdomain.com"                   # Your registered domain
export REGISTRY_DOMAIN="registry.${BASE_DOMAIN}"      # Docker registry subdomain
export GATEWAY_DOMAIN="dstack.${BASE_DOMAIN}"          # Gateway base domain (from *.dstack record)
export KMS_DOMAIN="kms.${GATEWAY_DOMAIN}"             # KMS domain
```

### Replace in Tutorials

```bash
cd ~/dstack-info

# Replace all placeholders (most specific patterns first)
find src/content/tutorials -name "*.md" -exec sed -i \
  -e "s|registry\.yourdomain\.com|${REGISTRY_DOMAIN}|g" \
  -e "s|vmm\.dstack\.yourdomain\.com|vmm.${GATEWAY_DOMAIN}|g" \
  -e "s|kms\.yourdomain\.com|${KMS_DOMAIN}|g" \
  -e "s|dstack\.yourdomain\.com|${GATEWAY_DOMAIN}|g" \
  -e "s|yourdomain\.com|${BASE_DOMAIN}|g" \
  {} +
```

### Verify Replacements

```bash
# Should return no results (or only this tutorial explaining the placeholder)
grep -r "yourdomain" src/content/tutorials/ | grep -v "dns-configuration.md"
```

> **Note:** These changes are local to your copy of the tutorials. Don't commit them to git — they're specific to your deployment. If you pull updates later, re-run the sed commands.

## Step 6: DNS Record Summary

After completion, you should have these DNS records in Cloudflare:

| Type | Name | Value | Proxy Status |
|------|------|-------|--------------|
| A | `dstack` | Your server IP | DNS only (gray) |
| A | `registry` | Your server IP | DNS only (gray) |
| A | `*.dstack` | Your server IP | DNS only (gray) |
| CAA | `dstack` | `letsencrypt.org` | N/A |
| CAA | `*.dstack` | `letsencrypt.org` | N/A |

## Troubleshooting

For detailed solutions, see the [Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#dns-configuration-issues):

- [DNS Not Resolving](/tutorial/troubleshooting-prerequisites#dns-not-resolving)
- [Wildcard Not Working](/tutorial/troubleshooting-prerequisites#wildcard-not-working)
- [API Token Permission Denied](/tutorial/troubleshooting-prerequisites#api-token-permission-denied)
- [Propagation Taking Too Long](/tutorial/troubleshooting-prerequisites#propagation-taking-too-long)

## Next Steps

With DNS configured, you're ready to proceed to blockchain setup:

- **Next Tutorial:** [Blockchain Wallet Setup](/tutorial/blockchain-setup)

After completing all prerequisites (DNS + Blockchain), you'll configure the dstack gateway to use:
- Your domain for TLS certificate provisioning
- Your Cloudflare API token for DNS management
- Your blockchain wallet for KMS interactions

---

**Important Notes:**

- Keep your Cloudflare API token secure - treat it like a password
- Use DNS only (gray cloud) for dstack records to preserve TDX attestation
- Wildcard DNS enables automatic subdomain provisioning for applications
- CAA records improve security by restricting certificate issuance
