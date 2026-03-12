---
title: "SSL Certificate Setup"
description: "Obtain Let's Encrypt SSL certificates for dstack services"
section: "Prerequisites"
stepNumber: 2
totalSteps: 7
lastUpdated: 2025-12-09
prerequisites:
  - dns-configuration
tags:
  - ssl
  - certificates
  - letsencrypt
  - https
  - prerequisites
difficulty: intermediate
estimatedTime: "20 minutes"
---

# SSL Certificate Setup

This tutorial guides you through obtaining SSL certificates from Let's Encrypt for your dstack deployment. These certificates enable HTTPS for the local Docker registry and other services.

## What You'll Configure

| Certificate | Used By | Domain Example |
|-------------|---------|----------------|
| Registry certificate | Local Docker registry | `registry.yourdomain.com` |
| Gateway wildcard | dstack Gateway | `*.dstack.yourdomain.com` |

This tutorial covers both the **registry certificate** (for the Docker registry) and the **gateway wildcard certificate** (for application subdomains).

## Prerequisites

Before starting, ensure you have:

- Completed [DNS Configuration](/tutorial/dns-configuration) - DNS records must exist
- Domain pointing to your server (verified via `dig`)
- Port 80 accessible for Let's Encrypt HTTP-01 challenge
- SSH access to your TDX server

### Verify DNS Resolution

```bash
# Replace with your domain
dig +short registry.yourdomain.com
```

Should return your server's IP address. If not, the certificate request will fail.

---


## Manual Setup

If you prefer to configure manually, follow these steps.

### Step 1: Install Certbot

```bash
sudo apt update
sudo apt install -y certbot
```

Verify installation:

```bash
certbot --version
```

### Step 2: Stop Services Using Port 80

Let's Encrypt's HTTP-01 challenge requires port 80. Stop any services using it:

```bash
# Check what's using port 80
sudo ss -tlnp | grep :80

# Stop HAProxy if running (or nginx on older setups)
sudo systemctl stop haproxy 2>/dev/null || true
sudo systemctl stop nginx 2>/dev/null || true

# Stop apache if running
sudo systemctl stop apache2 2>/dev/null || true
```

### Step 3: Obtain Registry Certificate

Request a certificate for your registry domain:

```bash
sudo certbot certonly --standalone \
  -d registry.yourdomain.com \
  --non-interactive \
  --agree-tos \
  --email your-email@example.com
```

**Replace:**
- `registry.yourdomain.com` with your actual registry domain
- `your-email@example.com` with your email (for expiry notifications)

**Expected output:**

```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/registry.yourdomain.com/privkey.pem
```

### Step 4: Verify Certificate

Check the certificate is valid:

```bash
sudo openssl x509 -in /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem -text -noout | \
  grep -E "(Subject:|Not After)"
```

Expected output shows your domain and expiry date (90 days from now):

```
        Subject: CN = registry.yourdomain.com
            Not After : Apr 21 12:00:00 2026 GMT
```

HAProxy uses these certificates via combined PEM files in `/etc/haproxy/certs/` (created by the renewal hook).

---

## Certificate Auto-Renewal

Let's Encrypt certificates expire after 90 days. Certbot sets up automatic renewal.

### Verify Auto-Renewal Timer

```bash
systemctl status certbot.timer
```

Should show the timer is active and running.

### Test Renewal Process

```bash
sudo certbot renew --dry-run
```

Should complete without errors.

### Set Up Renewal Hook for HAProxy

When certificates renew, HAProxy needs updated combined PEM files and a reload:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-haproxy.sh > /dev/null << 'EOF'
#!/bin/bash
# Reload HAProxy certificates after Let's Encrypt renewal

# Combine certificates for HAProxy (cert + key in single file)
cat /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem \
    /etc/letsencrypt/live/registry.yourdomain.com/privkey.pem \
    > /etc/haproxy/certs/registry.pem

# Wildcard cert if it exists
if [ -f /etc/letsencrypt/live/dstack.yourdomain.com/fullchain.pem ]; then
    cat /etc/letsencrypt/live/dstack.yourdomain.com/fullchain.pem \
        /etc/letsencrypt/live/dstack.yourdomain.com/privkey.pem \
        > /etc/haproxy/certs/wildcard.pem
fi

chmod 600 /etc/haproxy/certs/*.pem

systemctl reload haproxy

echo "HAProxy certificates updated: $(date)"
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-haproxy.sh
```

**Update the domain names** in the script to match your actual domains.

HAProxy requires certificates in a combined format (cert + key in one file), so the renewal hook concatenates them.

---

## Gateway Wildcard Certificate (Optional)

The dstack Gateway requires a wildcard certificate for automatic subdomain provisioning. This uses DNS-01 challenge with Cloudflare:

```bash
# Install Cloudflare plugin
sudo apt install -y python3-certbot-dns-cloudflare

# Create credentials file
sudo mkdir -p /etc/cloudflare
sudo tee /etc/cloudflare/credentials.ini > /dev/null << EOF
dns_cloudflare_api_token = YOUR_CLOUDFLARE_API_TOKEN
EOF
sudo chmod 600 /etc/cloudflare/credentials.ini

# Obtain wildcard certificate
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/cloudflare/credentials.ini \
  -d "*.dstack.yourdomain.com" \
  -d "dstack.yourdomain.com" \
  --non-interactive \
  --agree-tos \
  --email your-email@example.com
```

The certificate will be used by the gateway in the [Gateway Build & Configuration](/tutorial/gateway-build-configuration) tutorial.

---

## Verification Summary

Verify your SSL certificate setup:

```bash
# Check certbot installed
certbot --version

# Check auto-renewal timer is active
systemctl is-active certbot.timer

# List all certificates
sudo certbot certificates
```

### Registry Certificate

```bash
# Check certificate exists (replace with your domain)
sudo ls -la /etc/letsencrypt/live/registry.yourdomain.com/

# Check certificate validity
sudo openssl x509 -in /etc/letsencrypt/live/registry.yourdomain.com/fullchain.pem -noout -dates
```

HAProxy uses combined PEM files in `/etc/haproxy/certs/` which are updated by the renewal hook.

### Gateway Wildcard Certificate

```bash
# Check wildcard certificate exists (replace with your domain)
sudo ls -la /etc/letsencrypt/live/dstack.yourdomain.com/

# Check certificate covers wildcard
sudo openssl x509 -in /etc/letsencrypt/live/dstack.yourdomain.com/fullchain.pem -noout -text | grep -A1 "Subject Alternative Name"
```

Should show both `*.dstack.yourdomain.com` and `dstack.yourdomain.com`.

Save as `verify-ssl.sh`, update `DOMAIN`, make executable with `chmod +x verify-ssl.sh`, and run.

---

## Troubleshooting

For detailed solutions, see the [Prerequisites Troubleshooting Guide](/tutorial/troubleshooting-prerequisites#ssl-certificate-setup-issues):

- [Challenge Failed: Could not connect](/tutorial/troubleshooting-prerequisites#challenge-failed-could-not-connect)
- [Rate Limit Exceeded](/tutorial/troubleshooting-prerequisites#rate-limit-exceeded)
- [DNS Resolution Failed](/tutorial/troubleshooting-prerequisites#dns-resolution-failed)
- [HAProxy Can't Read Certificates](/tutorial/troubleshooting-prerequisites#haproxy-cant-read-certificates)

---

## Next Steps

With SSL certificates configured, proceed to:

- [HAProxy Setup](/tutorial/haproxy-setup) - Configure HAProxy as TLS entry point
- [Gramine Key Provider](/tutorial/gramine-key-provider) - Deploy SGX-based key provider
- [Local Docker Registry](/tutorial/local-docker-registry) - Uses these certificates

## Additional Resources

- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Certbot Documentation](https://certbot.eff.org/docs/)
- [Cloudflare DNS Plugin](https://certbot-dns-cloudflare.readthedocs.io/)
