# Nginx Configuration

## Overview

Nginx configuration is handled in two distinct phases:

1. **Phase 1: Base Setup** (`install_nginx_base.sh`)
   - Installs Nginx and Certbot via Ansible
   - Obtains SSL certificate from Let's Encrypt
   - Serves a placeholder page
   - Fully automated, multi-distribution support

2. **Phase 2: Application Config** (`install_nginx_app.sh`)
   - Removes the placeholder config
   - Deploys ColdFront reverse proxy
   - Configures static file serving and Gunicorn socket proxy

## Files in This Directory

| File | Purpose |
|------|---------|
| `coldfront-http.conf.template` | ColdFront HTTP-only config (proxy to Gunicorn) |
| `coldfront-https.conf.reference` | Reference for expected HTTPS config post-certbot |
| `README.md` | This file |

## Standard Workflow

### Step 1: Run Nginx Base Installation

```bash
sudo ./scripts/install_nginx_base.sh --domain YOUR_DOMAIN --email YOUR_EMAIL
```

This uses Ansible to:
- Install Nginx
- Install Certbot
- Obtain SSL certificate
- Configure HTTP→HTTPS redirect
- Start Nginx with a placeholder page

### Step 2: Deploy ColdFront Application Configuration

```bash
sudo ./scripts/install_nginx_app.sh --domain YOUR_DOMAIN
```

This will:
- Remove the placeholder config
- Deploy the ColdFront proxy config
- Reload Nginx

## Manual HTTPS Setup (Not Recommended)

If you need to bypass the Ansible-based setup:

1. Install Nginx manually
2. Copy `coldfront-http.conf.template` to `/etc/nginx/conf.d/`
3. Replace `{{DOMAIN_NAME}}` with your domain
4. Run `sudo certbot --nginx -d your-domain.org`
5. Certbot will automatically add HTTPS configuration

## Troubleshooting

### Error: "nginx: [emerg] cannot load certificate"

**Cause:** Nginx config references SSL certificates that don't exist yet.

**Solution:** Use the HTTP-only template and let certbot add HTTPS:
```bash
sudo rm /etc/nginx/conf.d/*.conf
sudo cp coldfront-http.conf.template /etc/nginx/conf.d/coldfront.conf
sudo sed -i 's/{{DOMAIN_NAME}}/your-domain.org/g' /etc/nginx/conf.d/coldfront.conf
sudo nginx -t && sudo systemctl restart nginx
sudo certbot --nginx -d your-domain.org
```

### Deprecation Warning: "listen ... http2"

This is a warning from newer Nginx versions. The site works fine.
To fix after certbot runs, update to use `http2 on;` directive format.

### 502 Bad Gateway

ColdFront service isn't running or socket doesn't exist:
```bash
sudo systemctl status coldfront
ls -la /srv/coldfront/coldfront.sock
sudo systemctl restart coldfront
```
