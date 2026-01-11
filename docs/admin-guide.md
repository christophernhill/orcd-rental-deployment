# ORCD Rental Portal - Administrator Guide

This guide provides complete instructions for deploying and maintaining the ORCD Rental Portal. The portal is built on ColdFront with the ORCD Direct Charge plugin and uses Globus OIDC for MIT authentication.

**Supported Distributions:**
- Amazon Linux 2023 (primary target)
- RHEL 8/9, Rocky Linux, AlmaLinux
- Debian 11/12
- Ubuntu 22.04/24.04

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Infrastructure Setup](#2-infrastructure-setup)
3. [Phase 1: Nginx Base Installation](#3-phase-1-nginx-base-installation)
4. [Phase 2: ColdFront Installation](#4-phase-2-coldfront-installation)
5. [Phase 3: Nginx Application Configuration](#5-phase-3-nginx-application-configuration)
6. [Globus OAuth Configuration](#6-globus-oauth-configuration)
7. [Service Configuration](#7-service-configuration)
8. [Database Initialization](#8-database-initialization)
9. [Post-Installation Setup](#9-post-installation-setup)
10. [Maintenance Operations](#10-maintenance-operations)
11. [Troubleshooting](#11-troubleshooting)

---

## Installation Overview

The installation is split into three phases:

```
Phase 1: Prerequisites       Phase 2: ColdFront         Phase 3: App Config
┌─────────────────────┐      ┌─────────────────────┐    ┌─────────────────────┐
│ install_prereqs.sh  │      │ install.sh          │    │ install_nginx_app   │
│                     │      │                     │    │                     │
│ - Install Nginx     │  →   │ - Install Python    │ →  │ - Deploy app config │
│ - Install Certbot   │      │ - Install ColdFront │    │ - Remove placeholder│
│ - Obtain SSL cert   │      │ - Install Plugin    │    │ - Proxy to Gunicorn │
│ - fail2ban jails    │      │ - Configure service │    │                     │
│ - 444 catch-all     │      │                     │    │                     │
└─────────────────────┘      └─────────────────────┘    └─────────────────────┘
         ↓                            ↓                          ↓
   Nginx + Security          ColdFront installed         App fully deployed
   HTTPS + fail2ban          Ready for config            Production ready
```

**Benefits of three-phase approach:**
- Infrastructure security from the start (fail2ban, 444 catch-all blocks)
- Nginx setup is reusable across projects
- Multi-distribution support via Ansible (Amazon Linux, RHEL, Debian, Ubuntu)
- Clear separation of infrastructure and application
- Easier troubleshooting

---

## 1. Prerequisites

Before beginning, ensure you have:

### Accounts and Access
- **AWS Account** with EC2 and VPC permissions
- **Domain Name** with DNS control (e.g., `rental.your-org.org`)
- **Globus Developer Account** at https://developers.globus.org/

### Technical Requirements
- SSH client for server access
- Basic familiarity with Linux command line
- Understanding of DNS configuration

### Time Estimate
- Initial deployment: 1-2 hours
- DNS propagation: Up to 48 hours (usually faster)

---

## 2. AWS Infrastructure Setup

### 2.1 Launch EC2 Instance

1. Go to **AWS Console → EC2 → Launch Instance**

2. Configure the instance:
   | Setting | Value |
   |---------|-------|
   | AMI | Amazon Linux 2023 |
   | Instance Type | t3.small (minimum) or t3.medium (recommended) |
   | Key Pair | Create or select existing SSH key |
   | Storage | 20 GB gp3 (minimum) |

3. **Network Settings:**
   - Select your VPC and subnet
   - Enable "Auto-assign public IP" (or use Elastic IP)

### 2.2 Configure Security Group

Create or modify the security group with these inbound rules:

| Type | Port | Source | Purpose |
|------|------|--------|---------|
| SSH | 22 | Your IP only | Admin access |
| HTTP | 80 | 0.0.0.0/0 | Web traffic (redirects to HTTPS) |
| HTTPS | 443 | 0.0.0.0/0 | Secure web traffic |

### 2.3 Allocate Elastic IP

1. Go to **EC2 → Elastic IPs → Allocate Elastic IP address**
2. Associate with your EC2 instance
3. Note the IP address for DNS configuration

### 2.4 Configure DNS

Create an **A Record** in your DNS provider:

```
Type:  A
Name:  rental (or your subdomain)
Value: <Elastic IP Address>
TTL:   300
```

**Wait for DNS propagation** before proceeding with SSL setup. Verify with:
```bash
dig rental.your-org.org +short
```

---

## 3. Phase 1: Nginx Base Installation

This phase sets up Nginx with HTTPS using Let's Encrypt. It uses Ansible for cross-distribution support.

SSH into your server:
```bash
ssh -i your-key.pem ec2-user@<Elastic-IP>
```

### 3.1 Clone the Deployment Repository

```bash
# Install git if needed
sudo dnf install -y git  # Amazon Linux / RHEL
# sudo apt install -y git  # Debian / Ubuntu

# Clone repository
git clone https://github.com/christophernhill/orcd-rental-deployment.git
cd orcd-rental-deployment
```

### 3.2 Run Prerequisites Installation

The `install_prereqs.sh` script:
- Detects your Linux distribution
- Installs Ansible if not present
- Runs Nginx base installation (via `install_nginx_base.sh`)
- Installs fail2ban with nginx protection jails
- Installs rkhunter rootkit scanner
- Configures 444 catch-all blocks for unknown domains

```bash
sudo ./scripts/install_prereqs.sh --domain YOUR_DOMAIN --email YOUR_EMAIL
```

**Example:**
```bash
sudo ./scripts/install_prereqs.sh --domain rental.mit-orcd.org --email admin@mit.edu
```

**Options:**
- `--domain DOMAIN` - Required. Your domain name.
- `--email EMAIL` - Required. Email for Let's Encrypt notifications.
- `--skip-nginx` - Optional. Skip nginx installation (if already done).
- `--skip-f2b` - Optional. Skip fail2ban installation.

### 3.3 Verify Prerequisites Installation

After the script completes:

1. **Check the placeholder page** is accessible:
   ```bash
   curl -I https://YOUR_DOMAIN/
   ```
   
2. **Verify Nginx is running:**
   ```bash
   sudo systemctl status nginx
   ```

3. **Verify SSL certificate:**
   ```bash
   sudo certbot certificates
   ```

4. **Verify fail2ban is protecting the server:**
   ```bash
   sudo fail2ban-client status
   sudo fail2ban-client status nginx-bad-host
   ```

5. **Test 444 catch-all** (should close connection):
   ```bash
   curl -H "Host: unknown.test" http://YOUR_SERVER_IP/
   # Should return: curl: (52) Empty reply from server
   ```

The placeholder page indicates that infrastructure is ready for ColdFront.

### 3.4 Configure Firewall

On Amazon Linux 2023 with AWS EC2, you have multiple firewall layers:

| Layer | Purpose | Status |
|-------|---------|--------|
| **AWS Security Groups** | Port-level access control | Required |
| **fail2ban + iptables** | Dynamic IP blocking | Installed by this package |
| **firewalld** | Host-level firewall | Optional |

**AWS Security Groups** (configured in step 2.2) are the primary firewall. The `fail2ban` tool uses `iptables` directly for dynamic blocking.

**Note:** If you enable `firewalld`, you must change fail2ban to use `firewallcmd-rich-rules` instead of `iptables-multiport` in the jail configs to avoid conflicts.

#### Option A: Security Groups + iptables only (Recommended)

This is the default configuration. No additional firewall setup needed - AWS Security Groups handle port access, and fail2ban uses iptables for dynamic blocking.

```bash
# Verify iptables is available
sudo iptables -L -n

# Verify fail2ban chains exist
sudo iptables -L -n | grep f2b
```

#### Option B: Enable firewalld (Defense in Depth)

If you prefer an additional host firewall layer:

```bash
# Enable firewalld
sudo systemctl enable --now firewalld

# Open HTTP and HTTPS
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# Verify
sudo firewall-cmd --list-all

# IMPORTANT: Update fail2ban to use firewalld
# Edit all files in /etc/fail2ban/jail.d/*.local
# Change: banaction = iptables-multiport
# To:     banaction = firewallcmd-rich-rules

# Restart fail2ban
sudo systemctl restart fail2ban
```

---

## 4. Phase 2: ColdFront Installation

**Prerequisites:** Phase 1 (Nginx Base) must be complete. Nginx should be running with HTTPS.

### 4.1 Review Deployment Configuration

Before installation, review the deployment configuration:

```bash
cd ~/orcd-rental-deployment
cat config/deployment.conf
```

This file controls:
- Plugin repository and version
- ColdFront version
- Installation paths
- Service user/group

**To install a specific plugin version**, edit before running install.sh:

```bash
nano config/deployment.conf
# Change PLUGIN_VERSION="v0.1" to desired version
```

Available versions: https://github.com/christophernhill/cf-orcd-rental/tags

### 4.2 Run ColdFront Installation

The `install.sh` script handles all installation steps:

```bash
cd ~/orcd-rental-deployment
sudo ./scripts/install.sh
```

This script:
- Verifies Nginx is running (from Phase 1)
- Installs Python, Redis, and build tools
- Creates `/srv/coldfront` directory
- Creates Python virtual environment
- Installs ColdFront and the ORCD plugin
- Copies configuration files
- Installs security tools (fail2ban, rkhunter)

### 4.3 Configure Secrets

Run the interactive secrets configuration:

```bash
./scripts/configure-secrets.sh
```

This prompts for:
- Domain name
- Globus OAuth Client ID
- Globus OAuth Client Secret

And generates:
- `/srv/coldfront/local_settings.py`
- `/srv/coldfront/coldfront.env`

### 4.4 Verify Installation

```bash
cd /srv/coldfront
source venv/bin/activate
coldfront --version  # Should show ColdFront version
```

---

## 5. Phase 3: Nginx Application Configuration

**Prerequisites:** Phase 1 (base Nginx + HTTPS) and Phase 2 (ColdFront install) are complete.

### 5.1 Deploy Application Nginx Config

```bash
cd ~/orcd-rental-deployment
sudo ./scripts/install_nginx_app.sh --domain rental.your-org.org
```

This playbook:
- Removes the placeholder config
- Deploys the ColdFront reverse proxy config
- Points to the Gunicorn socket `/srv/coldfront/coldfront.sock`
- Serves static files from `/srv/coldfront/static`

### 5.2 Validate

```bash
# HTTP should redirect to HTTPS
curl -I http://rental.your-org.org

# HTTPS should respond (200/301/302/502 if app not yet started)
curl -I https://rental.your-org.org

# Check nginx and certbot timers
sudo systemctl status nginx
sudo systemctl list-timers | grep certbot
```

If the ColdFront socket is not yet created, HTTPS may return 502 until the app service starts.

## 6. Globus OAuth Configuration

### 5.1 Register Application at Globus

1. Go to https://developers.globus.org/
2. Click **Register your app with Globus**
3. Fill in application details:
   | Field | Value |
   |-------|-------|
   | App Name | ORCD Rental Portal (or your name) |
   | Redirect URIs | `https://rental.your-org.org/oidc/callback/` |

4. **Under "Required Identity Provider":**
   - Select "Massachusetts Institute of Technology" (or your organization)
   
5. **Under "Pre-select Identity Provider":**
   - Select the same identity provider

6. Click **Create App**

7. **Generate Client Secret:**
   - Go to your app's settings
   - Click **Generate New Client Secret**
   - **Save the secret immediately** - it won't be shown again

### 5.2 Record Credentials

Note these values (you'll need them for configuration):
- **Client ID:** `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Client Secret:** `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- **MIT Identity Provider ID:** `67af3d07-a5ff-4445-8404-80ec541411f9`

### 5.3 Globus OIDC Endpoints Reference

| Endpoint | URL |
|----------|-----|
| Authorization | `https://auth.globus.org/v2/oauth2/authorize` |
| Token | `https://auth.globus.org/v2/oauth2/token` |
| UserInfo | `https://auth.globus.org/v2/oauth2/userinfo` |
| JWKS | `https://auth.globus.org/jwk.json` |

**Important:** Globus signs tokens with RS512 but their JWKS metadata claims RS256. The custom authentication backend handles this mismatch.

---

## 7. Service Configuration

### 6.1 Copy Configuration Files

From this deployment package, copy the configuration files:

```bash
cd /srv/coldfront

# Copy from the config directory of this deployment package
# Assuming you've cloned/downloaded this repo to ~/orcd-rental-deployment

# Custom auth backend (handles Globus RS512/JWKS quirk)
cp ~/orcd-rental-deployment/config/coldfront_auth.py .

# WSGI entry point
cp ~/orcd-rental-deployment/config/wsgi.py .
```

### 6.2 Create Local Settings

Run the secrets configuration script:
```bash
cd ~/orcd-rental-deployment
./scripts/configure-secrets.sh
```

Or create manually at `/srv/coldfront/local_settings.py`:

```python
from coldfront.config.settings import *
import os

# =============================================================================
# SECURITY
# =============================================================================
DEBUG = False
SECRET_KEY = 'your-generated-secret-key-here'
ALLOWED_HOSTS = ['rental.your-org.org', 'localhost', '127.0.0.1']

# =============================================================================
# DATABASE
# =============================================================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/srv/coldfront/coldfront.db',
    }
}

# =============================================================================
# STATIC FILES
# =============================================================================
STATIC_ROOT = '/srv/coldfront/static/'

# =============================================================================
# SSL & PROXY SETTINGS
# =============================================================================
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = True

# Cookie Security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True

# OIDC State Cookie (must survive Globus redirect)
OIDC_STATE_COOKIE_SECURE = True
OIDC_STATE_COOKIE_HTTPONLY = True
OIDC_STATE_COOKIE_SAMESITE = 'Lax'
OIDC_STATE_COOKIE_NAME = 'oidc_state'
OIDC_STATE_COOKIE_PATH = '/'
OIDC_STATE_COOKIE_DOMAIN = None

# =============================================================================
# GLOBUS OIDC AUTHENTICATION
# =============================================================================
AUTHENTICATION_BACKENDS = [
    'coldfront_auth.GlobusOIDCBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Globus OAuth Client (replace with your values)
OIDC_RP_CLIENT_ID = 'your-client-id-here'
OIDC_RP_CLIENT_SECRET = 'your-client-secret-here'

# Globus Endpoints
OIDC_OP_AUTHORIZATION_ENDPOINT = 'https://auth.globus.org/v2/oauth2/authorize'
OIDC_OP_TOKEN_ENDPOINT = 'https://auth.globus.org/v2/oauth2/token'
OIDC_OP_USER_ENDPOINT = 'https://auth.globus.org/v2/oauth2/userinfo'
OIDC_OP_JWKS_ENDPOINT = 'https://auth.globus.org/jwk.json'

# CRITICAL: Token is RS512 (must match token, not JWKS metadata)
OIDC_RP_SIGN_ALGO = "RS512"
OIDC_RP_SCOPES = "openid email profile"
OIDC_CREATE_USER = True

LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

# MIT Identity Provider Enforcement
MIT_IDP_ID = "67af3d07-a5ff-4445-8404-80ec541411f9"
OIDC_AUTH_REQUEST_EXTRA_PARAMS = {
    'session_required_single_domain': 'mit.edu',
    'identity_provider': MIT_IDP_ID,
}

# =============================================================================
# ORCD PLUGIN SETTINGS
# =============================================================================
# Enable API plugin (required for ORCD plugin)
os.environ.setdefault('PLUGIN_API', 'True')

# Auto-configure users as PIs
os.environ.setdefault('AUTO_PI_ENABLE', 'True')

# Auto-create personal and group projects for new users
os.environ.setdefault('AUTO_DEFAULT_PROJECT_ENABLE', 'True')

# =============================================================================
# LOGGING
# =============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/srv/coldfront/coldfront.log',
        },
        'oidc_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/srv/coldfront/oidc_debug.log',
        },
    },
    'loggers': {
        'django': {'handlers': ['file'], 'level': 'INFO'},
        'coldfront_auth': {'handlers': ['oidc_file'], 'level': 'DEBUG'},
        'mozilla_django_oidc': {'handlers': ['oidc_file'], 'level': 'DEBUG'},
    },
}
```

### 6.3 Create Environment File

Create `/srv/coldfront/coldfront.env`:
```bash
DEBUG=False
SECRET_KEY=your-generated-secret-key-here
```

### 6.4 Configure Systemd Service

Copy the service file:
```bash
sudo cp ~/orcd-rental-deployment/config/systemd/coldfront.service /etc/systemd/system/
```

Or create `/etc/systemd/system/coldfront.service`:
```ini
[Unit]
Description=Gunicorn instance to serve ColdFront ORCD Rental Portal
After=network.target

[Service]
User=ec2-user
Group=nginx
WorkingDirectory=/srv/coldfront
Environment="PATH=/srv/coldfront/venv/bin"
Environment="PYTHONPATH=/srv/coldfront"
Environment="DJANGO_SETTINGS_MODULE=local_settings"
Environment="PLUGIN_API=True"
Environment="AUTO_PI_ENABLE=True"
Environment="AUTO_DEFAULT_PROJECT_ENABLE=True"
EnvironmentFile=/srv/coldfront/coldfront.env
ExecStart=/srv/coldfront/venv/bin/gunicorn --workers 3 --chdir /srv/coldfront --bind unix:/srv/coldfront/coldfront.sock wsgi:application

[Install]
WantedBy=multi-user.target
```

Enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable coldfront
```

### 6.5 Configure Nginx (Initial HTTP Setup)

Create initial HTTP-only configuration (certbot will add HTTPS automatically):

```bash
# Copy HTTP-only template
sudo cp ~/orcd-rental-deployment/config/nginx/coldfront-http.conf.template /etc/nginx/conf.d/coldfront.conf

# Replace domain placeholder (use your actual domain)
sudo sed -i 's/{{DOMAIN_NAME}}/rental.your-org.org/g' /etc/nginx/conf.d/coldfront.conf

# Test configuration
sudo nginx -t

# If test passes, restart nginx
sudo systemctl restart nginx
```

**Important:** Do NOT manually add SSL configuration. The next step (certbot) will automatically convert this to HTTPS.

### 6.6 Obtain SSL Certificate

Certbot will automatically update the nginx configuration with HTTPS settings:

```bash
# Set up Nginx permissions first
sudo usermod -a -G ec2-user nginx
chmod 710 /srv/coldfront

# Run certbot - it will modify coldfront.conf automatically
sudo certbot --nginx -d rental.your-org.org

# Follow prompts:
# - Enter email for renewal notifications
# - Agree to Terms of Service
# - Choose whether to redirect HTTP to HTTPS (recommended: yes)
```

**What certbot does:**
1. Obtains SSL certificate from Let's Encrypt
2. Modifies `/etc/nginx/conf.d/coldfront.conf` to add HTTPS configuration
3. Sets up automatic renewal
4. Reloads nginx

**After certbot completes:**
- Your site will be available at `https://rental.your-org.org`
- HTTP traffic will redirect to HTTPS (if you chose that option)
- Certificates will auto-renew every 60 days

### 6.7 Set Up Auto-Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Certbot auto-creates a timer, verify it's active
sudo systemctl status certbot-renew.timer
```

---

## 8. Database Initialization

### 7.1 Run Migrations and Initial Setup

```bash
cd /srv/coldfront
source venv/bin/activate
export PYTHONPATH=/srv/coldfront
export DJANGO_SETTINGS_MODULE=local_settings
export PLUGIN_API=True
export AUTO_PI_ENABLE=True
export AUTO_DEFAULT_PROJECT_ENABLE=True

# Apply all migrations
coldfront migrate

# Load initial reference data (project statuses, field of science, etc.)
# Answer 'yes' when prompted
coldfront initial_setup

# Generate any missing plugin migrations
coldfront makemigrations

# Apply the newly generated migrations
coldfront migrate
```

**Note:** The `makemigrations` step after `initial_setup` handles any plugin migrations that may be missing from the installed version. This is particularly important for ensuring database compatibility across different plugin versions.

### 7.2 Collect Static Files

```bash
coldfront collectstatic --noinput
```

### 7.3 Create Superuser

```bash
coldfront createsuperuser
```

Follow prompts to create the admin account.

### 7.4 Fix Permissions

```bash
# Database must be writable by the service
sudo chown ec2-user:ec2-user /srv/coldfront/coldfront.db
sudo chmod 664 /srv/coldfront/coldfront.db
sudo chmod 775 /srv/coldfront
sudo chmod -R 755 /srv/coldfront/static
```

### 7.5 Start Services

```bash
sudo systemctl start coldfront
sudo systemctl restart nginx

# Verify services are running
sudo systemctl status coldfront
sudo systemctl status nginx
```

---

## 9. Post-Installation Setup

### 8.1 Access the Portal

Open your browser and navigate to `https://rental.your-org.org`

You should see:
- ColdFront login page
- "Login with Globus" button (if OIDC is configured correctly)

### 8.2 Login and Verify

1. Click the Globus login button
2. Authenticate with your MIT credentials
3. You should be redirected back and logged in

### 8.3 Create Manager Accounts

After logging in as superuser, set up manager permissions:

```bash
cd /srv/coldfront
source venv/bin/activate
export PYTHONPATH=/srv/coldfront
export DJANGO_SETTINGS_MODULE=local_settings
export PLUGIN_API=True

# Set up Rental Manager (can approve/decline reservations)
coldfront setup_rental_manager --add-user USERNAME

# Set up Billing Manager (can approve cost allocations, view invoices)
coldfront setup_billing_manager --add-user USERNAME
```

### 8.4 Load Node Fixtures (Optional)

If the plugin includes fixtures for node types and instances:

```bash
coldfront loaddata node_types
coldfront loaddata gpu_node_instances
coldfront loaddata cpu_node_instances
```

### 8.5 Configure ColdFront Resources (Django Admin)

1. Go to `https://rental.your-org.org/admin/`
2. Log in with superuser credentials
3. Navigate to **Core → Resources** to configure available resources
4. Navigate to **ORCD Direct Charge** section for plugin-specific models

---

## 10. Maintenance Operations

### 9.1 Service Management

```bash
# Restart ColdFront
sudo systemctl restart coldfront

# Restart Nginx
sudo systemctl restart nginx

# View ColdFront logs
sudo journalctl -u coldfront -f

# View Nginx logs
sudo tail -f /var/log/nginx/error.log
```

### 9.2 Log Locations

| Log | Location |
|-----|----------|
| ColdFront application | `/srv/coldfront/coldfront.log` |
| OIDC debug | `/srv/coldfront/oidc_debug.log` |
| Gunicorn/Systemd | `journalctl -u coldfront` |
| Nginx access | `/var/log/nginx/access.log` |
| Nginx error | `/var/log/nginx/error.log` |

### 9.3 Database Backup

```bash
# Create backup
cp /srv/coldfront/coldfront.db /srv/coldfront/backups/coldfront-$(date +%Y%m%d).db

# Create backup directory
mkdir -p /srv/coldfront/backups

# Set up daily backup cron job
echo "0 2 * * * cp /srv/coldfront/coldfront.db /srv/coldfront/backups/coldfront-\$(date +\%Y\%m\%d).db" | crontab -
```

### 9.4 Upgrade Process

#### Checking for New Releases

The ORCD plugin uses git tags to signal new releases. Check for available versions:

```bash
# View available tags on GitHub
curl -s https://api.github.com/repos/christophernhill/cf-orcd-rental/tags | grep '"name"'

# Or visit: https://github.com/christophernhill/cf-orcd-rental/tags
```

#### Upgrade Steps

```bash
cd /srv/coldfront
source venv/bin/activate

# Upgrade ColdFront
pip install --upgrade coldfront[common]

# Upgrade ORCD plugin (change @v0.1 to desired version)
pip install --upgrade git+https://github.com/christophernhill/cf-orcd-rental.git@v0.1

# Apply any new migrations
export PYTHONPATH=/srv/coldfront
export DJANGO_SETTINGS_MODULE=local_settings
export PLUGIN_API=True
coldfront migrate

# Collect updated static files
coldfront collectstatic --noinput

# Restart service
sudo systemctl restart coldfront
```

> **Note**: Always check the release notes before upgrading. Major version changes may require additional migration steps or configuration changes. See the plugin's `developer_docs/CHANGELOG.md` for details.

### 9.5 SSL Certificate Renewal

Certbot handles automatic renewal. Verify it's working:

```bash
# Check certificate expiry
sudo certbot certificates

# Manual renewal (if needed)
sudo certbot renew

# Restart Nginx after renewal
sudo systemctl restart nginx
```

---

## 11. Troubleshooting

### 10.1 Common Issues

#### Certbot Fails: "nginx configuration test failed"

**Symptom:**
```
nginx: [emerg] cannot load certificate "/etc/letsencrypt/live/.../fullchain.pem": No such file
```

**Cause:** Nginx config has SSL paths before certificates exist (chicken-and-egg problem).

**Solution:**
```bash
# Remove invalid config
sudo rm /etc/nginx/conf.d/coldfront.conf

# Copy HTTP-only template
sudo cp ~/orcd-rental-deployment/config/nginx/coldfront-http.conf.template /etc/nginx/conf.d/coldfront.conf
sudo sed -i 's/{{DOMAIN_NAME}}/your-domain.org/g' /etc/nginx/conf.d/coldfront.conf

# Test and restart
sudo nginx -t && sudo systemctl restart nginx

# Now run certbot
sudo certbot --nginx -d your-domain.org
```

#### Warning: "Your models have changes that are not yet reflected in a migration"

**Symptom:**
```
Your models in app(s): 'coldfront_orcd_direct_charge' have changes that are not yet reflected in a migration
```

**Cause:** Plugin version missing migration files (known issue with v0.1).

**Solution:**
```bash
# Generate missing migrations
coldfront makemigrations

# Apply them
coldfront migrate

# Continue with setup
coldfront collectstatic --noinput
```

This is expected and safe - the migrations will be generated in your virtual environment.

#### "500 Internal Server Error"
```bash
# Check Gunicorn logs
sudo journalctl -u coldfront -n 50

# Check Django logs
tail -f /srv/coldfront/coldfront.log
```

#### "Bad Gateway" (502)
```bash
# Ensure socket exists
ls -la /srv/coldfront/coldfront.sock

# Check if Gunicorn is running
sudo systemctl status coldfront

# Restart both services
sudo systemctl restart coldfront
sudo systemctl restart nginx
```

#### OIDC Login Fails
```bash
# Check OIDC debug log
tail -f /srv/coldfront/oidc_debug.log

# Common issues:
# - Wrong redirect URI in Globus app settings
# - Incorrect client ID/secret
# - Cookie issues (check OIDC_STATE_COOKIE settings)
```

#### "Could not find valid JWKS"
This indicates the custom auth backend isn't being used. Verify:
```python
# In local_settings.py
AUTHENTICATION_BACKENDS = [
    'coldfront_auth.GlobusOIDCBackend',  # Must be first
    'django.contrib.auth.backends.ModelBackend',
]
```

#### Static Files Not Loading
```bash
# Re-collect static files
source /srv/coldfront/venv/bin/activate
export DJANGO_SETTINGS_MODULE=local_settings
coldfront collectstatic --noinput

# Fix permissions
sudo chmod -R 755 /srv/coldfront/static
```

### 10.2 Health Check Commands

```bash
# Verify all services are running
sudo systemctl status coldfront nginx redis6

# Test Django can start
cd /srv/coldfront && source venv/bin/activate
export DJANGO_SETTINGS_MODULE=local_settings
python -c "import django; django.setup(); print('Django OK')"

# Test database connection
coldfront dbshell

# Check certificate validity
echo | openssl s_client -connect rental.your-org.org:443 2>/dev/null | openssl x509 -noout -dates
```

### 10.3 Reset User Session

If a user is stuck in a login loop:
```bash
cd /srv/coldfront && source venv/bin/activate
export DJANGO_SETTINGS_MODULE=local_settings
coldfront shell
```

```python
from django.contrib.sessions.models import Session
Session.objects.all().delete()  # Clears all sessions
```

---

## Appendix A: Quick Reference Commands

```bash
# Start/stop/restart ColdFront
sudo systemctl start coldfront
sudo systemctl stop coldfront
sudo systemctl restart coldfront

# View logs
sudo journalctl -u coldfront -f
tail -f /srv/coldfront/coldfront.log
tail -f /srv/coldfront/oidc_debug.log

# Activate virtual environment
cd /srv/coldfront && source venv/bin/activate

# Set environment for management commands
export PYTHONPATH=/srv/coldfront
export DJANGO_SETTINGS_MODULE=local_settings
export PLUGIN_API=True
export AUTO_PI_ENABLE=True
export AUTO_DEFAULT_PROJECT_ENABLE=True

# Django management
coldfront migrate
coldfront collectstatic --noinput
coldfront createsuperuser
coldfront shell

# Manager setup
coldfront setup_rental_manager --add-user USERNAME
coldfront setup_billing_manager --add-user USERNAME
```

## Appendix B: Security Checklist

- [ ] `DEBUG=False` in production
- [ ] Strong `SECRET_KEY` (50+ random characters)
- [ ] HTTPS only (HTTP redirects to HTTPS)
- [ ] `SESSION_COOKIE_SECURE=True`
- [ ] `CSRF_COOKIE_SECURE=True`
- [ ] Globus redirect URIs match exactly
- [ ] Secrets not in version control
- [ ] Database file permissions restricted
- [ ] SSH key-based authentication only
- [ ] Security group restricts SSH to known IPs
- [ ] SSL certificate auto-renewal configured
- [ ] Regular database backups

