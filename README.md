# ORCD Rental Portal - Deployment Package

This package contains everything needed to deploy the ORCD Rental Portal on AWS **Amazon Linux 2023**. The portal is built on [ColdFront](https://coldfront.io/) with the ORCD Direct Charge plugin and uses Globus OIDC for MIT authentication.

> **Note**: This deployment is specifically tailored for **Amazon Linux 2023** on AWS EC2. See [Amazon Linux 2023 Considerations](#amazon-linux-2023-considerations) for platform-specific details.

## Overview

The ORCD Rental Portal provides:
- **Node Rental Management**: Reserve GPU/CPU compute nodes
- **Project Management**: Create and manage research projects
- **Cost Allocation**: Assign billing codes to projects
- **Invoice Reporting**: Generate monthly billing reports
- **MIT Authentication**: Single sign-on via Globus/MIT Okta

## Quick Start

### Prerequisites

- AWS EC2 instance (Amazon Linux 2023, t3.small or larger)
- Domain name with DNS access
- Globus Developer account (https://developers.globus.org/)

### Installation

**Option A: Using git (recommended)**
```bash
# 0. Install git (required on fresh Amazon Linux 2023)
sudo dnf install -y git

# 1. Clone this repository on your EC2 instance
git clone https://github.com/christophernhill/orcd-rental-deployment.git
cd orcd-rental-deployment
```

**Option B: Download without git**
```bash
# Download and extract the latest release
curl -L https://github.com/christophernhill/orcd-rental-deployment/archive/refs/heads/main.tar.gz | tar xz
cd orcd-rental-deployment-main
```

**Continue with installation:**
```bash
# 2. Run the installation script (as root)
sudo ./scripts/install.sh

# 3. Configure secrets (as ec2-user)
./scripts/configure-secrets.sh

# 4. Set up DNS A record pointing to your Elastic IP

# 5. Configure Nginx and get SSL certificate
sudo cp config/nginx/coldfront-http.conf.template /etc/nginx/conf.d/coldfront.conf
sudo sed -i 's/{{DOMAIN_NAME}}/your-domain.org/g' /etc/nginx/conf.d/coldfront.conf
sudo nginx -t && sudo systemctl restart nginx
sudo certbot --nginx -d your-domain.org

# 6. Initialize the database
cd /srv/coldfront
source venv/bin/activate
export PYTHONPATH=/srv/coldfront
export DJANGO_SETTINGS_MODULE=local_settings
export PLUGIN_API=True AUTO_PI_ENABLE=True AUTO_DEFAULT_PROJECT_ENABLE=True
coldfront migrate
coldfront initial_setup  # Load initial reference data (answer 'yes' when prompted)
coldfront makemigrations  # Generate any missing migrations
coldfront migrate  # Apply the new migrations
coldfront collectstatic --noinput
coldfront createsuperuser

# 7. Fix permissions and start services
sudo chown ec2-user:ec2-user /srv/coldfront/coldfront.db
sudo chmod 664 /srv/coldfront/coldfront.db
sudo systemctl start coldfront
sudo systemctl restart nginx

# 8. Verify deployment
cd ~/orcd-rental-deployment
./scripts/healthcheck.sh
```

## Configuration

### Deployment Configuration File

The `config/deployment.conf` file controls key deployment settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `PLUGIN_REPO` | `https://github.com/christophernhill/cf-orcd-rental.git` | Plugin repository URL |
| `PLUGIN_VERSION` | `v0.1` | Plugin version (git tag or branch) |
| `COLDFRONT_VERSION` | `coldfront[common]` | ColdFront package version |
| `APP_DIR` | `/srv/coldfront` | Installation directory |
| `VENV_DIR` | `/srv/coldfront/venv` | Virtual environment path |
| `SERVICE_USER` | `ec2-user` | Service account user |
| `SERVICE_GROUP` | `nginx` | Web server group |

**To use a different plugin version:**
1. Edit `config/deployment.conf`
2. Change `PLUGIN_VERSION` to desired tag (e.g., `v0.2`)
3. Run installation script

**Available plugin versions:** https://github.com/christophernhill/cf-orcd-rental/tags

## Documentation

| Document | Description |
|----------|-------------|
| [Admin Guide](docs/admin-guide.md) | Complete AWS deployment and maintenance guide |
| [Developer Guide](docs/developer-guide.md) | Architecture, local setup, and customization |
| [User Guide](docs/user-guide.md) | End-user documentation for the portal |

## Directory Structure

```
orcd-rental-deployment/
├── README.md                          # This file
├── .gitignore                         # Git ignore rules (secrets protected)
├── docs/
│   ├── admin-guide.md                 # AWS setup, installation, maintenance
│   ├── developer-guide.md             # Architecture, customization, contributing
│   └── user-guide.md                  # End-user documentation
├── config/
│   ├── local_settings.py.template     # Django settings template
│   ├── coldfront.env.template         # Environment variables template
│   ├── coldfront_auth.py              # Custom Globus OIDC backend
│   ├── wsgi.py                        # WSGI entry point
│   ├── nginx/
│   │   ├── coldfront-http.conf.template    # Nginx HTTP-only config (use first)
│   │   ├── coldfront-https.conf.reference  # HTTPS reference (post-certbot)
│   │   └── README.md                        # Nginx template documentation
│   └── systemd/
│       └── coldfront.service          # Systemd service file
├── scripts/
│   ├── install.sh                     # Automated installation
│   ├── configure-secrets.sh           # Interactive secrets setup
│   └── healthcheck.sh                 # Service health check
└── secrets/
    ├── .gitkeep                       # Keeps folder in git
    └── README.md                      # Instructions for secrets
```

## Configuration

### Required Settings

Before deploying, you'll need:

1. **Globus OAuth Client** (from developers.globus.org)
   - Client ID
   - Client Secret
   - Redirect URI: `https://YOUR_DOMAIN/oidc/callback/`

2. **Domain Name**
   - DNS A record pointing to your Elastic IP

3. **Django Secret Key**
   - Auto-generated by `configure-secrets.sh`

### Environment Variables

The ORCD plugin is controlled by these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PLUGIN_API` | `False` | Enable REST API endpoints |
| `AUTO_PI_ENABLE` | `False` | Auto-set users as Principal Investigators |
| `AUTO_DEFAULT_PROJECT_ENABLE` | `False` | Auto-create personal/group projects |

## Security

### Secrets Management

- **Never commit secrets to git** - all sensitive files are in `.gitignore`
- Secret files are stored in `/srv/coldfront/` on the server
- Backup copies are kept in `secrets/` directory (also gitignored)
- Use strong passwords and rotate regularly

### Security Checklist

- [ ] `DEBUG=False` in production
- [ ] Strong `SECRET_KEY` (50+ random characters)
- [ ] HTTPS only (HTTP redirects)
- [ ] Globus redirect URIs match exactly
- [ ] SSH key-based authentication
- [ ] Security groups restrict SSH access
- [ ] SSL certificate auto-renewal

## Components

### ColdFront Core

[ColdFront](https://coldfront.io/) is an open-source HPC resource allocation management system. Version 1.1.7 is used as the base.

### ORCD Direct Charge Plugin

The plugin (from https://github.com/christophernhill/cf-orcd-rental) adds:

- GPU/CPU node management
- Reservation system with calendar
- Cost allocation workflow
- Invoice generation
- Activity logging
- Custom dashboard

**Version Configuration:** The plugin version is specified in `config/deployment.conf` (default: v0.1). Check the [plugin repository](https://github.com/christophernhill/cf-orcd-rental/tags) for available versions.

### Globus OIDC Authentication

Authentication uses Globus Auth with MIT as the identity provider:
- Users authenticate via MIT Okta
- Automatic account creation on first login
- Custom backend handles Globus RS512/JWKS quirk

## Support

### Logs

```bash
# Application logs
tail -f /srv/coldfront/coldfront.log

# OIDC debug logs
tail -f /srv/coldfront/oidc_debug.log

# Service logs
sudo journalctl -u coldfront -f

# Nginx logs
sudo tail -f /var/log/nginx/error.log
```

### Common Commands

```bash
# Restart services
sudo systemctl restart coldfront
sudo systemctl restart nginx

# Check service status
sudo systemctl status coldfront

# Run health check
./scripts/healthcheck.sh

# Django management
cd /srv/coldfront && source venv/bin/activate
export DJANGO_SETTINGS_MODULE=local_settings PLUGIN_API=True
coldfront migrate
coldfront collectstatic
coldfront shell
```

### Getting Help

- **Email**: orcd-help@mit.edu
- **ColdFront Docs**: https://coldfront.readthedocs.io/
- **Globus Auth**: https://docs.globus.org/api/auth/

## Amazon Linux 2023 Considerations

This deployment package is tailored for **Amazon Linux 2023** (AL2023). Several configurations differ from other Linux distributions:

### Package Management

| Standard | Amazon Linux 2023 |
|----------|-------------------|
| `apt` / `yum` | `dnf` (AL2023 default) |
| `python3-pip` | `python3.9-pip` |
| `redis` | `redis6` (Amazon Extras) |

### Firewall

AL2023 does **not** include `firewalld` by default. Security is managed via **AWS Security Groups**:

- The install script skips `firewalld` configuration
- Configure inbound rules in the EC2 Security Group:
  - SSH (22): Your IP only
  - HTTP (80): Anywhere (redirects to HTTPS)
  - HTTPS (443): Anywhere

### Logging

AL2023 uses **journald** by default instead of traditional log files:

| Standard | Amazon Linux 2023 |
|----------|-------------------|
| `/var/log/secure` | `journalctl -u sshd` |
| `/var/log/messages` | `journalctl` |

The fail2ban sshd jail uses `backend = systemd` instead of `logpath = /var/log/secure`.

### Python

AL2023 ships with Python 3.9:

```bash
python3 --version  # Python 3.9.x
```

Virtual environments are created with:
```bash
python3 -m venv venv
```

### SELinux

AL2023 has SELinux in **permissive** mode by default. If enabled in enforcing mode, you may need:

```bash
# Allow nginx to connect to unix socket
sudo setsebool -P httpd_can_network_connect 1

# Allow nginx to read static files
sudo chcon -R -t httpd_sys_content_t /srv/coldfront/static/
```

### Service Names

| Standard | Amazon Linux 2023 |
|----------|-------------------|
| `redis` | `redis6` |
| `nginx` | `nginx` (same) |

### Adapting to Other Distributions

If deploying to Ubuntu, RHEL, or other distributions:

1. **Ubuntu/Debian**: Change `dnf` to `apt`, adjust package names
2. **RHEL 8/9**: Similar to AL2023, may need EPEL for some packages
3. **Firewall**: Enable and configure `firewalld` or `ufw`
4. **fail2ban**: Use `logpath = /var/log/auth.log` (Ubuntu) or `/var/log/secure` (RHEL)

## License

This deployment package is provided for deploying the ORCD Rental Portal.

- ColdFront: AGPLv3
- ORCD Plugin: See plugin repository
- Configuration files: MIT

## Contributing

See [Developer Guide](docs/developer-guide.md) for development setup and contribution guidelines.

