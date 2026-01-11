# ORCD Rental Portal - Deployment Package

This package contains everything needed to deploy the ORCD Rental Portal. The portal is built on [ColdFront](https://coldfront.io/) with the ORCD Direct Charge plugin and uses Globus OIDC for MIT authentication.

## Supported Distributions

- **Amazon Linux 2023** (primary target)
- **RHEL 8/9, Rocky Linux, AlmaLinux**
- **Debian 11/12**
- **Ubuntu 22.04/24.04**

## Overview

The ORCD Rental Portal provides:
- **Node Rental Management**: Reserve GPU/CPU compute nodes
- **Project Management**: Create and manage research projects
- **Cost Allocation**: Assign billing codes to projects
- **Invoice Reporting**: Generate monthly billing reports
- **MIT Authentication**: Single sign-on via Globus/MIT Okta

## Quick Start

### Prerequisites

- Server (EC2, VM, or bare metal) with supported Linux distribution
- Domain name with DNS access
- Globus Developer account (https://developers.globus.org/)

### Three-Phase Installation

1) **Phase 1: Nginx Base** – Install Nginx with HTTPS (Ansible)
2) **Phase 2: ColdFront** – Install ColdFront and the ORCD plugin
3) **Phase 3: Nginx App Config** – Deploy the ColdFront reverse proxy config

This separation allows:
- Reusable Nginx setup across projects
- Multi-distribution support
- Clear separation of infra vs. application

### Installation (Quick Path)

```bash
# 0. Clone this repository
git clone https://github.com/christophernhill/orcd-rental-deployment.git
cd orcd-rental-deployment

# 1. Set up DNS A record pointing to your server's IP address
#    Wait for DNS propagation before continuing

# 2. PHASE 1: Install Nginx with HTTPS
sudo ./scripts/install_nginx_base.sh --domain YOUR_DOMAIN --email YOUR_EMAIL

# 3. PHASE 2: Install ColdFront
sudo ./scripts/install.sh

# 4. Configure secrets (as regular user)
./scripts/configure-secrets.sh

# 5. PHASE 3: Deploy ColdFront Nginx app config
sudo ./scripts/install_nginx_app.sh --domain YOUR_DOMAIN

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
sudo chown $(whoami):$(whoami) /srv/coldfront/coldfront.db
sudo chmod 664 /srv/coldfront/coldfront.db
sudo systemctl enable coldfront
sudo systemctl start coldfront

# 8. Verify deployment (placeholder should be replaced by app)
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
| [Admin Guide](docs/admin-guide.md) | Complete deployment and maintenance guide |
| [Developer Guide](docs/developer-guide.md) | Architecture, local setup, and customization |
| [User Guide](docs/user-guide.md) | End-user documentation for the portal |

## Directory Structure

```
orcd-rental-deployment/
├── README.md                          # This file
├── .gitignore                         # Git ignore rules (secrets protected)
├── ansible/                           # Ansible playbooks for nginx setup
│   ├── nginx-base.yml                 # Main playbook
│   ├── nginx-app.yml                  # ColdFront app proxy playbook
│   ├── inventory/                     # Inventory files
│   ├── roles/nginx_base/              # Nginx base installation role
│   └── roles/nginx_app/               # ColdFront app proxy role
├── docs/
│   ├── admin-guide.md                 # Deployment, installation, maintenance
│   ├── developer-guide.md             # Architecture, customization, contributing
│   └── user-guide.md                  # End-user documentation
├── config/
│   ├── deployment.conf                # Deployment configuration
│   ├── deployment.conf.template       # Template for deployment config
│   ├── local_settings.py.template     # Django settings template
│   ├── coldfront.env.template         # Environment variables template
│   ├── coldfront_auth.py              # Custom Globus OIDC backend
│   ├── wsgi.py                        # WSGI entry point
│   ├── nginx/
│   │   ├── coldfront-http.conf.template    # Nginx HTTP-only config
│   │   ├── coldfront-https.conf.reference  # HTTPS reference (post-certbot)
│   │   └── README.md                        # Nginx template documentation
│   └── systemd/
│       └── coldfront.service          # Systemd service file
├── scripts/
│   ├── install_nginx_base.sh          # Phase 1: Nginx + HTTPS installation
│   ├── install_nginx_app.sh           # Phase 3: ColdFront app Nginx config
│   ├── install.sh                     # Phase 2: ColdFront installation
│   ├── configure-secrets.sh           # Interactive secrets setup
│   └── healthcheck.sh                 # Service health check
└── secrets/
    ├── .gitkeep                       # Keeps folder in git
    └── README.md                      # Instructions for secrets
```

## Required Settings

Before deploying, you'll need:

1. **Globus OAuth Client** (from developers.globus.org)
   - Client ID
   - Client Secret
   - Redirect URI: `https://YOUR_DOMAIN/oidc/callback/`

2. **Domain Name**
   - DNS A record pointing to your server IP

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

[ColdFront](https://coldfront.io/) is an open-source HPC resource allocation management system.

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

## Distribution-Specific Notes

### Amazon Linux 2023

- Default service user: `ec2-user`
- Firewall managed via AWS Security Groups
- Redis package: `redis6`

### Debian/Ubuntu

- Default service user: configured during installation
- Certbot installed via apt package
- Redis package: `redis-server`

### RHEL/Rocky/Alma

- Similar to Amazon Linux 2023
- May need EPEL for some packages
- Certbot installed via pip in venv

## License

This deployment package is provided for deploying the ORCD Rental Portal.

- ColdFront: AGPLv3
- ORCD Plugin: See plugin repository
- Configuration files: MIT

## Contributing

See [Developer Guide](docs/developer-guide.md) for development setup and contribution guidelines.
