# PR: Nginx Base Installation Refactor

## Summary

This PR refactors the Nginx installation into a standalone, multi-distro Ansible-based setup that produces a working HTTPS server with a placeholder page, independent of ColdFront configuration.

## Motivation

The current `install.sh` mixes infrastructure setup (Nginx, SSL) with application deployment (ColdFront). This creates several issues:

1. **Tight coupling** - Can't set up base web server without ColdFront
2. **Single distro** - Only Amazon Linux 2023 supported
3. **Manual SSL** - Certbot must be run manually after installation
4. **No verification** - No automatic check that HTTPS is working

## Changes

### New Components

- `scripts/install_nginx_base.sh` - Control script for Nginx/HTTPS setup
- `ansible/` - Ansible playbooks and roles for multi-distro support
- Placeholder page served until ColdFront is configured

### Refactored Components

- `scripts/install.sh` - Removed Nginx installation, now expects Nginx pre-configured
- `scripts/configure-secrets.sh` - Updated for new workflow
- Documentation updated for two-phase installation

### Supported Distributions

| Distribution | Package Manager | Status |
|-------------|-----------------|--------|
| Amazon Linux 2023 | dnf | Supported |
| RHEL 8/9, Rocky, Alma | dnf | Supported |
| Debian 11/12 | apt | Supported |
| Ubuntu 22.04/24.04 | apt | Supported |

## Usage

```bash
# Phase 1: Set up base Nginx with HTTPS
sudo ./scripts/install_nginx_base.sh --domain example.com --email admin@example.com

# Phase 2: Install ColdFront (existing workflow, now simplified)
sudo ./scripts/install.sh
./scripts/configure-secrets.sh
```

## Testing

- [ ] Fresh Amazon Linux 2023 instance
- [ ] Fresh Ubuntu 22.04 instance  
- [ ] Fresh Debian 12 instance
- [ ] Nginx running under systemd
- [ ] HTTPS with valid Let's Encrypt certificate
- [ ] Placeholder page displays correctly
- [ ] Certbot auto-renewal configured
- [ ] install.sh works after nginx base setup

---

## Development Log

### Prompts Used

#### Initial Request
```
Can you look at how the setup handles the nginx install and basic https configuration. 
Can you make a plan to refactor the nginx basic config code as follow

1. carry out the work in a branch and plan to create a PR that will log the changes 
   and the prompting (including these prompts) and the models used.

2. separate out the nginx install and basic https setup to be cleanly distinct from 
   the other setup steps. 

3. make the install a first step in the new work flow. At them end of the step nginx 
   should be running under systemd and with https configured correctly. 

4. the coldfront specific configuration of nginx will be carried out separately after 
   this step. Plan to refactor all code, documentation and tests to reflect this.

5. consider using ansible for standardized parts of the nginx install if that makes sense.
```

#### Clarification Questions

The agent asked:
1. When 'basic HTTPS configuration' is complete, what should nginx be serving?
2. For the Ansible approach, what platforms should be supported?
3. How should the new nginx setup script relate to the existing install.sh?

#### User Responses
```
For 1 choose option A (placeholder page)

For 2 choose option C (Multiple distros) and include Amazon Linux 2023 as part of 
"Multiple Distros"

For 3. Create a new set of code run by a control script install_nginx_base.sh. 
Eventually this script will be called from an overall driver script.
```

### Model Used

- Claude Opus 4.5 (claude-sonnet-4-20250514)

### Plan Document

See: [Nginx Base Install Plan](/.cursor/plans/nginx_base_install_refactor_74803aa0.plan.md)

The complete plan was generated and approved before implementation began.

---

## Implementation Notes

### Phase 1: Branch and PR Setup
- Created branch `feature/nginx-base-refactor`
- Created this PR description document
- PR #6 created via `gh` CLI

### Phase 2: Control Script
- Created `scripts/install_nginx_base.sh`
- Features:
  - Multi-distribution detection (Amazon Linux, RHEL, Debian, Ubuntu)
  - Automatic Ansible installation if not present
  - Automatic Ansible collection install (community.general, ansible.posix)
  - Pre-flight checks (DNS, port availability)
  - Verification after installation
  - `--skip-ssl` and `--dry-run` options for testing

### Phase 3: Ansible Playbooks  
- Created `ansible/` directory structure
- Main playbook: `ansible/nginx-base.yml`
- Role: `ansible/roles/nginx_base/`
  - `tasks/main.yml` - Entry point
  - `tasks/install-redhat.yml` - RHEL/Amazon Linux tasks
  - `tasks/install-debian.yml` - Debian/Ubuntu tasks
  - `tasks/configure.yml` - Common configuration
  - `tasks/certbot.yml` - SSL certificate acquisition + renewal method logging
  - `handlers/main.yml` - nginx restart/reload
  - `templates/nginx-placeholder.conf.j2` - HTTP placeholder config
  - `templates/placeholder.html.j2` - Styled placeholder page
  - `defaults/main.yml` - Default variables
  - `defaults/redhat.yml` - RHEL-specific defaults
  - `defaults/debian.yml` - Debian-specific defaults

### Phase 4: App Nginx Layer
- Added `scripts/install_nginx_app.sh` for application proxy deployment
- Added `ansible/nginx-app.yml` + `roles/nginx_app`:
  - Removes placeholder config
  - Deploys ColdFront proxy config with TLS
  - Validates HTTP/HTTPS (non-fatal if app not started)
  - Warns if ColdFront socket is missing
- Placeholder is automatically removed/disabled when app config is enabled

### Phase 5: Refactor Existing Scripts
- Updated `scripts/install.sh`:
  - Removed nginx/certbot installation
  - Added nginx running check (requires Phase 1)
  - Added multi-distro support
  - Next steps now call `install_nginx_app.sh` for app Nginx
- Updated `scripts/configure-secrets.sh`:
  - Now secrets-only; Nginx deployment removed
  - Guides user to run `install_nginx_app.sh`

### Phase 6: Documentation Updates
- Updated `README.md`:
  - Added three-phase installation overview (Base → App → ColdFront)
  - Updated quick start for new workflow
  - Added multi-distro support info
  - Updated directory structure
- Updated `docs/admin-guide.md`:
  - Added installation overview diagram
  - Section 3: Phase 1 (Nginx Base)
  - Section 4: Phase 2 (ColdFront)
  - Section 5: Phase 3 (Nginx App config)
  - Updated instructions for new workflow
- Updated `config/nginx/README.md`:
  - Explained two-phase approach
  - Updated troubleshooting

---

## Testing Procedures

### Test Matrix

| Distribution | Status | Notes |
|-------------|--------|-------|
| Amazon Linux 2023 | Pending | Primary target |
| Ubuntu 22.04 | Pending | |
| Debian 12 | Pending | |
| RHEL 9 | Pending | |

### Test Procedure

For each distribution:

1. **Fresh Instance Setup**
   ```bash
   # Launch fresh instance
   # SSH in and clone repo
   git clone https://github.com/christophernhill/orcd-rental-deployment.git
   cd orcd-rental-deployment
   git checkout feature/nginx-base-refactor
   ```

2. **Phase 1: Nginx Base**
   ```bash
   # Set up DNS A record first
   sudo ./scripts/install_nginx_base.sh --domain test.example.com --email test@example.com
   
   # Verify
   curl -I https://test.example.com/
   sudo systemctl status nginx
   sudo certbot certificates
   ```

3. **Phase 2: ColdFront**
   ```bash
   sudo ./scripts/install.sh
   ./scripts/configure-secrets.sh
   
   # Initialize database
   cd /srv/coldfront
   source venv/bin/activate
   export DJANGO_SETTINGS_MODULE=local_settings
   export PLUGIN_API=True
   coldfront migrate
   coldfront initial_setup
   coldfront collectstatic --noinput
   
   # Start service
   sudo systemctl enable coldfront
   sudo systemctl start coldfront
   ```

4. **Phase 3: Nginx App Config**
   ```bash
   sudo ./scripts/install_nginx_app.sh --domain test.example.com
   ```

5. **Verify Complete Installation**
   ```bash
   curl -I https://test.example.com/
   sudo systemctl status coldfront
   sudo systemctl status nginx
   ```

### Checklist Per Distribution

- [ ] `install_nginx_base.sh` completes without errors
- [ ] Nginx running under systemd
- [ ] HTTPS working with valid certificate
- [ ] Placeholder page displays correctly
- [ ] Certbot auto-renewal configured (timer or cron) and logged
- [ ] `install.sh` detects nginx is running
- [ ] `install.sh` completes without errors
- [ ] `install_nginx_app.sh` removes placeholder and deploys app proxy
- [ ] ColdFront service starts successfully
- [ ] Application accessible via HTTPS

---

## Debugging Notes

*(Any issues encountered during development will be documented here)*

### Known Considerations

1. **Ansible Collections**: The Debian tasks use `community.general.ufw` module.
   May need to install ansible collections on some systems:
   ```bash
   ansible-galaxy collection install community.general
   ```

2. **Firewalld on RHEL**: The `ansible.posix.firewalld` module requires the
   `ansible.posix` collection. May need:
   ```bash
   ansible-galaxy collection install ansible.posix
   ```

3. **DNS Propagation**: SSL certificate acquisition will fail if DNS hasn't
   propagated yet. The script includes a DNS check but it's advisory only.

---

## Related Issues

- Relates to: SSL bootstrap issue (PR #3)
- Relates to: Template naming confusion (PR #5)
- See: OUTSTANDING_ISSUES.md for full context
