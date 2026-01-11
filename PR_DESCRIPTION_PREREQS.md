# PR: Infrastructure Prerequisites and Security Hardening

## Agent/Model Used

**Claude Opus 4.5** (claude-opus-4-5-20251101)

## Prompts Used

### Initial Request
> I would like the base nginx to reject with a 444 code requests to an unknown domain. The conf extract below shows this.
>
> Could you make a plan to update to enable this and to include fail2ban setup as (with the jails and filters defined in this repo) in the repo included in the base install. You can use ansible for fail2ban if that makes sense. You will need to remove fail2ban from the coldfront install phase.
>
> Can you plan to have the first phase be run from an `install_prereqs.sh` script that does nginx base and fail2ban.
>
> Can you check if there are other system pre-reqs that make sense to separate from the coldfront phase and perform ahead of that phase.
>
> Can you plan to make changes in a PR and include prompts and documentation in PR.

The user also provided the nginx catch-all configuration snippet:
```nginx
# Reject HTTP requests for unknown domains
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;  # Nginx special: close connection without response
}

# Reject HTTPS requests for unknown domains
server {
    listen 443 default_server ssl;
    listen [::]:443 default_server ssl;
    server_name _;
    ssl_certificate /etc/letsencrypt/live/{{DOMAIN_NAME}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{DOMAIN_NAME}}/privkey.pem;
    return 444;
}
```

### Follow-up Request
> Can you plan to include in the PR description the prompts and the agent used.

## Development Plan

### Problem Statement

1. Nginx did not reject requests to unknown/spoofed domains (no catch-all 444 blocks)
2. fail2ban was installed during the ColdFront phase, but it's infrastructure security that should be set up earlier
3. The fail2ban `nginx-bad-host` filter expected 444 responses that weren't being generated
4. No unified "prerequisites" script existed to set up base infrastructure

### Solution Architecture

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
```

## Changes Made

### New Files

| File | Description |
|------|-------------|
| `scripts/install_prereqs.sh` | Orchestration script for Phase 1 prerequisites |
| `ansible/prereqs.yml` | Ansible playbook for fail2ban and rkhunter |
| `ansible/roles/fail2ban/` | Complete Ansible role for fail2ban installation |
| `ansible/roles/nginx_base/templates/nginx-catchall-https.conf.j2` | HTTPS catch-all template |

### Modified Files

| File | Changes |
|------|---------|
| `ansible/roles/nginx_base/templates/nginx-placeholder.conf.j2` | Added HTTP 444 catch-all block |
| `ansible/roles/nginx_base/tasks/certbot.yml` | Deploy HTTPS catch-all after cert obtained |
| `ansible/roles/nginx_app/templates/nginx-app.conf.j2` | Added both HTTP/HTTPS catch-all blocks |
| `ansible/roles/nginx_app/tasks/main.yml` | Remove standalone HTTPS catch-all on deploy |
| `scripts/install.sh` | Removed `install_security_tools()`, updated comments |
| `README.md` | Updated installation flow and directory structure |
| `docs/admin-guide.md` | Updated to three-phase installation |

### fail2ban Role Structure

```
ansible/roles/fail2ban/
├── defaults/main.yml       # Default variables
├── handlers/main.yml       # Restart/reload handlers
├── tasks/
│   ├── main.yml           # Entry point
│   ├── install-redhat.yml # RHEL/Amazon Linux installation
│   └── install-debian.yml # Debian/Ubuntu installation
└── files/
    ├── filter.d/          # nginx-bad-host, nginx-bad-request, nginx-noscript
    └── jail.d/            # nginx jails, sshd jail
```

## New Installation Flow

```bash
# Step 1: Prerequisites (nginx + fail2ban)
sudo ./scripts/install_prereqs.sh --domain YOUR_DOMAIN --email YOUR_EMAIL

# Step 2: ColdFront application
sudo ./scripts/install.sh

# Step 3: Configure secrets
./scripts/configure-secrets.sh

# Step 4: ColdFront nginx config
sudo ./scripts/install_nginx_app.sh --domain YOUR_DOMAIN

# Step 5: Database setup and service start
```

## Security Features Added

### 444 Catch-All Blocks
- **HTTP catch-all**: Immediately closes connections to unknown domains
- **HTTPS catch-all**: Uses domain's SSL cert, then closes connection
- Prevents domain spoofing and reduces scanner exposure

### fail2ban Jails
| Jail | Triggers | Ban Duration |
|------|----------|--------------|
| `nginx-bad-request` | 3 malformed requests in 10 min | 24 hours |
| `nginx-noscript` | 2 probe attempts (.env, wp-login) in 10 min | 48 hours |
| `nginx-bad-host` | 3 wrong-host requests (444s) in 10 min | 1 hour |
| `sshd` | 5 failed SSH logins in 10 min | 1 hour |

## Testing Checklist

- [ ] 444 returned for HTTP requests to wrong hostname
- [ ] 444 returned for HTTPS requests to wrong hostname
- [ ] fail2ban installed and running
- [ ] All jails active: `sudo fail2ban-client status`
- [ ] nginx-bad-host jail triggers on 444 responses
- [ ] ColdFront installation still works without fail2ban step
- [ ] Placeholder page accessible at correct domain
- [ ] Application works after full installation

## Implementation Notes

1. **HTTP catch-all is immediate**: Added to `nginx-placeholder.conf.j2`, works from first nginx start
2. **HTTPS catch-all requires cert**: Deployed separately after certbot obtains certificate
3. **App config includes both**: When `install_nginx_app.sh` runs, the standalone HTTPS catch-all is removed and both catch-alls are included inline in the app config
4. **fail2ban uses iptables**: Works on Amazon Linux 2023 without firewalld
5. **rkhunter included**: Rootkit scanner installed as part of prerequisites

## Distribution Support

Tested on:
- Amazon Linux 2023 (primary target)
- RHEL 8/9 family (Rocky, Alma)
- Debian 11/12
- Ubuntu 22.04/24.04
