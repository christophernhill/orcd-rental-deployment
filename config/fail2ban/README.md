# Fail2Ban Security Configuration

This directory contains fail2ban filters and jails to protect the ORCD Rental Portal from common attacks.

## What's Included

### Filters (`filter.d/`)

| Filter | Purpose |
|--------|---------|
| `nginx-bad-request.conf` | Catches malformed/binary garbage requests (scanners) |
| `nginx-noscript.conf` | Blocks probing for .env, .git, wp-login, phpinfo, etc. |
| `nginx-bad-host.conf` | Catches requests to wrong/spoofed hostnames (444 responses) |

### Jails (`jail.d/`)

| Jail | Triggers | Ban Duration |
|------|----------|--------------|
| `nginx-bad-request` | 3 bad requests in 10 min | 24 hours |
| `nginx-noscript` | 2 probe attempts in 10 min | 48 hours |
| `nginx-bad-host` | 3 wrong-host requests in 10 min | 1 hour |

## Installation

```bash
# Install fail2ban
sudo dnf install -y fail2ban

# Copy filter files
sudo cp filter.d/*.conf /etc/fail2ban/filter.d/

# Copy jail files
sudo cp jail.d/*.local /etc/fail2ban/jail.d/

# Enable and start fail2ban
sudo systemctl enable --now fail2ban

# Verify jails are active
sudo fail2ban-client status
```

## Monitoring

```bash
# Check status of all jails
sudo fail2ban-client status

# Check specific jail
sudo fail2ban-client status nginx-bad-request

# View banned IPs
sudo fail2ban-client status nginx-noscript | grep "Banned IP"

# Unban an IP (if needed)
sudo fail2ban-client set nginx-bad-request unbanip 1.2.3.4
```

## Log Locations

- Fail2ban log: `/var/log/fail2ban.log`
- Nginx access log: `/var/log/nginx/access.log`

## Requirements

- fail2ban package
- iptables (included in Amazon Linux 2023)
- nginx configured with catch-all servers (for nginx-bad-host)

## How It Works

Fail2ban monitors log files for malicious patterns and uses **iptables** to block offending IPs at the kernel level. This works independently of AWS Security Groups:

- **AWS Security Groups**: Allow/deny by port and source IP ranges (stateless, at VPC level)
- **iptables (via fail2ban)**: Dynamic blocking of specific IPs based on behavior (stateful, at instance level)

Both layers work together - Security Groups allow HTTP/HTTPS from anywhere, but fail2ban blocks specific bad actors.

## Notes

- The `banaction = iptables-multiport` uses iptables directly (works on Amazon Linux 2023 without firewalld)
- For systems with firewalld, change to `banaction = firewallcmd-rich-rules`
- Adjust `bantime`, `findtime`, and `maxretry` as needed for your security policy
- Banned IPs are stored in memory; they reset on fail2ban restart

