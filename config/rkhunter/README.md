# rkhunter - Rootkit Hunter

rkhunter scans for rootkits, backdoors, and local exploits. It runs daily via cron.

## Installation

```bash
# Install rkhunter
sudo dnf install -y rkhunter

# Copy local configuration (reduces false positives on AL2023)
sudo cp rkhunter.conf.local /etc/rkhunter.conf.d/

# Initialize the file properties database
sudo rkhunter --propupd

# Run initial scan (interactive, to see what's happening)
sudo rkhunter --check

# Install daily cron job
sudo cp rkhunter-daily.sh /etc/cron.daily/rkhunter-daily
sudo chmod +x /etc/cron.daily/rkhunter-daily

# Create log directory
sudo mkdir -p /var/log/rkhunter
```

## What It Checks

- Known rootkits and malware signatures
- Suspicious file permissions
- Hidden files and directories
- Suspicious kernel modules
- Network port listeners
- Startup file changes
- Binary file modifications

## Commands

```bash
# Manual scan with all output
sudo rkhunter --check

# Quick scan (warnings only)
sudo rkhunter --check --skip-keypress --report-warnings-only

# Update signatures database
sudo rkhunter --update

# Update file properties (run after installing/updating packages)
sudo rkhunter --propupd

# View logs
sudo cat /var/log/rkhunter/rkhunter.log
sudo cat /var/log/rkhunter/rkhunter-cron.log
```

## Handling Warnings

After system updates, you may see warnings about changed binaries. This is normal:

```bash
# After dnf update, refresh the baseline
sudo rkhunter --propupd
```

## Log Locations

| Log | Purpose |
|-----|---------|
| `/var/log/rkhunter/rkhunter.log` | Main scan log |
| `/var/log/rkhunter/rkhunter-cron.log` | Daily cron job log |

## False Positives on Amazon Linux 2023

The included `rkhunter.conf.local` disables some checks that cause false positives on cloud instances:

- `suspscan` - Flags many legitimate cloud tools
- `hidden_ports` - Cloud metadata service uses unusual ports
- `deleted_files` - Common after package updates

## Cron Schedule

The daily script runs via `/etc/cron.daily/` which typically executes between 3-5 AM (depends on anacron/crond configuration).

To check when it runs:
```bash
cat /etc/anacrontab
```

