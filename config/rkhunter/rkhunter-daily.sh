#!/bin/bash
# =============================================================================
# rkhunter Daily Scan Script
# =============================================================================
#
# This script updates rkhunter databases and runs a full scan.
# Designed to be run via cron daily.
#
# Install location: /etc/cron.daily/rkhunter-daily
#
# =============================================================================

# Exit on error
set -e

# Log file
LOGFILE="/var/log/rkhunter/rkhunter-cron.log"
MAILTO="root"

# Ensure log directory exists
mkdir -p /var/log/rkhunter

# Add timestamp
echo "========================================" >> "$LOGFILE"
echo "rkhunter scan started: $(date)" >> "$LOGFILE"
echo "========================================" >> "$LOGFILE"

# Update rkhunter database (signatures)
echo "Updating rkhunter database..." >> "$LOGFILE"
/usr/bin/rkhunter --update >> "$LOGFILE" 2>&1 || true

# Update file properties database (after system updates)
echo "Updating file properties..." >> "$LOGFILE"
/usr/bin/rkhunter --propupd >> "$LOGFILE" 2>&1

# Run the scan
echo "Running rkhunter scan..." >> "$LOGFILE"
/usr/bin/rkhunter --check --skip-keypress --report-warnings-only >> "$LOGFILE" 2>&1
SCAN_RESULT=$?

# Add completion timestamp
echo "Scan completed: $(date)" >> "$LOGFILE"
echo "Exit code: $SCAN_RESULT" >> "$LOGFILE"
echo "" >> "$LOGFILE"

# If warnings found, send email (if mail is configured)
if [ $SCAN_RESULT -ne 0 ]; then
    echo "rkhunter found warnings - check $LOGFILE"
    if command -v mail &> /dev/null; then
        tail -100 "$LOGFILE" | mail -s "rkhunter WARNING on $(hostname)" "$MAILTO"
    fi
fi

exit 0

