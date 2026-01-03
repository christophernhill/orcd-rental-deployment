#!/bin/bash
# =============================================================================
# ORCD Rental Portal - Health Check Script
# =============================================================================
#
# This script checks the health of all components of the ORCD Rental Portal.
#
# Usage:
#   chmod +x healthcheck.sh
#   ./healthcheck.sh
#
# Exit codes:
#   0 - All checks passed
#   1 - One or more checks failed
#
# =============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED=0

# =============================================================================
# Helper Functions
# =============================================================================

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=1
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

check_service() {
    local service=$1
    if systemctl is-active --quiet "${service}"; then
        check_pass "Service ${service} is running"
    else
        check_fail "Service ${service} is not running"
    fi
}

check_file() {
    local file=$1
    local description=$2
    if [[ -f "${file}" ]]; then
        check_pass "${description}: ${file}"
    else
        check_fail "${description} not found: ${file}"
    fi
}

check_port() {
    local port=$1
    local description=$2
    if ss -tlnp | grep -q ":${port}"; then
        check_pass "${description} is listening on port ${port}"
    else
        check_fail "${description} is not listening on port ${port}"
    fi
}

# =============================================================================
# Checks
# =============================================================================

echo "=============================================="
echo " ORCD Rental Portal Health Check"
echo "=============================================="
echo ""
echo "Timestamp: $(date)"
echo ""

# System Services
echo "--- System Services ---"
check_service "coldfront"
check_service "nginx"
check_service "redis6"
echo ""

# Network Ports
echo "--- Network Ports ---"
check_port 80 "HTTP"
check_port 443 "HTTPS"
echo ""

# Configuration Files
echo "--- Configuration Files ---"
check_file "/srv/coldfront/local_settings.py" "Django settings"
check_file "/srv/coldfront/coldfront.env" "Environment file"
check_file "/srv/coldfront/coldfront_auth.py" "OIDC backend"
check_file "/srv/coldfront/wsgi.py" "WSGI entry"
check_file "/etc/nginx/conf.d/coldfront.conf" "Nginx config"
check_file "/etc/systemd/system/coldfront.service" "Systemd service"
echo ""

# Database
echo "--- Database ---"
if [[ -f "/srv/coldfront/coldfront.db" ]]; then
    check_pass "Database file exists"
    
    # Check if writable
    if [[ -w "/srv/coldfront/coldfront.db" ]]; then
        check_pass "Database is writable"
    else
        check_warn "Database may not be writable by current user"
    fi
else
    check_fail "Database file not found"
fi
echo ""

# Gunicorn Socket
echo "--- Application Socket ---"
if [[ -S "/srv/coldfront/coldfront.sock" ]]; then
    check_pass "Gunicorn socket exists"
else
    check_fail "Gunicorn socket not found (is coldfront service running?)"
fi
echo ""

# Static Files
echo "--- Static Files ---"
if [[ -d "/srv/coldfront/static" ]]; then
    FILE_COUNT=$(find /srv/coldfront/static -type f | wc -l)
    if [[ ${FILE_COUNT} -gt 0 ]]; then
        check_pass "Static files directory has ${FILE_COUNT} files"
    else
        check_fail "Static files directory is empty (run collectstatic)"
    fi
else
    check_fail "Static files directory not found"
fi
echo ""

# SSL Certificate
echo "--- SSL Certificate ---"
# Try to find any certificate in letsencrypt live directory
CERT_FILE=""
if [[ -d "/etc/letsencrypt/live" ]]; then
    # Find the first certificate directory
    for dir in /etc/letsencrypt/live/*/; do
        if [[ -f "${dir}fullchain.pem" ]]; then
            CERT_FILE="${dir}fullchain.pem"
            CERT_DOMAIN=$(basename "${dir%/}")
            break
        fi
    done
fi

if [[ -n "${CERT_FILE}" && -f "${CERT_FILE}" ]]; then
    check_pass "SSL certificate exists for ${CERT_DOMAIN}"
    
    # Check expiry
    EXPIRY=$(openssl x509 -enddate -noout -in "${CERT_FILE}" 2>/dev/null | cut -d= -f2)
    if [[ -n "${EXPIRY}" ]]; then
        EXPIRY_EPOCH=$(date -d "${EXPIRY}" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        if [[ -n "${EXPIRY_EPOCH}" ]]; then
            DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
            
            if [[ ${DAYS_LEFT} -gt 30 ]]; then
                check_pass "SSL certificate expires in ${DAYS_LEFT} days"
            elif [[ ${DAYS_LEFT} -gt 0 ]]; then
                check_warn "SSL certificate expires in ${DAYS_LEFT} days (renew soon!)"
            else
                check_fail "SSL certificate has expired!"
            fi
        fi
    fi
else
    # Check if HTTPS is actually working even if we can't find the cert file
    if curl -s -o /dev/null -w "%{http_code}" -k https://localhost/ 2>/dev/null | grep -qE "^(200|301|302)"; then
        check_warn "SSL is working but certificate file not found in /etc/letsencrypt/live/"
    else
        check_fail "SSL certificate not found (run certbot)"
    fi
fi
echo ""

# Django Health
echo "--- Django Application ---"
if [[ -f "/srv/coldfront/venv/bin/python" ]]; then
    check_pass "Python virtual environment exists"
    
    # Try to import Django
    cd /srv/coldfront
    source venv/bin/activate
    export DJANGO_SETTINGS_MODULE=local_settings
    export PLUGIN_API=True
    
    if python -c "import django; django.setup()" 2>/dev/null; then
        check_pass "Django configuration is valid"
    else
        check_fail "Django configuration error (check logs)"
    fi
    
    deactivate 2>/dev/null || true
else
    check_fail "Python virtual environment not found"
fi
echo ""

# Log Files
echo "--- Log Files ---"
for logfile in /srv/coldfront/coldfront.log /srv/coldfront/oidc_debug.log /srv/coldfront/gunicorn-error.log; do
    if [[ -f "${logfile}" ]]; then
        SIZE=$(du -h "${logfile}" | cut -f1)
        ERRORS=$(tail -100 "${logfile}" 2>/dev/null | grep -ciE "error|exception|critical" || true)
        # Ensure ERRORS is a valid number
        if [[ ! "${ERRORS}" =~ ^[0-9]+$ ]]; then
            ERRORS=0
        fi
        if [[ ${ERRORS} -gt 0 ]]; then
            check_warn "${logfile} (${SIZE}) - ${ERRORS} recent errors"
        else
            check_pass "${logfile} (${SIZE})"
        fi
    fi
done
echo ""

# Web Response Test
echo "--- Web Response Test ---"
if command -v curl &> /dev/null; then
    # Test HTTP redirect
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null || echo "000")
    if [[ "${HTTP_CODE}" == "301" || "${HTTP_CODE}" == "302" ]]; then
        check_pass "HTTP redirects to HTTPS (${HTTP_CODE})"
    elif [[ "${HTTP_CODE}" == "000" ]]; then
        check_fail "Cannot connect to HTTP"
    else
        check_warn "HTTP returns ${HTTP_CODE} (expected 301/302)"
    fi
    
    # Test HTTPS
    HTTPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -k https://localhost/ 2>/dev/null || echo "000")
    if [[ "${HTTPS_CODE}" == "200" || "${HTTPS_CODE}" == "302" ]]; then
        check_pass "HTTPS responds (${HTTPS_CODE})"
    elif [[ "${HTTPS_CODE}" == "000" ]]; then
        check_fail "Cannot connect to HTTPS"
    else
        check_warn "HTTPS returns ${HTTPS_CODE}"
    fi
else
    check_warn "curl not available - skipping web tests"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================

echo "=============================================="
if [[ ${FAILED} -eq 0 ]]; then
    echo -e "${GREEN}All checks passed!${NC}"
    exit 0
else
    echo -e "${RED}Some checks failed - review above for details${NC}"
    exit 1
fi

