#!/bin/bash
# =============================================================================
# ORCD Rental Portal - Infrastructure Prerequisites Installation
# =============================================================================
#
# This script installs infrastructure prerequisites:
#   1. Nginx with HTTPS (via install_nginx_base.sh)
#   2. fail2ban with nginx protection jails
#   3. rkhunter rootkit scanner
#
# The nginx configuration includes catch-all server blocks that return 444
# for requests to unknown/spoofed domains.
#
# Usage:
#   sudo ./install_prereqs.sh --domain YOUR_DOMAIN --email YOUR_EMAIL
#
# Options:
#   --domain       Domain name for SSL certificate (required)
#   --email        Email for Let's Encrypt notifications (required)
#   --skip-nginx   Skip nginx installation (if already installed)
#   --skip-f2b     Skip fail2ban installation
#   --help         Show this help message
#
# After running this script:
#   1. Run install.sh to set up ColdFront
#   2. Run configure-secrets.sh
#   3. Run install_nginx_app.sh to deploy app-specific nginx config
#
# =============================================================================

set -e  # Exit on any error

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="${SCRIPT_DIR}/../ansible"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Helper Functions
# =============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

usage() {
    cat << EOF
Usage: $0 --domain DOMAIN --email EMAIL [OPTIONS]

Install infrastructure prerequisites for ORCD Rental Portal.

Required:
  --domain DOMAIN    Domain name for SSL certificate
  --email EMAIL      Email for Let's Encrypt notifications

Options:
  --skip-nginx       Skip nginx base installation (if already done)
  --skip-f2b         Skip fail2ban installation
  --help             Show this help message

Examples:
  $0 --domain rental.example.com --email admin@example.com
  $0 --domain rental.example.com --email admin@example.com --skip-nginx

EOF
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID}"
        DISTRO_NAME="${NAME}"
        
        case "${DISTRO_ID}" in
            amzn|rhel|centos|rocky|almalinux|fedora)
                DISTRO_FAMILY="rhel"
                PKG_MANAGER="dnf"
                ;;
            debian|ubuntu)
                DISTRO_FAMILY="debian"
                PKG_MANAGER="apt"
                ;;
            *)
                log_warn "Unknown distribution: ${DISTRO_ID}"
                DISTRO_FAMILY="unknown"
                PKG_MANAGER="unknown"
                ;;
        esac
        
        log_info "Detected: ${DISTRO_NAME} (${DISTRO_FAMILY} family)"
    else
        log_warn "Cannot detect distribution, assuming RHEL-like"
        DISTRO_FAMILY="rhel"
        PKG_MANAGER="dnf"
    fi
}

# =============================================================================
# Installation Steps
# =============================================================================

install_nginx_base() {
    log_step "Installing Nginx with HTTPS..."
    
    if [[ ! -f "${SCRIPT_DIR}/install_nginx_base.sh" ]]; then
        log_error "install_nginx_base.sh not found in ${SCRIPT_DIR}"
        exit 1
    fi
    
    # Run nginx base installation
    "${SCRIPT_DIR}/install_nginx_base.sh" --domain "${DOMAIN_NAME}" --email "${CERTBOT_EMAIL}"
    
    log_info "Nginx base installation complete"
}

ensure_ansible() {
    log_step "Ensuring Ansible is available..."
    
    if command -v ansible-playbook &>/dev/null; then
        log_info "Ansible already installed: $(ansible --version | head -1)"
        return 0
    fi
    
    log_info "Installing Ansible..."
    case "${PKG_MANAGER}" in
        dnf)
            dnf install -y ansible-core
            ;;
        apt)
            apt-get update
            apt-get install -y ansible
            ;;
        *)
            log_error "Cannot install Ansible: unknown package manager"
            exit 1
            ;;
    esac
    
    log_info "Ansible installed successfully"
}

install_fail2ban_and_security() {
    log_step "Installing fail2ban and security tools..."
    
    if [[ ! -f "${ANSIBLE_DIR}/prereqs.yml" ]]; then
        log_error "Ansible playbook not found: ${ANSIBLE_DIR}/prereqs.yml"
        exit 1
    fi
    
    # Run Ansible playbook for fail2ban and rkhunter
    cd "${ANSIBLE_DIR}"
    ansible-playbook prereqs.yml \
        -e "domain_name=${DOMAIN_NAME}" \
        -i inventory/localhost.yml \
        --connection=local
    
    log_info "Security tools installation complete"
}

verify_installation() {
    log_step "Verifying installation..."
    
    local errors=0
    
    # Check nginx
    if systemctl is-active --quiet nginx; then
        log_info "✓ Nginx is running"
    else
        log_error "✗ Nginx is not running"
        errors=$((errors + 1))
    fi
    
    # Check fail2ban
    if systemctl is-active --quiet fail2ban; then
        log_info "✓ fail2ban is running"
        
        # Check jails
        local jail_count=$(fail2ban-client status 2>/dev/null | grep "Number of jail" | awk '{print $NF}')
        if [[ "${jail_count}" -gt 0 ]]; then
            log_info "✓ fail2ban has ${jail_count} active jails"
        else
            log_warn "⚠ No active fail2ban jails"
        fi
    else
        log_error "✗ fail2ban is not running"
        errors=$((errors + 1))
    fi
    
    # Check SSL certificate
    if [[ -f "/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem" ]]; then
        log_info "✓ SSL certificate exists for ${DOMAIN_NAME}"
    else
        log_warn "⚠ SSL certificate not found (HTTPS catch-all disabled)"
    fi
    
    # Test HTTP 444 catch-all
    log_info "Testing HTTP catch-all (should return connection reset)..."
    if curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -H "Host: unknown.domain.test" "http://localhost/" 2>/dev/null | grep -q "000"; then
        log_info "✓ HTTP catch-all is working (connection closed)"
    else
        log_warn "⚠ HTTP catch-all test inconclusive"
    fi
    
    return ${errors}
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Parse arguments
    DOMAIN_NAME=""
    CERTBOT_EMAIL=""
    SKIP_NGINX=false
    SKIP_F2B=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                DOMAIN_NAME="$2"
                shift 2
                ;;
            --email)
                CERTBOT_EMAIL="$2"
                shift 2
                ;;
            --skip-nginx)
                SKIP_NGINX=true
                shift
                ;;
            --skip-f2b)
                SKIP_F2B=true
                shift
                ;;
            --help)
                usage
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "${DOMAIN_NAME}" ]]; then
        log_error "Missing required argument: --domain"
        usage
    fi
    
    if [[ -z "${CERTBOT_EMAIL}" ]] && [[ "${SKIP_NGINX}" != "true" ]]; then
        log_error "Missing required argument: --email (required unless --skip-nginx)"
        usage
    fi
    
    echo "=============================================="
    echo " Infrastructure Prerequisites Installation"
    echo "=============================================="
    echo ""
    echo " Domain: ${DOMAIN_NAME}"
    echo " Email:  ${CERTBOT_EMAIL:-N/A}"
    echo " Skip Nginx: ${SKIP_NGINX}"
    echo " Skip fail2ban: ${SKIP_F2B}"
    echo ""
    
    check_root
    detect_distro
    
    # Step 1: Install Nginx with HTTPS
    if [[ "${SKIP_NGINX}" != "true" ]]; then
        install_nginx_base
    else
        log_info "Skipping nginx installation (--skip-nginx)"
        # Verify nginx is running
        if ! systemctl is-active --quiet nginx; then
            log_error "Nginx is not running but --skip-nginx was specified"
            log_error "Please run install_nginx_base.sh first or remove --skip-nginx"
            exit 1
        fi
    fi
    
    # Step 2: Install fail2ban and security tools
    if [[ "${SKIP_F2B}" != "true" ]]; then
        ensure_ansible
        install_fail2ban_and_security
    else
        log_info "Skipping fail2ban installation (--skip-f2b)"
    fi
    
    # Step 3: Verify installation
    verify_installation
    
    echo ""
    echo "=============================================="
    echo " Prerequisites Installation Complete!"
    echo "=============================================="
    echo ""
    echo "Infrastructure Security:"
    echo "  - Nginx with HTTPS configured"
    echo "  - HTTP/HTTPS catch-all blocks returning 444"
    echo "  - fail2ban protecting against attacks"
    echo "  - rkhunter rootkit scanner installed"
    echo ""
    echo "Next steps:"
    echo "  1. Install ColdFront: sudo ./scripts/install.sh"
    echo "  2. Configure secrets: ./scripts/configure-secrets.sh"
    echo "  3. Deploy app nginx:  sudo ./scripts/install_nginx_app.sh --domain ${DOMAIN_NAME}"
    echo ""
    echo "Verify fail2ban: sudo fail2ban-client status"
    echo ""
}

main "$@"
