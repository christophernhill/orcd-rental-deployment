#!/bin/bash
# =============================================================================
# ORCD Rental Portal - Nginx Base Installation Script
# =============================================================================
#
# This script installs and configures Nginx with HTTPS (via Let's Encrypt)
# on multiple Linux distributions. It uses Ansible for the actual installation
# to ensure consistent behavior across distros.
#
# Usage:
#   sudo ./install_nginx_base.sh --domain example.com --email admin@example.com
#
# Supported Distributions:
#   - Amazon Linux 2023
#   - RHEL 8/9, Rocky Linux, AlmaLinux
#   - Debian 11/12
#   - Ubuntu 22.04/24.04
#
# After running this script:
#   - Nginx will be running under systemd
#   - HTTPS will be configured with a valid Let's Encrypt certificate
#   - A placeholder page will be served
#   - You can then run install.sh to set up ColdFront
#
# =============================================================================

set -e

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"
ANSIBLE_DIR="${REPO_DIR}/ansible"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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
    echo -e "${CYAN}[STEP]${NC} $1"
}

usage() {
    cat << EOF
Usage: sudo $0 --domain DOMAIN --email EMAIL [OPTIONS]

Required:
  --domain DOMAIN    Domain name for the server (e.g., example.com)
  --email EMAIL      Email address for Let's Encrypt notifications

Options:
  --skip-ssl         Skip SSL certificate acquisition (for testing)
  --dry-run          Show what would be done without making changes
  --help             Show this help message

Examples:
  sudo $0 --domain rental.mit-orcd.org --email admin@mit.edu
  sudo $0 --domain test.example.com --email test@example.com --skip-ssl

EOF
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# =============================================================================
# Distribution Detection
# =============================================================================

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID}"
        DISTRO_VERSION="${VERSION_ID}"
        DISTRO_NAME="${NAME}"
        
        # Normalize distro family
        case "${DISTRO_ID}" in
            amzn)
                DISTRO_FAMILY="rhel"
                PKG_MANAGER="dnf"
                ;;
            rhel|centos|rocky|almalinux|fedora)
                DISTRO_FAMILY="rhel"
                PKG_MANAGER="dnf"
                ;;
            debian)
                DISTRO_FAMILY="debian"
                PKG_MANAGER="apt"
                ;;
            ubuntu)
                DISTRO_FAMILY="debian"
                PKG_MANAGER="apt"
                ;;
            *)
                log_error "Unsupported distribution: ${DISTRO_ID}"
                log_error "Supported: Amazon Linux, RHEL, Rocky, Alma, Debian, Ubuntu"
                exit 1
                ;;
        esac
        
        log_info "Detected: ${DISTRO_NAME} (${DISTRO_FAMILY} family)"
    else
        log_error "Cannot detect distribution: /etc/os-release not found"
        exit 1
    fi
}

# =============================================================================
# Ansible Installation
# =============================================================================

install_ansible() {
    if command -v ansible-playbook &> /dev/null; then
        local version=$(ansible --version | head -1)
        log_info "Ansible already installed: ${version}"
        return 0
    fi
    
    log_step "Installing Ansible..."
    
    case "${PKG_MANAGER}" in
        dnf)
            dnf install -y ansible-core
            ;;
        apt)
            apt-get update
            apt-get install -y ansible
            ;;
    esac
    
    if command -v ansible-playbook &> /dev/null; then
        log_info "Ansible installed successfully"
    else
        log_error "Failed to install Ansible"
        exit 1
    fi
}

install_ansible_collections() {
    log_step "Ensuring required Ansible collections are installed..."

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "DRY RUN - would execute:"
        echo "  ansible-galaxy collection install community.general ansible.posix"
        return 0
    fi

    # Install required collections (idempotent)
    if ! ansible-galaxy collection install community.general ansible.posix >/dev/null 2>&1; then
        log_warn "Collection install reported warnings; re-running with output"
        ansible-galaxy collection install community.general ansible.posix
    fi

    log_info "Ansible collections ready (community.general, ansible.posix)"
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight_checks() {
    log_step "Running pre-flight checks..."
    
    # Check domain resolves
    log_info "Checking DNS resolution for ${DOMAIN_NAME}..."
    if command -v host >/dev/null 2>&1; then
        if host "${DOMAIN_NAME}" >/dev/null 2>&1; then
            log_info "DNS resolution OK"
        else
            log_warn "DNS lookup failed for ${DOMAIN_NAME}"
            log_warn "Make sure DNS is configured before obtaining SSL certificate"
        fi
    elif command -v dig >/dev/null 2>&1; then
        # Consider DNS OK if dig returns a non-empty result
        if [[ -n "$(dig +short "${DOMAIN_NAME}" 2>/dev/null)" ]]; then
            log_info "DNS resolution OK"
        else
            log_warn "DNS lookup failed for ${DOMAIN_NAME}"
            log_warn "Make sure DNS is configured before obtaining SSL certificate"
        fi
    elif command -v getent >/dev/null 2>&1; then
        if getent hosts "${DOMAIN_NAME}" >/dev/null 2>&1; then
            log_info "DNS resolution OK"
        else
            log_warn "DNS lookup failed for ${DOMAIN_NAME}"
            log_warn "Make sure DNS is configured before obtaining SSL certificate"
        fi
    else
        log_warn "No DNS lookup tools found (host, dig, getent); skipping DNS resolution check"
    fi
    
    # Check ports are available
    if ss -tuln | grep -q ':80 '; then
        log_warn "Port 80 is already in use"
        if systemctl is-active --quiet nginx; then
            log_info "Nginx is already running - will reconfigure"
        else
            log_error "Port 80 is in use by another service"
            ss -tuln | grep ':80 '
            exit 1
        fi
    fi
    
    if ss -tuln | grep -q ':443 '; then
        log_warn "Port 443 is already in use"
        if systemctl is-active --quiet nginx; then
            log_info "Nginx is already running - will reconfigure"
        else
            log_error "Port 443 is in use by another service"
            ss -tuln | grep ':443 '
            exit 1
        fi
    fi
    
    # Check Ansible playbook exists
    if [[ ! -f "${ANSIBLE_DIR}/nginx-base.yml" ]]; then
        log_error "Ansible playbook not found: ${ANSIBLE_DIR}/nginx-base.yml"
        log_error "Make sure you're running from the repository directory"
        exit 1
    fi
    
    log_info "Pre-flight checks passed"
}

# =============================================================================
# Run Ansible Playbook
# =============================================================================

run_ansible() {
    log_step "Running Ansible playbook..."
    
    local extra_vars="domain_name=${DOMAIN_NAME} certbot_email=${CERTBOT_EMAIL}"
    
    if [[ "${SKIP_SSL}" == "true" ]]; then
        extra_vars="${extra_vars} skip_ssl=true"
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "DRY RUN - would execute:"
        echo "  ansible-playbook ${ANSIBLE_DIR}/nginx-base.yml \\"
        echo "    -i ${ANSIBLE_DIR}/inventory/localhost.yml \\"
        echo "    -e \"${extra_vars}\""
        return 0
    fi
    
    cd "${ANSIBLE_DIR}"
    
    ansible-playbook nginx-base.yml \
        -i inventory/localhost.yml \
        -e "${extra_vars}" \
        --become
    
    local result=$?
    
    if [[ ${result} -ne 0 ]]; then
        log_error "Ansible playbook failed with exit code ${result}"
        exit ${result}
    fi
    
    log_info "Ansible playbook completed successfully"
}

# =============================================================================
# Verification
# =============================================================================

verify_installation() {
    log_step "Verifying installation..."
    
    local errors=0
    
    # Check nginx is running
    if systemctl is-active --quiet nginx; then
        log_info "✓ Nginx is running"
    else
        log_error "✗ Nginx is not running"
        ((errors++))
    fi
    
    # Check nginx is enabled
    if systemctl is-enabled --quiet nginx; then
        log_info "✓ Nginx is enabled (will start on boot)"
    else
        log_warn "⚠ Nginx is not enabled for boot"
    fi
    
    # Check HTTP response (use Host header to avoid 444 catch-all)
    if curl -s -o /dev/null -w "%{http_code}" -H "Host: ${DOMAIN_NAME}" "http://127.0.0.1/" | grep -q "200\|301\|302"; then
        log_info "✓ HTTP is responding for ${DOMAIN_NAME}"
    else
        log_warn "⚠ HTTP not responding (may be redirecting to HTTPS)"
    fi
    
    # Check HTTPS if not skipped
    if [[ "${SKIP_SSL}" != "true" ]]; then
        # Wait a moment for certificate to be fully configured
        sleep 2
        
        if curl -s -o /dev/null -w "%{http_code}" "https://${DOMAIN_NAME}/" 2>/dev/null | grep -q "200"; then
            log_info "✓ HTTPS is working"
        else
            log_warn "⚠ HTTPS check failed (may need DNS propagation)"
        fi
        
        # Check certificate
        if [[ -f "/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem" ]]; then
            log_info "✓ SSL certificate exists"
            
            # Show expiry
            local expiry=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem" 2>/dev/null | cut -d= -f2)
            if [[ -n "${expiry}" ]]; then
                log_info "  Certificate expires: ${expiry}"
            fi
        else
            log_error "✗ SSL certificate not found"
            ((errors++))
        fi
        
        # Check certbot timer
        if systemctl is-active --quiet certbot-renew.timer 2>/dev/null || \
           systemctl is-active --quiet certbot.timer 2>/dev/null; then
            log_info "✓ Certbot auto-renewal is configured"
        else
            log_warn "⚠ Certbot timer not found (check cron for renewal)"
        fi
    fi
    
    if [[ ${errors} -gt 0 ]]; then
        log_error "Verification failed with ${errors} error(s)"
        return 1
    fi
    
    log_info "Verification passed"
    return 0
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Parse arguments
    DOMAIN_NAME=""
    CERTBOT_EMAIL=""
    SKIP_SSL="false"
    DRY_RUN="false"
    
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
            --skip-ssl)
                SKIP_SSL="true"
                shift
                ;;
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --help|-h)
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
    
    if [[ -z "${CERTBOT_EMAIL}" ]] && [[ "${SKIP_SSL}" != "true" ]]; then
        log_error "Missing required argument: --email (required for SSL)"
        usage
    fi
    
    echo "=============================================="
    echo " Nginx Base Installation"
    echo "=============================================="
    echo ""
    echo " Domain: ${DOMAIN_NAME}"
    echo " Email:  ${CERTBOT_EMAIL:-N/A}"
    echo " SSL:    $([ "${SKIP_SSL}" == "true" ] && echo "Skipped" || echo "Let's Encrypt")"
    echo ""
    
    check_root
    detect_distro
    install_ansible
    install_ansible_collections
    preflight_checks
    run_ansible
    
    if [[ "${DRY_RUN}" != "true" ]]; then
        verify_installation
    fi
    
    echo ""
    echo "=============================================="
    echo " Installation Complete!"
    echo "=============================================="
    echo ""
    
    if [[ "${SKIP_SSL}" == "true" ]]; then
        echo "Note: SSL was skipped. To obtain a certificate later:"
        echo "  sudo certbot --nginx -d ${DOMAIN_NAME}"
        echo ""
    fi
    
    echo "Nginx is now serving a placeholder page at:"
    if [[ "${SKIP_SSL}" == "true" ]]; then
        echo "  http://${DOMAIN_NAME}/"
    else
        echo "  https://${DOMAIN_NAME}/"
    fi
    echo ""
    echo "Next steps:"
    echo "  1. Verify the placeholder page is accessible"
    echo "  2. Run install.sh to set up ColdFront"
    echo "  3. Configure ColdFront-specific Nginx settings"
    echo ""
}

main "$@"
