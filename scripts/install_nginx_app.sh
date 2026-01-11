#!/bin/bash
# =============================================================================
# ORCD Rental Portal - Nginx Application Configuration Script
# =============================================================================
#
# This script deploys the ColdFront application Nginx configuration AFTER
# the base Nginx + HTTPS setup (install_nginx_base.sh) is complete.
#
# Usage:
#   sudo ./install_nginx_app.sh --domain example.com [--app-socket /srv/coldfront/coldfront.sock] [--static-root /srv/coldfront/static]
#
# Requirements:
#   - Base Nginx install with valid SSL certificate already completed
#   - Ansible installed (installed by install_nginx_base.sh)
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"
ANSIBLE_DIR="${REPO_DIR}/ansible"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

usage() {
    cat << EOF
Usage: sudo $0 --domain DOMAIN [--app-socket PATH] [--static-root PATH] [--dry-run]

Required:
  --domain DOMAIN       Domain name for the application (e.g., example.com)

Optional:
  --app-socket PATH     Gunicorn socket path (default: /srv/coldfront/coldfront.sock)
  --static-root PATH    Static files root (default: /srv/coldfront/static)
  --dry-run             Show what would be done without applying changes
  --help                Show this help
EOF
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_ansible() {
    if ! command -v ansible-playbook >/dev/null 2>&1; then
        log_error "ansible-playbook not found."
        log_error "Run install_nginx_base.sh first to install Ansible and base Nginx."
        exit 1
    fi
}

check_cert() {
    local cert_path="/etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem"
    if [[ ! -f "${cert_path}" ]]; then
        log_warn "Certificate not found at ${cert_path}."
        log_warn "Ensure install_nginx_base.sh completed and certbot succeeded."
    fi
}

run_playbook() {
    log_step "Running Nginx application playbook..."

    local extra_vars="domain_name=${DOMAIN_NAME} app_socket=${APP_SOCKET} static_root=${STATIC_ROOT}"

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "DRY RUN - would execute:"
        echo "  ansible-playbook ${ANSIBLE_DIR}/nginx-app.yml \\"
        echo "    -i ${ANSIBLE_DIR}/inventory/localhost.yml \\"
        echo "    -e \"${extra_vars}\""
        return 0
    fi

    cd "${ANSIBLE_DIR}"

    ansible-playbook nginx-app.yml \
        -i inventory/localhost.yml \
        -e "${extra_vars}" \
        --become
}

main() {
    DOMAIN_NAME=""
    APP_SOCKET="/srv/coldfront/coldfront.sock"
    STATIC_ROOT="/srv/coldfront/static"
    DRY_RUN="false"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)
                DOMAIN_NAME="$2"; shift 2 ;;
            --app-socket)
                APP_SOCKET="$2"; shift 2 ;;
            --static-root)
                STATIC_ROOT="$2"; shift 2 ;;
            --dry-run)
                DRY_RUN="true"; shift ;;
            --help|-h)
                usage ;;
            *)
                log_error "Unknown option: $1"
                usage ;;
        esac
    done

    if [[ -z "${DOMAIN_NAME}" ]]; then
        log_error "Missing required argument: --domain"
        usage
    fi

    echo "=============================================="
    echo " Nginx Application Configuration"
    echo "=============================================="
    echo " Domain: ${DOMAIN_NAME}"
    echo " Socket: ${APP_SOCKET}"
    echo " Static: ${STATIC_ROOT}"
    echo "=============================================="

    check_root
    check_ansible
    check_cert
    run_playbook

    if [[ "${DRY_RUN}" != "true" ]]; then
        log_info "Application Nginx configuration applied."
        log_info "Placeholder config has been removed if present."
        log_info "If ColdFront is not yet running, start it and verify HTTPS."
    else
        log_info "Dry run complete. No changes applied."
    fi
}

main "$@"
