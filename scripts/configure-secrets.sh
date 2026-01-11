#!/bin/bash
# =============================================================================
# ORCD Rental Portal - Interactive Secrets Configuration Script
# =============================================================================
#
# This script interactively prompts for credentials and generates the
# configuration files with actual secrets.
#
# Usage:
#   chmod +x configure-secrets.sh
#   ./configure-secrets.sh
#
# Prerequisites:
#   - install_nginx_base.sh must have been run first (Nginx with HTTPS)
#   - install.sh must have been run (ColdFront installed)
#
# This script will:
#   1. Prompt for Globus OAuth client ID and secret
#   2. Prompt for your domain name
#   3. Generate a Django secret key
#   4. Create local_settings.py and coldfront.env from templates
#   5. Optionally deploy ColdFront-specific Nginx configuration
#
# =============================================================================

set -e

# =============================================================================
# Configuration
# =============================================================================

APP_DIR="/srv/coldfront"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/../config"
SECRETS_DIR="${SCRIPT_DIR}/../secrets"

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

prompt() {
    echo -e "${CYAN}$1${NC}"
}

generate_secret_key() {
    python3 -c "import secrets; print(secrets.token_urlsafe(50))"
}

# Detect service user from deployment.conf or default
detect_service_user() {
    local DEPLOY_CONF="${CONFIG_DIR}/deployment.conf"
    if [[ -f "${DEPLOY_CONF}" ]]; then
        source "${DEPLOY_CONF}"
    fi
    SERVICE_USER="${SERVICE_USER:-ec2-user}"
}

# =============================================================================
# Input Collection
# =============================================================================

collect_inputs() {
    echo ""
    echo "=============================================="
    echo " ORCD Rental Portal - Secrets Configuration"
    echo "=============================================="
    echo ""
    echo "This script will generate configuration files with your credentials."
    echo "You will need:"
    echo "  - Globus OAuth Client ID and Secret (from developers.globus.org)"
    echo "  - Your domain name (e.g., rental.mit-orcd.org)"
    echo ""
    
    # Domain name
    prompt "Enter your domain name (e.g., rental.mit-orcd.org):"
    read -r DOMAIN_NAME
    if [[ -z "${DOMAIN_NAME}" ]]; then
        log_error "Domain name is required"
        exit 1
    fi
    
    echo ""
    
    # Globus Client ID
    prompt "Enter your Globus OAuth Client ID:"
    read -r OIDC_CLIENT_ID
    if [[ -z "${OIDC_CLIENT_ID}" ]]; then
        log_error "Client ID is required"
        exit 1
    fi
    
    echo ""
    
    # Globus Client Secret (hidden input)
    prompt "Enter your Globus OAuth Client Secret (input hidden):"
    read -rs OIDC_CLIENT_SECRET
    echo ""  # Newline after hidden input
    if [[ -z "${OIDC_CLIENT_SECRET}" ]]; then
        log_error "Client Secret is required"
        exit 1
    fi
    
    echo ""
    
    # Generate Secret Key
    log_info "Generating Django secret key..."
    SECRET_KEY=$(generate_secret_key)
    
    echo ""
    echo "Configuration summary:"
    echo "  Domain:        ${DOMAIN_NAME}"
    echo "  Client ID:     ${OIDC_CLIENT_ID}"
    echo "  Client Secret: ****$(echo "${OIDC_CLIENT_SECRET}" | tail -c 5)"
    echo "  Secret Key:    ${SECRET_KEY:0:20}..."
    echo ""
    
    prompt "Create configuration files with these values? (y/n)"
    read -r CONFIRM
    if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
        log_warn "Cancelled by user"
        exit 0
    fi
}

# =============================================================================
# File Generation
# =============================================================================

generate_local_settings() {
    local TEMPLATE="${CONFIG_DIR}/local_settings.py.template"
    local OUTPUT="${APP_DIR}/local_settings.py"
    local SECRETS_COPY="${SECRETS_DIR}/local_settings.py"
    
    if [[ ! -f "${TEMPLATE}" ]]; then
        log_error "Template not found: ${TEMPLATE}"
        exit 1
    fi
    
    log_info "Generating local_settings.py..."
    
    # Save a copy in secrets directory first (always works)
    mkdir -p "${SECRETS_DIR}"
    sed -e "s|{{SECRET_KEY}}|${SECRET_KEY}|g" \
        -e "s|{{DOMAIN_NAME}}|${DOMAIN_NAME}|g" \
        -e "s|{{OIDC_CLIENT_ID}}|${OIDC_CLIENT_ID}|g" \
        -e "s|{{OIDC_CLIENT_SECRET}}|${OIDC_CLIENT_SECRET}|g" \
        "${TEMPLATE}" > "${SECRETS_COPY}"
    chmod 600 "${SECRETS_COPY}"
    log_info "Backup created: ${SECRETS_COPY}"
    
    # Try to copy to app directory (may need sudo)
    if cp "${SECRETS_COPY}" "${OUTPUT}" 2>/dev/null; then
        chmod 600 "${OUTPUT}"
        log_info "Created: ${OUTPUT}"
    else
        log_warn "Could not write to ${OUTPUT} (permission denied)"
        log_warn "Copying with sudo..."
        sudo cp "${SECRETS_COPY}" "${OUTPUT}"
        sudo chown "${SERVICE_USER}:${SERVICE_USER}" "${OUTPUT}"
        sudo chmod 600 "${OUTPUT}"
        log_info "Created: ${OUTPUT} (using sudo)"
    fi
}

generate_coldfront_env() {
    local TEMPLATE="${CONFIG_DIR}/coldfront.env.template"
    local OUTPUT="${APP_DIR}/coldfront.env"
    local SECRETS_COPY="${SECRETS_DIR}/coldfront.env"
    
    if [[ ! -f "${TEMPLATE}" ]]; then
        log_error "Template not found: ${TEMPLATE}"
        exit 1
    fi
    
    log_info "Generating coldfront.env..."
    
    # Save a copy in secrets directory first (always works)
    mkdir -p "${SECRETS_DIR}"
    sed -e "s|{{SECRET_KEY}}|${SECRET_KEY}|g" \
        -e "s|{{OIDC_CLIENT_ID}}|${OIDC_CLIENT_ID}|g" \
        -e "s|{{OIDC_CLIENT_SECRET}}|${OIDC_CLIENT_SECRET}|g" \
        "${TEMPLATE}" > "${SECRETS_COPY}"
    chmod 600 "${SECRETS_COPY}"
    log_info "Backup created: ${SECRETS_COPY}"
    
    # Try to copy to app directory (may need sudo)
    if cp "${SECRETS_COPY}" "${OUTPUT}" 2>/dev/null; then
        chmod 600 "${OUTPUT}"
        log_info "Created: ${OUTPUT}"
    else
        log_warn "Could not write to ${OUTPUT} (permission denied)"
        log_warn "Copying with sudo..."
        sudo cp "${SECRETS_COPY}" "${OUTPUT}"
        sudo chown "${SERVICE_USER}:${SERVICE_USER}" "${OUTPUT}"
        sudo chmod 600 "${OUTPUT}"
        log_info "Created: ${OUTPUT} (using sudo)"
    fi
}

deploy_coldfront_nginx() {
    log_warn "Nginx deployment has moved to scripts/install_nginx_app.sh"
    log_warn "Run: sudo ./scripts/install_nginx_app.sh --domain ${DOMAIN_NAME}"
}

# =============================================================================
# Post-Generation Info
# =============================================================================

print_next_steps() {
    echo ""
    echo "=============================================="
    echo " Configuration Complete!"
    echo "=============================================="
    echo ""
    echo "Files created:"
    echo "  - ${APP_DIR}/local_settings.py"
    echo "  - ${APP_DIR}/coldfront.env"
    echo "  - Backup copies in ${SECRETS_DIR}/"
    echo ""
    echo "IMPORTANT SECURITY NOTES:"
    echo "  - These files contain secrets - never commit to git!"
    echo "  - The secrets directory is gitignored for safety"
    echo "  - Keep backup copies in a secure location"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Deploy ColdFront Nginx app config:"
    echo "   sudo ./scripts/install_nginx_app.sh --domain ${DOMAIN_NAME}"
    echo ""
    echo "2. Initialize database:"
    echo "   cd ${APP_DIR}"
    echo "   source venv/bin/activate"
    echo "   export DJANGO_SETTINGS_MODULE=local_settings"
    echo "   export PLUGIN_API=True AUTO_PI_ENABLE=True AUTO_DEFAULT_PROJECT_ENABLE=True"
    echo "   coldfront migrate"
    echo "   coldfront initial_setup"
    echo "   coldfront makemigrations"
    echo "   coldfront migrate"
    echo "   coldfront collectstatic --noinput"
    echo "   coldfront createsuperuser"
    echo ""
    echo "3. Fix permissions:"
    echo "   sudo chown ${SERVICE_USER}:${SERVICE_USER} ${APP_DIR}/coldfront.db"
    echo "   sudo chmod 664 ${APP_DIR}/coldfront.db"
    echo "   sudo chmod -R 755 ${APP_DIR}/static"
    echo ""
    echo "4. Start ColdFront service:"
    echo "   sudo systemctl enable coldfront"
    echo "   sudo systemctl start coldfront"
    echo ""
    echo "5. Verify the site is working:"
    echo "   curl -I https://${DOMAIN_NAME}/"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Check if we can access the app directory
    if [[ ! -d "${APP_DIR}" ]]; then
        log_error "Application directory not found: ${APP_DIR}"
        log_error "Run install.sh first to create the directory structure"
        exit 1
    fi
    
    # Check for config templates
    if [[ ! -d "${CONFIG_DIR}" ]]; then
        log_error "Config directory not found: ${CONFIG_DIR}"
        log_error "Make sure you're running from the deployment package directory"
        exit 1
    fi
    
    detect_service_user
    collect_inputs
    generate_local_settings
    generate_coldfront_env
    print_next_steps
}

main "$@"
