#!/bin/bash
# =============================================================================
# ORCD Rental Portal - ColdFront Installation Script
# =============================================================================
#
# This script installs ColdFront with the ORCD Direct Charge plugin.
#
# PREREQUISITES:
#   - Nginx with HTTPS must be configured first!
#   - Run: sudo ./install_nginx_base.sh --domain YOUR_DOMAIN --email YOUR_EMAIL
#
# Usage:
#   chmod +x install.sh
#   sudo ./install.sh
#
# Supported Distributions:
#   - Amazon Linux 2023
#   - RHEL 8/9, Rocky Linux, AlmaLinux
#   - Debian 11/12
#   - Ubuntu 22.04/24.04
#
# After running this script, you still need to:
#   1. Run configure-secrets.sh to set up credentials
#   2. Run database migrations
#   3. Create superuser
#   4. Deploy ColdFront-specific Nginx configuration
#
# =============================================================================

set -e  # Exit on any error

# =============================================================================
# Configuration
# =============================================================================

# These will be loaded from deployment.conf
# Defaults here are overridden by load_deployment_config()
APP_DIR="/srv/coldfront"
VENV_DIR="${APP_DIR}/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/../config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
                log_warn "Attempting to continue..."
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

load_deployment_config() {
    local CONFIG_FILE="${CONFIG_DIR}/deployment.conf"
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        log_error "Deployment configuration not found: ${CONFIG_FILE}"
        log_error "Please create deployment.conf from the template:"
        log_error "  cp config/deployment.conf.template config/deployment.conf"
        exit 1
    fi
    
    log_info "Loading deployment configuration from ${CONFIG_FILE}..."
    source "${CONFIG_FILE}"
    
    # Validate required variables
    local required_vars=("PLUGIN_REPO" "PLUGIN_VERSION" "COLDFRONT_VERSION" "APP_DIR" "VENV_DIR" "SERVICE_USER")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            log_error "Required variable ${var} not set in deployment.conf"
            exit 1
        fi
    done
    
    log_info "Configuration loaded successfully"
    log_info "  Plugin: ${PLUGIN_VERSION} from ${PLUGIN_REPO}"
    log_info "  ColdFront: ${COLDFRONT_VERSION}"
    log_info "  Install path: ${APP_DIR}"
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

check_nginx_running() {
    log_info "Checking Nginx status..."
    
    if ! systemctl is-active --quiet nginx; then
        log_error "Nginx is not running!"
        log_error ""
        log_error "You must run install_nginx_base.sh first to set up Nginx with HTTPS."
        log_error "Example:"
        log_error "  sudo ./install_nginx_base.sh --domain YOUR_DOMAIN --email YOUR_EMAIL"
        log_error ""
        exit 1
    fi
    
    log_info "✓ Nginx is running"
    
    # Check if HTTPS is configured (certificate exists)
    if [[ -d /etc/letsencrypt/live ]]; then
        local cert_count=$(find /etc/letsencrypt/live -name "fullchain.pem" 2>/dev/null | wc -l)
        if [[ ${cert_count} -gt 0 ]]; then
            log_info "✓ SSL certificates found"
        else
            log_warn "No SSL certificates found in /etc/letsencrypt/live"
            log_warn "HTTPS may not be configured. Consider running install_nginx_base.sh"
        fi
    else
        log_warn "Let's Encrypt directory not found"
        log_warn "HTTPS may not be configured. Consider running install_nginx_base.sh"
    fi
}

# =============================================================================
# Installation Steps
# =============================================================================

install_system_packages() {
    log_info "Installing system packages..."
    
    case "${PKG_MANAGER}" in
        dnf)
            dnf update -y
            dnf install -y python3 python3-devel python3-pip git redis6
            dnf groupinstall -y "Development Tools"
            
            log_info "Enabling and starting Redis..."
            systemctl enable --now redis6
            ;;
        apt)
            apt-get update
            apt-get install -y python3 python3-dev python3-pip python3-venv git redis-server build-essential
            
            log_info "Enabling and starting Redis..."
            systemctl enable --now redis-server
            ;;
        *)
            log_warn "Unknown package manager, skipping system package installation"
            log_warn "Please manually install: python3, python3-pip, git, redis"
            ;;
    esac
}

create_app_directory() {
    log_info "Creating application directory..."
    
    mkdir -p "${APP_DIR}"
    mkdir -p "${APP_DIR}/backups"
    
    # Set ownership using configured service user
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
}

install_coldfront() {
    log_info "Creating Python virtual environment..."
    
    sudo -u "${SERVICE_USER}" python3 -m venv "${VENV_DIR}"
    
    log_info "Upgrading pip..."
    sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install --upgrade pip
    
    log_info "Installing ColdFront: ${COLDFRONT_VERSION}..."
    sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install "${COLDFRONT_VERSION}"
    sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install gunicorn mozilla-django-oidc pyjwt requests
    
    log_info "Installing ORCD Direct Charge plugin: ${PLUGIN_VERSION} from ${PLUGIN_REPO}..."
    sudo -u "${SERVICE_USER}" "${VENV_DIR}/bin/pip" install "git+${PLUGIN_REPO}@${PLUGIN_VERSION}"
    
    log_info "Installation complete"
    log_info "  ColdFront: ${COLDFRONT_VERSION}"
    log_info "  ORCD Plugin: ${PLUGIN_VERSION}"
}

copy_config_files() {
    log_info "Copying configuration files..."
    
    if [[ ! -d "${CONFIG_DIR}" ]]; then
        log_error "Config directory not found: ${CONFIG_DIR}"
        log_error "Make sure you're running from the deployment package directory"
        exit 1
    fi
    
    # Copy auth backend
    cp "${CONFIG_DIR}/coldfront_auth.py" "${APP_DIR}/"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/coldfront_auth.py"
    
    # Copy WSGI
    cp "${CONFIG_DIR}/wsgi.py" "${APP_DIR}/"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/wsgi.py"
    
    # Copy custom URLs (adds OIDC routes)
    cp "${CONFIG_DIR}/urls.py" "${APP_DIR}/"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/urls.py"
    
    # Copy systemd service
    cp "${CONFIG_DIR}/systemd/coldfront.service" /etc/systemd/system/
    
    log_info "Configuration files copied"
    log_info "Note: local_settings.py and coldfront.env must be created using configure-secrets.sh"
}

setup_nginx_permissions() {
    log_info "Setting up Nginx permissions..."
    
    # Add nginx to service user group to access socket
    if id nginx &>/dev/null; then
        usermod -a -G "${SERVICE_USER}" nginx
    elif id www-data &>/dev/null; then
        usermod -a -G "${SERVICE_USER}" www-data
    fi
    
    # Set directory permissions
    chmod 710 "${APP_DIR}"
}

reload_systemd() {
    log_info "Reloading systemd..."
    systemctl daemon-reload
}

install_security_tools() {
    log_info "Installing security tools..."
    
    case "${PKG_MANAGER}" in
        dnf)
            dnf install -y fail2ban rkhunter
            ;;
        apt)
            apt-get install -y fail2ban rkhunter
            ;;
        *)
            log_warn "Skipping security tools installation"
            return
            ;;
    esac
    
    # Copy fail2ban filters
    if [[ -d "${CONFIG_DIR}/fail2ban/filter.d" ]]; then
        cp "${CONFIG_DIR}/fail2ban/filter.d/"*.conf /etc/fail2ban/filter.d/
        log_info "Copied fail2ban filters"
    fi
    
    # Copy fail2ban jails
    if [[ -d "${CONFIG_DIR}/fail2ban/jail.d" ]]; then
        cp "${CONFIG_DIR}/fail2ban/jail.d/"*.local /etc/fail2ban/jail.d/
        log_info "Copied fail2ban jails"
    fi
    
    # Enable fail2ban
    systemctl enable --now fail2ban
    
    # Copy rkhunter local config
    if [[ -f "${CONFIG_DIR}/rkhunter/rkhunter.conf.local" ]]; then
        mkdir -p /etc/rkhunter.conf.d
        cp "${CONFIG_DIR}/rkhunter/rkhunter.conf.local" /etc/rkhunter.conf.d/
        log_info "Copied rkhunter config"
    fi
    
    # Create rkhunter log directory
    mkdir -p /var/log/rkhunter
    
    # Install daily cron job
    if [[ -f "${CONFIG_DIR}/rkhunter/rkhunter-daily.sh" ]]; then
        cp "${CONFIG_DIR}/rkhunter/rkhunter-daily.sh" /etc/cron.daily/rkhunter-daily
        chmod +x /etc/cron.daily/rkhunter-daily
        log_info "Installed rkhunter daily cron job"
    fi
    
    # Initialize rkhunter database
    log_info "Initializing rkhunter database..."
    rkhunter --propupd
    
    log_info "Security tools installed (fail2ban, rkhunter)"
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "=============================================="
    echo " ORCD Rental Portal - ColdFront Installation"
    echo "=============================================="
    echo ""
    
    check_root
    detect_distro
    check_nginx_running
    load_deployment_config
    
    log_info "Starting installation..."
    
    install_system_packages
    create_app_directory
    install_coldfront
    copy_config_files
    setup_nginx_permissions
    install_security_tools
    reload_systemd
    
    echo ""
    echo "=============================================="
    echo " ColdFront Installation Complete!"
    echo "=============================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Configure secrets (run as ${SERVICE_USER}):"
    echo "   cd ${SCRIPT_DIR}"
    echo "   ./configure-secrets.sh"
    echo ""
    echo "2. Deploy ColdFront Nginx app config (run as root):"
    echo "   sudo ./scripts/install_nginx_app.sh --domain YOUR_DOMAIN"
    echo ""
    echo "3. Initialize database (as ${SERVICE_USER}):"
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
    echo "4. Fix permissions:"
    echo "   sudo chown ${SERVICE_USER}:${SERVICE_USER} ${APP_DIR}/coldfront.db"
    echo "   sudo chmod 664 ${APP_DIR}/coldfront.db"
    echo "   sudo chmod -R 755 ${APP_DIR}/static"
    echo ""
    echo "5. Start ColdFront service:"
    echo "   sudo systemctl enable coldfront"
    echo "   sudo systemctl start coldfront"
    echo ""
    echo "For detailed instructions, see docs/admin-guide.md"
}

main "$@"
