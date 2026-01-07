#!/bin/bash
# =============================================================================
# ORCD Rental Portal - Automated Installation Script
# =============================================================================
#
# This script automates the installation of ColdFront with the ORCD Direct
# Charge plugin on Amazon Linux 2023.
#
# Usage:
#   chmod +x install.sh
#   sudo ./install.sh
#
# Prerequisites:
#   - Amazon Linux 2023 EC2 instance
#   - Root/sudo access
#   - Internet connectivity
#
# After running this script, you still need to:
#   1. Run configure-secrets.sh to set up credentials
#   2. Run database migrations
#   3. Create superuser
#   4. Obtain SSL certificate
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
CONFIG_DIR="$(dirname "$0")/../config"

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

check_amazon_linux() {
    if ! grep -q "Amazon Linux 2023" /etc/os-release 2>/dev/null; then
        log_warn "This script is designed for Amazon Linux 2023"
        log_warn "Other distributions may require modifications"
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
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
# Installation Steps
# =============================================================================

install_system_packages() {
    log_info "Updating system packages..."
    dnf update -y

    log_info "Installing required packages..."
    dnf install -y python3 python3-devel python3-pip git nginx redis6

    log_info "Installing development tools..."
    dnf groupinstall -y "Development Tools"

    log_info "Enabling and starting Redis..."
    systemctl enable --now redis6

    log_info "Enabling Nginx..."
    systemctl enable nginx
}

install_certbot() {
    log_info "Installing Certbot..."
    
    if [[ ! -d /opt/certbot ]]; then
        python3 -m venv /opt/certbot/
    fi
    
    /opt/certbot/bin/pip install --upgrade pip
    /opt/certbot/bin/pip install certbot certbot-nginx
    
    if [[ ! -L /usr/bin/certbot ]]; then
        ln -s /opt/certbot/bin/certbot /usr/bin/certbot
    fi
}

configure_firewall() {
    log_info "Checking firewall configuration..."
    
    # Amazon Linux 2023 on EC2 typically uses AWS Security Groups
    # instead of firewalld. Only configure if firewalld is available.
    if command -v firewall-cmd &> /dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null || systemctl start firewalld 2>/dev/null; then
            log_info "Configuring firewalld..."
            systemctl enable firewalld
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            firewall-cmd --reload
        else
            log_warn "firewalld is installed but couldn't be started"
            log_warn "Ensure AWS Security Groups allow HTTP (80) and HTTPS (443)"
        fi
    else
        log_warn "firewalld not installed (this is normal for Amazon Linux 2023 on EC2)"
        log_warn "Firewall is managed via AWS Security Groups"
        log_warn "Ensure your Security Group allows inbound traffic on ports 80 and 443"
    fi
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
    
    # Resolve absolute path to config directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CONFIG_DIR="${SCRIPT_DIR}/../config"
    
    if [[ ! -d "${CONFIG_DIR}" ]]; then
        log_error "Config directory not found: ${CONFIG_DIR}"
        log_error "Make sure you're running from the deployment package directory"
        exit 1
    fi
    
    # Copy auth backend
    cp "${CONFIG_DIR}/coldfront_auth.py" "${APP_DIR}/"
    chown ec2-user:ec2-user "${APP_DIR}/coldfront_auth.py"
    
    # Copy WSGI
    cp "${CONFIG_DIR}/wsgi.py" "${APP_DIR}/"
    chown ec2-user:ec2-user "${APP_DIR}/wsgi.py"
    
    # Copy custom URLs (adds OIDC routes)
    cp "${CONFIG_DIR}/urls.py" "${APP_DIR}/"
    chown ec2-user:ec2-user "${APP_DIR}/urls.py"
    
    # Copy systemd service
    cp "${CONFIG_DIR}/systemd/coldfront.service" /etc/systemd/system/
    
    log_info "Configuration files copied"
    log_info "Note: local_settings.py and coldfront.env must be created using configure-secrets.sh"
}

setup_nginx_permissions() {
    log_info "Setting up Nginx permissions..."
    
    # Add nginx to service user group to access socket
    usermod -a -G "${SERVICE_USER}" "${SERVICE_GROUP}"
    
    # Set directory permissions
    chmod 710 "${APP_DIR}"
}

reload_systemd() {
    log_info "Reloading systemd..."
    systemctl daemon-reload
}

install_security_tools() {
    log_info "Installing security tools..."
    
    # Resolve absolute path to config directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    CONFIG_DIR="${SCRIPT_DIR}/../config"
    
    # Install fail2ban
    log_info "Installing fail2ban..."
    dnf install -y fail2ban
    
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
    
    # Install rkhunter
    log_info "Installing rkhunter..."
    dnf install -y rkhunter
    
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
    echo " ORCD Rental Portal Installation"
    echo "=============================================="
    echo ""
    
    check_root
    check_amazon_linux
    load_deployment_config
    
    log_info "Starting installation..."
    
    install_system_packages
    install_certbot
    configure_firewall
    create_app_directory
    install_coldfront
    copy_config_files
    setup_nginx_permissions
    install_security_tools
    reload_systemd
    
    echo ""
    echo "=============================================="
    echo " Installation Complete!"
    echo "=============================================="
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Configure secrets (run as ec2-user):"
    echo "   cd $(dirname "$0")"
    echo "   ./configure-secrets.sh"
    echo ""
    echo "2. Set up Nginx (replace DOMAIN with your domain):"
    echo "   sudo cp ../config/nginx/coldfront-http.conf.template /etc/nginx/conf.d/coldfront.conf"
    echo "   sudo sed -i 's/{{DOMAIN_NAME}}/YOUR_DOMAIN/g' /etc/nginx/conf.d/coldfront.conf"
    echo ""
    echo "3. Obtain SSL certificate (certbot will add HTTPS automatically):"
    echo "   sudo certbot --nginx -d YOUR_DOMAIN"
    echo ""
    echo "4. Initialize database (as ec2-user):"
    echo "   cd ${APP_DIR}"
    echo "   source venv/bin/activate"
    echo "   export DJANGO_SETTINGS_MODULE=local_settings"
    echo "   export PLUGIN_API=True AUTO_PI_ENABLE=True AUTO_DEFAULT_PROJECT_ENABLE=True"
    echo "   coldfront migrate"
    echo "   coldfront collectstatic --noinput"
    echo "   coldfront createsuperuser"
    echo ""
    echo "5. Fix permissions:"
    echo "   sudo chown ec2-user:ec2-user ${APP_DIR}/coldfront.db"
    echo "   sudo chmod 664 ${APP_DIR}/coldfront.db"
    echo "   sudo chmod -R 755 ${APP_DIR}/static"
    echo ""
    echo "6. Start services:"
    echo "   sudo systemctl start coldfront"
    echo "   sudo systemctl restart nginx"
    echo ""
    echo "For detailed instructions, see docs/admin-guide.md"
}

main "$@"

