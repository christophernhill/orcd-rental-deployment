# =============================================================================
# ORCD Rental Portal - WSGI Entry Point
# =============================================================================
#
# This file is the entry point for Gunicorn to serve the Django application.
#
# It handles some Amazon Linux specific quirks:
# - Adds lib64 site-packages to path (Amazon Linux uses lib64)
# - Ensures local_settings is used instead of default settings
#
# Copy this file to /srv/coldfront/wsgi.py
#
# =============================================================================

import os
import sys
import site

# =============================================================================
# Path Configuration for Amazon Linux 2023
# =============================================================================

# Add Amazon Linux specific site-packages directory
# (Amazon Linux uses lib64 instead of lib for some packages)
VENV_PATH = '/srv/coldfront/venv'
PYTHON_VERSION = 'python3.9'  # Update if using different Python version

# Try both lib and lib64 paths
for lib_dir in ['lib64', 'lib']:
    site_packages = os.path.join(VENV_PATH, lib_dir, PYTHON_VERSION, 'site-packages')
    if os.path.exists(site_packages):
        site.addsitedir(site_packages)

# Add the application directory to the path
APP_PATH = '/srv/coldfront'
if APP_PATH not in sys.path:
    sys.path.insert(0, APP_PATH)

# =============================================================================
# Django WSGI Application
# =============================================================================

# Force use of our local_settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'local_settings')

# Import must happen after path and environment setup
from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()

