# =============================================================================
# ORCD Rental Portal - Custom URL Configuration
# =============================================================================
#
# This file extends ColdFront's URL patterns to add OIDC and ORCD plugin URLs.
#
# Copy this file to /srv/coldfront/urls.py
#
# =============================================================================

from coldfront.config.urls import urlpatterns
from django.urls import path, include

# Add OIDC authentication URLs
# These provide:
#   /oidc/authenticate/ - Initiates OIDC login flow
#   /oidc/callback/     - Handles callback from OIDC provider
#   /oidc/logout/       - OIDC logout
urlpatterns += [
    path('oidc/', include('mozilla_django_oidc.urls')),
]

# Add ORCD Direct Charge plugin URLs
# These provide the rental portal, node management, billing, etc.
urlpatterns += [
    path('', include('coldfront_orcd_direct_charge.urls')),
]

# Add django-su URLs (admin user switching)
# This is used by ColdFront templates for the admin impersonation feature
try:
    import django_su
    urlpatterns += [
        path('su/', include('django_su.urls')),
    ]
except ImportError:
    pass  # django-su not installed

