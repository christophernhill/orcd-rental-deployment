# =============================================================================
# ORCD Rental Portal - OIDC Authentication Backends
# =============================================================================
#
# This module provides two OIDC authentication backends:
#
# 1. GlobusOIDCBackend - For Globus Auth (handles RS512/RS256 algorithm mismatch)
# 2. GenericOIDCBackend - For standard OIDC providers (Okta, Keycloak, Azure AD, etc.)
#
# Both backends:
# - Extract username from email (e.g., "cnh@mit.edu" -> "cnh")
# - Create ColdFront UserProfile on first login
# - Support standard OIDC claims (email, given_name, family_name)
#
# Choose the appropriate backend in your local_settings.py:
#
#   # For Globus Auth:
#   AUTHENTICATION_BACKENDS = [
#       'coldfront_auth.GlobusOIDCBackend',
#       'django.contrib.auth.backends.ModelBackend',
#   ]
#
#   # For Generic OIDC (Okta, etc.):
#   AUTHENTICATION_BACKENDS = [
#       'coldfront_auth.GenericOIDCBackend',
#       'django.contrib.auth.backends.ModelBackend',
#   ]
#
# Copy this file to /srv/coldfront/coldfront_auth.py
#
# =============================================================================

import logging
import requests
import jwt

from django.conf import settings
from django.core.exceptions import SuspiciousOperation, PermissionDenied
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

# Try to load ColdFront UserProfile model
# (may fail during initial setup when DB isn't ready)
try:
    from coldfront.core.user.models import UserProfile
except ImportError:
    UserProfile = None

logger = logging.getLogger(__name__)


# =============================================================================
# Base Backend - Shared functionality
# =============================================================================

class BaseOIDCBackend(OIDCAuthenticationBackend):
    """
    Base OIDC backend with shared functionality for all providers.
    
    Features:
    - Uses email stem as username (e.g., "cnh" from "cnh@mit.edu")
    - Creates ColdFront UserProfile on first login
    - Handles standard OIDC claims
    """
    
    def get_username_from_email(self, email):
        """
        Extract username stem from email address.
        
        Args:
            email: The email address (e.g., "cnh@mit.edu")
            
        Returns:
            The username stem (e.g., "cnh")
        """
        if email and '@' in email:
            return email.split('@')[0]
        return email
    
    def create_user(self, claims):
        """
        Create a new Django user from OIDC claims.
        
        Uses email to generate username:
        - Extracts email from claims (e.g., "cnh@mit.edu")
        - Uses stem as username (e.g., "cnh")
        
        Also creates the ColdFront UserProfile if the model is available.
        """
        email = claims.get('email', '')
        if not email:
            logger.error("No email claim found in OIDC response")
            raise ValueError("Email claim is required for user creation")
        
        username = self.get_username_from_email(email)
        
        logger.info(f"Creating new user: username={username}, email={email}")
        
        # Create Django user with email-derived username
        user = self.UserModel.objects.create_user(
            username=username,
            email=email
        )
        
        # Set name from claims
        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')
        
        # Fallback: try to parse from 'name' claim if no given/family name
        if not user.first_name and claims.get('name'):
            name_parts = claims['name'].split(' ', 1)
            user.first_name = name_parts[0]
            if len(name_parts) > 1:
                user.last_name = name_parts[1]
        
        user.is_active = True
        user.save()
        
        logger.info(f"Django user created: ID={user.id}, username={user.username}")
        
        # Create ColdFront UserProfile
        if UserProfile is not None:
            profile, created = UserProfile.objects.get_or_create(user=user)
            logger.debug(f"UserProfile {'created' if created else 'already exists'}")
        
        return user

    def update_user(self, user, claims):
        """
        Update existing user from OIDC claims.
        
        Called on subsequent logins to sync user data.
        """
        logger.debug(f"Updating user: {user.username}")
        
        # Ensure user is active
        if not user.is_active:
            user.is_active = True
            user.save()
        
        # Ensure UserProfile exists
        if UserProfile is not None:
            UserProfile.objects.get_or_create(user=user)
        
        return user

    def filter_users_by_claims(self, claims):
        """
        Find existing users that match the OIDC claims.
        
        First tries to match by email-derived username, then falls back
        to email matching.
        """
        email = claims.get('email')
        
        if email:
            # Try to find user by email-derived username
            username = self.get_username_from_email(email)
            users = self.UserModel.objects.filter(username=username)
            if users.exists():
                logger.debug(f"Found user by email-derived username: {username}")
                return users
            
            # Fallback: try email match
            users = self.UserModel.objects.filter(email=email)
            if users.exists():
                logger.debug(f"Found user by email: {email}")
                return users
        
        logger.debug(f"No existing user found for email={email}")
        return self.UserModel.objects.none()


# =============================================================================
# Generic OIDC Backend - For standard providers (Okta, Keycloak, Azure AD, etc.)
# =============================================================================

class GenericOIDCBackend(BaseOIDCBackend):
    """
    Standard OIDC authentication backend for generic providers.
    
    Use this backend for:
    - Okta (including MIT Okta at okta.mit.edu)
    - Keycloak
    - Azure AD
    - Any standard OIDC-compliant provider
    
    Features:
    - Standard RS256 token signing
    - PKCE support (enable with OIDC_USE_PKCE = True)
    - Standard OIDC claims
    
    No special workarounds needed - uses mozilla-django-oidc defaults.
    """
    pass  # All functionality inherited from BaseOIDCBackend


# =============================================================================
# Globus OIDC Backend - Handles Globus-specific quirks
# =============================================================================

class GlobusOIDCBackend(BaseOIDCBackend):
    """
    Custom OIDC authentication backend for Globus Auth.
    
    Use this backend when authenticating via Globus Auth (auth.globus.org).
    
    Globus Auth has a specific quirk:
    - Globus signs ID tokens with RS512 algorithm
    - But their JWKS metadata (jwk.json) claims the key uses RS256
    - Standard OIDC libraries (like mozilla-django-oidc) reject this mismatch
    
    This backend overrides retrieve_matching_jwk() to handle this mismatch.
    
    Additionally, this backend can:
    - Validate that users authenticate via a specific IdP (e.g., MIT)
    - Extract EPPN from Globus identity_set claims
    """
    
    def extract_mit_eppn(self, claims):
        """
        Extract EPPN from MIT identity in identity_set (Globus-specific).
        
        The identity_set contains all linked identities. We look for
        one with a username ending in @mit.edu (the MIT EPPN).
        
        Args:
            claims: The userinfo claims from Globus
            
        Returns:
            The MIT EPPN (e.g., "cnh@mit.edu") or None if not found
        """
        eppn = None
        identity_set = claims.get('identity_set', [])
        
        logger.debug(f"Searching for MIT EPPN in {len(identity_set)} identities")
        
        for identity in identity_set:
            username = identity.get('username', '')
            if username.endswith('@mit.edu'):
                eppn = username
                logger.debug(f"Found MIT EPPN: {eppn}")
                break
        
        # Fallback to preferred_username if no MIT identity found
        if not eppn:
            eppn = claims.get('preferred_username', claims.get('email'))
            logger.debug(f"No MIT identity in identity_set, falling back to: {eppn}")
        
        return eppn
    
    def validate_mit_identity(self, claims):
        """
        Verify user has authenticated via MIT IdP (optional enforcement).
        
        Checks that identity_set contains at least one @mit.edu identity.
        Only enforced if MIT_IDP_REQUIRED setting is True.
        
        Args:
            claims: The userinfo claims from Globus
            
        Returns:
            True if MIT identity found or not required, False otherwise
        """
        # Check if MIT identity validation is required
        if not getattr(settings, 'MIT_IDP_REQUIRED', False):
            return True
            
        identity_set = claims.get('identity_set', [])
        
        for identity in identity_set:
            username = identity.get('username', '')
            if username.endswith('@mit.edu'):
                logger.debug(f"MIT identity validated: {username}")
                return True
        
        logger.warning("No MIT identity found in identity_set")
        return False
    
    def retrieve_matching_jwk(self, token):
        """
        Override to force acceptance of JWKS key despite algorithm mismatch.
        
        Standard behavior:
            1. Fetch JWKS from Globus
            2. Match key by 'kid' (Key ID) from token header
            3. Verify algorithm matches
            
        Our override:
            - Skip algorithm verification (Globus claims RS256 but uses RS512)
            - Return the key if 'kid' matches (or first key if no match)
        """
        try:
            jwks_url = settings.OIDC_OP_JWKS_ENDPOINT
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            jwks = response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise SuspiciousOperation("Could not fetch JWKS from identity provider")
        except ValueError as e:
            logger.error(f"Invalid JWKS JSON: {e}")
            raise SuspiciousOperation("Invalid JWKS response from identity provider")

        keys = jwks.get('keys', [])
        if not keys:
            logger.error("JWKS has no keys")
            raise SuspiciousOperation("JWKS contains no keys")

        # Decode token header to get key ID
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            alg = header.get('alg')
        except jwt.exceptions.DecodeError as e:
            logger.error(f"Could not decode token header: {e}")
            raise SuspiciousOperation("Could not decode ID token header")

        logger.debug(f"Token header - KID: {kid}, Algorithm: {alg}")

        # Try to find matching key by 'kid'
        for key in keys:
            key_id = key.get('kid')
            key_alg = key.get('alg')
            
            if kid and key_id == kid:
                logger.debug(f"Found matching key by KID: {key_id} (key claims {key_alg})")
                # FORCE RETURN - ignore algorithm mismatch
                return key

        # Fallback: if only one key, use it regardless
        if len(keys) == 1:
            logger.debug("Using single available key (no KID match)")
            return keys[0]

        # Fallback: try to match by algorithm
        for key in keys:
            if key.get('alg') == alg:
                logger.debug(f"Using key matched by algorithm: {alg}")
                return key

        logger.error(f"No matching key found. Token KID: {kid}, Available keys: {[k.get('kid') for k in keys]}")
        raise SuspiciousOperation("Could not find matching JWKS key for ID token")

    def create_user(self, claims):
        """
        Create a new Django user from Globus OIDC claims.
        
        Uses MIT EPPN from identity_set to generate username if available,
        otherwise falls back to email.
        """
        # Validate MIT identity if required
        if not self.validate_mit_identity(claims):
            raise PermissionDenied("Authentication requires MIT credentials")
        
        # Try to get EPPN from Globus identity_set
        eppn = self.extract_mit_eppn(claims)
        email = claims.get('email', eppn)
        
        if eppn and '@' in eppn:
            username = self.get_username_from_email(eppn)
        elif email:
            username = self.get_username_from_email(email)
        else:
            logger.error("No valid email or EPPN found in claims")
            raise SuspiciousOperation("No valid identifier found in claims")
        
        logger.info(f"Creating new user: username={username}, email={email}")
        
        # Create Django user
        user = self.UserModel.objects.create_user(
            username=username,
            email=email
        )
        
        # Set name from claims
        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')
        
        # If no given/family name, try to parse from 'name' claim
        if not user.first_name and claims.get('name'):
            name_parts = claims['name'].split(' ', 1)
            user.first_name = name_parts[0]
            if len(name_parts) > 1:
                user.last_name = name_parts[1]
        
        user.is_active = True
        user.save()
        
        logger.info(f"Django user created: ID={user.id}, username={user.username}")
        
        # Create ColdFront UserProfile
        if UserProfile is not None:
            profile, created = UserProfile.objects.get_or_create(user=user)
            logger.debug(f"UserProfile {'created' if created else 'already exists'}")
        
        return user

    def update_user(self, user, claims):
        """
        Update existing user from Globus OIDC claims.
        
        Called on subsequent logins to sync user data.
        """
        logger.debug(f"Updating user: {user.username}")
        
        # Validate MIT identity if required
        if not self.validate_mit_identity(claims):
            raise PermissionDenied("Authentication requires MIT credentials")
        
        # Ensure user is active
        if not user.is_active:
            user.is_active = True
            user.save()
        
        # Ensure UserProfile exists
        if UserProfile is not None:
            UserProfile.objects.get_or_create(user=user)
        
        return user

    def filter_users_by_claims(self, claims):
        """
        Find existing users that match the Globus OIDC claims.
        
        First tries to match by EPPN-derived username, then falls back
        to email matching.
        """
        # Validate MIT identity if required
        if not self.validate_mit_identity(claims):
            logger.debug("No MIT identity found - rejecting user lookup")
            return self.UserModel.objects.none()
        
        # Try to find user by EPPN-derived username
        eppn = self.extract_mit_eppn(claims)
        if eppn and '@' in eppn:
            username = self.get_username_from_email(eppn)
            users = self.UserModel.objects.filter(username=username)
            if users.exists():
                logger.debug(f"Found user by EPPN-derived username: {username}")
                return users
        
        # Fallback: try email match
        email = claims.get('email')
        if email:
            users = self.UserModel.objects.filter(email=email)
            if users.exists():
                logger.debug(f"Found user by email: {email}")
                return users
        
        logger.debug(f"No existing user found for EPPN={eppn}, email={email}")
        return self.UserModel.objects.none()
