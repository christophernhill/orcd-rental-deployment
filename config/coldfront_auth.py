# =============================================================================
# ORCD Rental Portal - Custom Globus OIDC Authentication Backend
# =============================================================================
#
# This custom backend is REQUIRED because Globus Auth has a quirk:
# - Globus signs ID tokens with RS512 algorithm
# - But their JWKS metadata (jwk.json) claims the key uses RS256
# - Standard OIDC libraries (like mozilla-django-oidc) reject this mismatch
#
# This backend overrides the key retrieval to force acceptance of the key
# despite the algorithm mismatch.
#
# Copy this file to /srv/coldfront/coldfront_auth.py
#
# =============================================================================

import datetime
import logging
import requests
import jwt

from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

# Try to load ColdFront UserProfile model
# (may fail during initial setup when DB isn't ready)
try:
    from coldfront.core.user.models import UserProfile
except ImportError:
    UserProfile = None

logger = logging.getLogger(__name__)


def debug_log(message):
    """
    Write debug messages to a dedicated log file.
    
    This bypasses Django's logging complexity during auth debugging.
    Useful for troubleshooting OIDC issues in production.
    """
    try:
        with open("/srv/coldfront/oidc_debug.log", "a") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except IOError:
        # Fail silently if we can't write to the log
        pass


class GlobusOIDCBackend(OIDCAuthenticationBackend):
    """
    Custom OIDC authentication backend for Globus Auth.
    
    Handles the RS512/RS256 algorithm mismatch in Globus's JWKS.
    """
    
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
            debug_log(f"CRITICAL: Failed to fetch JWKS: {e}")
            raise SuspiciousOperation("Could not fetch JWKS from identity provider")
        except ValueError as e:
            debug_log(f"CRITICAL: Invalid JWKS JSON: {e}")
            raise SuspiciousOperation("Invalid JWKS response from identity provider")

        keys = jwks.get('keys', [])
        if not keys:
            debug_log("CRITICAL: JWKS has no keys")
            raise SuspiciousOperation("JWKS contains no keys")

        # Decode token header to get key ID
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get('kid')
            alg = header.get('alg')
        except jwt.exceptions.DecodeError as e:
            debug_log(f"CRITICAL: Could not decode token header: {e}")
            raise SuspiciousOperation("Could not decode ID token header")

        debug_log(f"Token header - KID: {kid}, Algorithm: {alg}")

        # Try to find matching key by 'kid'
        for key in keys:
            key_id = key.get('kid')
            key_alg = key.get('alg')
            
            if kid and key_id == kid:
                debug_log(f"Found matching key by KID: {key_id} (key claims {key_alg})")
                # FORCE RETURN - ignore algorithm mismatch
                return key

        # Fallback: if only one key, use it regardless
        if len(keys) == 1:
            debug_log(f"Using single available key (no KID match)")
            return keys[0]

        # Fallback: try to match by algorithm
        for key in keys:
            if key.get('alg') == alg:
                debug_log(f"Using key matched by algorithm: {alg}")
                return key

        debug_log(f"CRITICAL: No matching key found. Token KID: {kid}, Available keys: {[k.get('kid') for k in keys]}")
        raise SuspiciousOperation("Could not find matching JWKS key for ID token")

    def create_user(self, claims):
        """
        Create a new Django user from OIDC claims.
        
        Also creates the ColdFront UserProfile if the model is available.
        """
        email = claims.get('email', '')
        username = claims.get('preferred_username', email)
        
        debug_log(f"Creating new user: {username} ({email})")
        
        try:
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
            
            debug_log(f"Django user created: ID={user.id}, username={user.username}")
            
            # Create ColdFront UserProfile
            if UserProfile is not None:
                profile, created = UserProfile.objects.get_or_create(user=user)
                debug_log(f"UserProfile {'created' if created else 'already exists'}")
            
            return user
            
        except Exception as e:
            debug_log(f"CRITICAL: Failed to create user: {e}")
            # Re-raise to let Django handle the error
            raise

    def update_user(self, user, claims):
        """
        Update existing user from OIDC claims.
        
        Called on subsequent logins to sync user data.
        """
        debug_log(f"Updating user: {user.username}")
        
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
        
        Tries to match by email, then by preferred_username.
        """
        email = claims.get('email')
        preferred_username = claims.get('preferred_username')
        
        if email:
            users = self.UserModel.objects.filter(email=email)
            if users.exists():
                debug_log(f"Found user by email: {email}")
                return users
        
        if preferred_username:
            users = self.UserModel.objects.filter(username=preferred_username)
            if users.exists():
                debug_log(f"Found user by username: {preferred_username}")
                return users
        
        debug_log(f"No existing user found for claims: email={email}, preferred_username={preferred_username}")
        return self.UserModel.objects.none()

