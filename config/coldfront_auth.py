# =============================================================================
# ORCD Rental Portal - Custom Globus OIDC Authentication Backend
# =============================================================================
#
# This custom backend is REQUIRED because Globus Auth has a quirk:
# - Globus signs ID tokens with RS512 algorithm
# - But their JWKS metadata (jwk.json) claims the key uses RS256
# - Standard OIDC libraries (like mozilla-django-oidc) reject this mismatch
#
# Additionally, this backend:
# - Validates that users authenticate via MIT IdP
# - Extracts EPPN from MIT identity claims
# - Uses EPPN stem (before @) as the Django username
#
# Copy this file to /srv/coldfront/coldfront_auth.py
#
# =============================================================================

import datetime
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
    
    Features:
    - Handles the RS512/RS256 algorithm mismatch in Globus's JWKS
    - Validates MIT IdP identity in claims
    - Uses EPPN stem as username (e.g., "cnh" from "cnh@mit.edu")
    """
    
    def extract_mit_eppn(self, claims):
        """
        Extract EPPN from MIT identity in identity_set.
        
        The identity_set contains all linked identities. We look for
        one with a username ending in @mit.edu (the MIT EPPN).
        
        Args:
            claims: The userinfo claims from Globus
            
        Returns:
            The MIT EPPN (e.g., "cnh@mit.edu") or None if not found
        """
        eppn = None
        identity_set = claims.get('identity_set', [])
        
        debug_log(f"Searching for MIT EPPN in {len(identity_set)} identities")
        
        for identity in identity_set:
            username = identity.get('username', '')
            if username.endswith('@mit.edu'):
                eppn = username
                debug_log(f"Found MIT EPPN: {eppn}")
                break
        
        # Fallback to preferred_username if no MIT identity found
        if not eppn:
            eppn = claims.get('preferred_username', claims.get('username'))
            debug_log(f"No MIT identity in identity_set, falling back to: {eppn}")
        
        return eppn
    
    def validate_mit_identity(self, claims):
        """
        Verify user has authenticated via MIT IdP.
        
        Checks that identity_set contains at least one @mit.edu identity.
        
        Args:
            claims: The userinfo claims from Globus
            
        Returns:
            True if MIT identity found, False otherwise
        """
        identity_set = claims.get('identity_set', [])
        
        for identity in identity_set:
            username = identity.get('username', '')
            if username.endswith('@mit.edu'):
                debug_log(f"MIT identity validated: {username}")
                return True
        
        debug_log("WARNING: No MIT identity found in identity_set")
        return False
    
    def get_username_from_eppn(self, eppn):
        """
        Extract username stem from EPPN.
        
        Args:
            eppn: The EPPN (e.g., "cnh@mit.edu")
            
        Returns:
            The username stem (e.g., "cnh")
        """
        if eppn and '@' in eppn:
            return eppn.split('@')[0]
        return eppn
    
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
        
        Uses MIT EPPN to generate username:
        - Extracts EPPN from identity_set (e.g., "cnh@mit.edu")
        - Uses stem as username (e.g., "cnh")
        
        Also creates the ColdFront UserProfile if the model is available.
        """
        # Validate MIT identity
        if not self.validate_mit_identity(claims):
            debug_log("CRITICAL: Rejecting user - no MIT identity")
            raise PermissionDenied("Authentication requires MIT credentials")
        
        # Extract EPPN and derive username
        eppn = self.extract_mit_eppn(claims)
        if not eppn or '@' not in eppn:
            debug_log(f"CRITICAL: Invalid EPPN: {eppn}")
            raise SuspiciousOperation("No valid MIT EPPN found in claims")
        
        username = self.get_username_from_eppn(eppn)
        email = claims.get('email', eppn)
        
        debug_log(f"Creating new user: username={username}, email={email}, eppn={eppn}")
        
        try:
            # Create Django user with EPPN-derived username
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
        
        # Validate MIT identity on every login
        if not self.validate_mit_identity(claims):
            debug_log(f"CRITICAL: Rejecting update - no MIT identity for {user.username}")
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
        Find existing users that match the OIDC claims.
        
        First tries to match by EPPN-derived username, then falls back
        to email matching.
        """
        # Validate MIT identity
        if not self.validate_mit_identity(claims):
            debug_log("No MIT identity found - rejecting user lookup")
            return self.UserModel.objects.none()
        
        # Try to find user by EPPN-derived username
        eppn = self.extract_mit_eppn(claims)
        if eppn and '@' in eppn:
            username = self.get_username_from_eppn(eppn)
            users = self.UserModel.objects.filter(username=username)
            if users.exists():
                debug_log(f"Found user by EPPN-derived username: {username}")
                return users
        
        # Fallback: try email match
        email = claims.get('email')
        if email:
            users = self.UserModel.objects.filter(email=email)
            if users.exists():
                debug_log(f"Found user by email: {email}")
                return users
        
        debug_log(f"No existing user found for EPPN={eppn}, email={email}")
        return self.UserModel.objects.none()
