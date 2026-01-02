# Secrets Directory

This directory is for storing sensitive configuration files that should **NEVER** be committed to version control.

## Required Secret Files

After running `scripts/configure-secrets.sh`, the following files will be created here:

### `local_settings.py`
Django settings file with your actual credentials:
- `SECRET_KEY` - Django secret key
- `OIDC_RP_CLIENT_ID` - Globus OAuth client ID
- `OIDC_RP_CLIENT_SECRET` - Globus OAuth client secret
- `ALLOWED_HOSTS` - Your domain name

### `coldfront.env`
Environment variables for systemd service:
- `DEBUG` - Set to False for production
- `SECRET_KEY` - Same as in local_settings.py
- Globus OAuth credentials

## Security Checklist

- [ ] All files in this directory are listed in `.gitignore`
- [ ] File permissions are restricted: `chmod 600 secrets/*`
- [ ] Secrets are not echoed in scripts or logs
- [ ] Backup secrets securely (not in git)
- [ ] Rotate secrets periodically

## Obtaining Credentials

### Globus OAuth Client
1. Go to https://developers.globus.org/
2. Register a new application
3. Set redirect URI to: `https://YOUR_DOMAIN/oidc/callback/`
4. Enable MIT as required identity provider
5. Copy Client ID and generate a Client Secret

### Django Secret Key
Generate with:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(50))"
```

## Recovery

If secrets are lost:
1. Generate new Django SECRET_KEY (existing sessions will be invalidated)
2. Generate new Globus client secret at developers.globus.org
3. Re-run `scripts/configure-secrets.sh`
4. Restart ColdFront service

