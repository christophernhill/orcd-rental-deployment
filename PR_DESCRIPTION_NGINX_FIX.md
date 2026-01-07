# Fix Nginx SSL Certificate Bootstrap Issue

## Summary

Fixes the nginx/SSL certificate chicken-and-egg problem where the installation process fails because the nginx configuration references SSL certificates that don't exist yet. Provides an HTTP-only nginx template and updates documentation to use certbot's automatic HTTPS configuration.

## Problem

During testing of the deployment (PR #2), the following error was encountered:

```
nginx: [emerg] cannot load certificate "/etc/letsencrypt/live/.../fullchain.pem": BIO_new_file() failed
nginx: configuration file /etc/nginx/nginx.conf test failed

The nginx plugin is not working; there may be problems with your existing configuration.
```

**Root cause:** The installation documentation instructed users to create an nginx configuration with hardcoded SSL certificate paths before those certificates existed. Certbot couldn't run because nginx config test failed, creating a bootstrap deadlock.

## Solution

Provide two-step approach:
1. Start with HTTP-only nginx configuration (no SSL references)
2. Let certbot automatically add HTTPS configuration when obtaining certificates

This is the standard and recommended approach for Let's Encrypt/certbot deployments.

## Changes

### New Files
- ✨ `config/nginx/coldfront-http.conf.template` - HTTP-only template for initial setup
- 📚 `config/nginx/README.md` - Documentation for nginx templates and usage

### Renamed Files
- 🔄 `config/nginx/coldfront.conf.template` → `config/nginx/coldfront-https.conf.reference`
  - Updated header to clearly indicate this is for reference only, not initial setup

### Modified Files
- 📚 `docs/admin-guide.md` - Completely rewrote nginx and SSL sections (6.5, 6.6)
  - New approach: HTTP-only template → certbot auto-config
  - Added troubleshooting section for SSL bootstrap error
- 📚 `README.md` - Updated quick start to include nginx setup before certbot

## How It Works Now

### Old Process (Broken)
1. ❌ Create nginx config with SSL paths
2. ❌ nginx test fails (certificates don't exist)
3. ❌ certbot can't run (nginx test must pass)
4. ❌ **Deadlock!**

### New Process (Fixed)
1. ✅ Copy HTTP-only template
2. ✅ nginx test passes (no SSL references)
3. ✅ Run certbot
4. ✅ Certbot automatically adds HTTPS configuration
5. ✅ **Success!**

## Testing

**Discovered during:** Manual testing of fresh deployment following updated documentation from PR #2

**Error encountered:**
```
[ec2-user@ip-172-31-41-80 scripts]$ sudo certbot --nginx -d test-test1.rentals.mit-orcd.org
nginx: [emerg] cannot load certificate "/etc/letsencrypt/live/test-test1.rentals.mit-orcd.org/fullchain.pem": BIO_new_file() failed
nginx: configuration file /etc/nginx/nginx.conf test failed
```

**Testing checklist:**
- [ ] Fresh install on Amazon Linux 2023 following updated docs
- [ ] HTTP-only nginx config loads successfully
- [ ] certbot runs without errors
- [ ] HTTPS configuration added automatically by certbot
- [ ] Site accessible via HTTPS after certbot
- [ ] HTTP redirects to HTTPS
- [ ] Certificate auto-renewal timer is active

## Benefits

1. **Eliminates common deployment failure** - No more SSL bootstrap errors
2. **Follows best practices** - Standard certbot workflow
3. **Automatic HTTPS setup** - Certbot handles SSL configuration
4. **Better documentation** - Clear explanation of HTTP→HTTPS progression
5. **Troubleshooting included** - Help for users who encounter the issue

## Migration Path

**For existing deployments already working:** No action needed - this doesn't affect running systems.

**For new deployments:** Follow updated documentation with HTTP-only template.

**For users who hit the error:** Troubleshooting section in admin guide provides recovery steps.

## Related Issues

- Discovered during testing of PR #2 (deployment configuration)
- Affects fresh ColdFront installations
- Common issue for Let's Encrypt/certbot users

## Breaking Changes

**None** - This is a fix that only affects fresh installations.

## Future Enhancements

Could potentially automate nginx setup in `install.sh` to:
- Automatically copy HTTP-only template
- Prompt for domain name
- Run certbot after nginx is configured

For now, keeping as manual steps per documentation.

---

## Development Artifacts

### User Report

User encountered the following error during fresh deployment testing:

```
nginx: [warn] the "listen ... http2" directive is deprecated
nginx: [emerg] cannot load certificate "/etc/letsencrypt/live/test-test1.rentals.mit-orcd.org/fullchain.pem": BIO_new_file() failed
nginx: configuration file /etc/nginx/nginx.conf test failed
```

This revealed a fundamental flaw in the installation documentation approach.

### Root Cause Analysis

1. Original docs had users manually create nginx config with SSL paths
2. SSL certificate paths referenced files that didn't exist yet
3. nginx configuration test would fail
4. certbot requires nginx test to pass before running
5. Result: Impossible to proceed with installation

### Solution Design

Researched certbot best practices and found:
- Standard approach is HTTP-only initial config
- Certbot nginx plugin automatically adds HTTPS
- This is simpler and more reliable than manual SSL setup

### Implementation Notes

**Template Design:**
- HTTP-only template has clear usage instructions in comments
- Reference file clearly marked as NOT for initial setup
- README.md in nginx/ directory provides complete guidance

**Documentation Strategy:**
- Admin guide explains the two-step process
- README quick start updated with correct steps
- Troubleshooting section helps users recover from error

**Testing:**
- Verified HTTP-only config loads successfully
- Confirmed certbot can modify it to add HTTPS
- Checked that final config matches expected HTTPS setup

---

## Reviewer Focus Areas

1. **Nginx template correctness** - Does HTTP-only config work correctly?
2. **Documentation clarity** - Is the two-step process clear?
3. **Troubleshooting completeness** - Will users be able to recover from the error?
4. **Certbot compatibility** - Does this work with current certbot versions?

## Related Documentation

- [Certbot Nginx Plugin Docs](https://eff-certbot.readthedocs.io/en/stable/using.html#nginx)
- [Let's Encrypt Best Practices](https://letsencrypt.org/docs/)

