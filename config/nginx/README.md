# Nginx Configuration Templates

## Files

- **coldfront-http.conf.template** - Initial HTTP-only configuration (use this first)
- **coldfront-https.conf.reference** - Reference showing final HTTPS configuration

## Usage

### Initial Setup (Before SSL Certificates)

Use the HTTP-only template for initial setup. Certbot will automatically add HTTPS configuration.

1. Copy HTTP template:
   ```bash
   sudo cp coldfront-http.conf.template /etc/nginx/conf.d/coldfront.conf
   sudo sed -i 's/{{DOMAIN_NAME}}/your-domain.org/g' /etc/nginx/conf.d/coldfront.conf
   ```

2. Test and restart nginx:
   ```bash
   sudo nginx -t
   sudo systemctl restart nginx
   ```

3. Obtain SSL certificate (certbot will modify the config automatically):
   ```bash
   sudo certbot --nginx -d your-domain.org
   ```

## What Certbot Does

Certbot automatically:
- Obtains SSL certificates from Let's Encrypt
- Modifies your nginx config to add HTTPS settings
- Sets up HTTP→HTTPS redirect
- Configures automatic renewal

You don't need to manually create HTTPS configuration!

## Common Mistakes

❌ **DON'T** manually copy `coldfront-https.conf.reference` for initial setup
- This will fail because SSL certificates don't exist yet

✅ **DO** use `coldfront-http.conf.template` and let certbot handle HTTPS
- This is the correct and easiest approach

## Manual HTTPS Configuration

If you absolutely need manual SSL setup (not recommended), see `coldfront-https.conf.reference` for the expected final configuration. However, you'll need to:
1. Obtain certificates manually first
2. Update all certificate paths
3. Handle renewal yourself

The automated certbot approach is strongly recommended.

## Troubleshooting

### Error: "nginx: [emerg] cannot load certificate"

**Cause:** You tried to use HTTPS configuration before certificates exist.

**Solution:** Remove the config and start with HTTP-only template:
```bash
sudo rm /etc/nginx/conf.d/coldfront.conf
sudo cp coldfront-http.conf.template /etc/nginx/conf.d/coldfront.conf
sudo sed -i 's/{{DOMAIN_NAME}}/your-domain.org/g' /etc/nginx/conf.d/coldfront.conf
sudo nginx -t && sudo systemctl restart nginx
sudo certbot --nginx -d your-domain.org
```

### Deprecation Warning: "listen ... http2" directive

This is a warning from newer nginx versions. Certbot may generate config with deprecated syntax. The site will still work fine. To fix the warning after certbot runs, you can manually update the config to use the newer `http2 on;` directive format.

