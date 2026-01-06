# Add Deployment Configuration System

## Summary

Introduces `deployment.conf` to centralize configuration for plugin installation, including repository URL, version/tag, ColdFront version, and installation paths. This provides a foundation for version management and future upgrade automation.

## Motivation

**Problem:** Plugin version and repository were hardcoded in install.sh, making it difficult to:
- Track which version is deployed
- Install specific versions
- Prepare for future upgrade automation
- Customize installation paths consistently

**Solution:** Centralized configuration file that is:
- Version controlled
- Self-documenting
- Easy to modify
- Foundation for future upgrade script

## Changes

### New Files
- ✨ `config/deployment.conf` - Live deployment configuration
- 📝 `config/deployment.conf.template` - Configuration template with docs

### Modified Files
- 🔧 `scripts/install.sh` - Load and use deployment.conf
- 📚 `README.md` - Document configuration system
- 📚 `docs/admin-guide.md` - Update installation instructions
- 📚 `docs/developer-guide.md` - Update release workflow

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `PLUGIN_REPO` | Plugin repository URL | `https://github.com/christophernhill/cf-orcd-rental.git` |
| `PLUGIN_VERSION` | Git tag or branch | `v0.1` |
| `COLDFRONT_VERSION` | ColdFront package spec | `coldfront[common]` |
| `APP_DIR` | Installation directory | `/srv/coldfront` |
| `VENV_DIR` | Virtual environment path | `/srv/coldfront/venv` |
| `SERVICE_USER` | Service account | `ec2-user` |
| `SERVICE_GROUP` | Web server group | `nginx` |

## Testing Checklist

- [ ] Fresh installation with default deployment.conf works
- [ ] Installation with custom PLUGIN_VERSION works
- [ ] Validation catches missing deployment.conf
- [ ] Validation catches missing required variables
- [ ] Documentation is accurate and complete
- [ ] install.sh displays configuration during installation

## Future Enhancements

This PR lays groundwork for:
- **Upgrade script** - Read target version from deployment.conf
- **Version detection** - Compare installed vs configured version
- **Multi-environment** - Different configs for dev/staging/prod
- **Backup integration** - Configuration-aware backup paths

---

## Development Artifacts

### Initial User Request

<details>
<summary>Click to expand original prompt</summary>

```
Can you make a plan to use a feature branch and a PR with this repo to make a change as follows.

Guide and scripts should be changed to allow 

1. installation of a specific tag from https://github.com/christophernhill/cf-orcd-rental 

2. add instructions for upgrading to use a different tag in an existing deployment. 

In the making the plan consider how you would show any migrations that might be needed as part of a tag upgrade.
```

</details>

### Clarification Prompts

<details>
<summary>Click to expand clarification questions and answers</summary>

**Q1: Implementation Approach**
- How should the plugin tag/version be specified during installation?
- How should the upgrade process be implemented?
- How should migration information be displayed during upgrades?

**A1:** Use configuration file (deployment.conf) to specify repo and tag, support multiple methods with fallback order, create both upgrade script and documentation, show migrations interactively with confirmation.

**Q2: PR Documentation**
- Request to store prompts, plans, and debugging notes in PR

**A2:** Create comprehensive PR_DESCRIPTION.md with all development artifacts

**Q3: Backup Modularity**
- Request to make backup functionality modular for potential separation

**A3:** Design backup.sh as standalone utility that can be sourced

**Q4: Plan Scope**
- Request to split into smaller focused plans

**A4:** Focus this PR on deployment.conf and installation only; defer backup and upgrade to future PRs

**Q5: PR Creation Method**
- Can we use gh CLI to automate PR creation?

**A5:** Yes, use `gh pr create --body-file PR_DESCRIPTION.md` for full automation

</details>

### Development Plan

<details>
<summary>Click to expand complete development plan</summary>

# Tag-Based Plugin Installation Configuration

## Overview

This plan focuses on two main goals:

1. **Create deployment.conf** - Centralize configuration for plugin repository, version/tag, and installation settings
2. **Feature Branch & PR with Development Artifacts** - Create a well-documented PR that includes all prompts, plans, and decision-making context

**Out of scope** (for future plans):
- Backup utility (backup.sh)
- Upgrade script (upgrade.sh)
- Migration display functionality

## Implementation Details

### 1. Create Configuration File System

Create `config/deployment.conf` with centralized settings for plugin repository, version, ColdFront version, installation paths, and service configuration.

**Benefits:**
- **Version control** - Track which plugin version is deployed
- **Consistency** - Single source of truth for installation parameters
- **Easy upgrades** - Change version in one place (foundation for future upgrade script)
- **Documentation** - Self-documenting configuration file

### 2. Create Configuration Template

Create `config/deployment.conf.template` with same content plus additional comments explaining how to choose versions, when to pin, and customization options.

### 3. Update Installation Script

Modify `scripts/install.sh` to:
- Add `load_deployment_config()` function that sources and validates deployment.conf
- Update `main()` to call load_deployment_config()
- Update `install_coldfront()` to use configuration variables
- Update `create_app_directory()` to use SERVICE_USER
- Update other references to use variables from deployment.conf

### 4. Update Documentation

#### README.md
- Add Configuration section explaining deployment.conf
- Update Components section to mention version configuration

#### docs/admin-guide.md
- Add section 4.1 about reviewing deployment configuration
- Update installation section to reference configuration

#### docs/developer-guide.md
- Add Deployment Configuration subsection to Release Practices
- Document how to update default version for new installations

### 5. Feature Branch Workflow

Create feature branch following git best practices with clear, conventional commit messages.

### 6. PR Documentation with Development Artifacts

Create PR_DESCRIPTION.md containing:
- Summary and motivation
- Changes and configuration options
- Testing checklist and future enhancements
- Complete development artifacts (prompts, plans, implementation notes)

### 7. Create the Pull Request (Automated with GitHub CLI)

Use `gh pr create` command to automatically create PR with PR_DESCRIPTION.md as body, applying labels and setting branch references.

</details>

### Implementation Notes

<details>
<summary>Click to expand implementation decisions and notes</summary>

**Configuration File Design:**
- Chose bash script format for easy sourcing by install.sh
- Validation function ensures all required variables present
- Comments provide inline documentation
- Template file helps new deployments

**install.sh Modifications:**
- Added load_deployment_config() function for clean separation
- Validation happens early (fail fast principle)
- Configuration displayed during installation for transparency
- Maintains backward compatibility principles (though config is required)

**Documentation Strategy:**
- README: High-level overview of configuration
- Admin Guide: Detailed installation/configuration steps
- Developer Guide: Release and version management workflow
- All docs link to plugin repository tags for version discovery

**Version Control:**
- deployment.conf IS committed (not in .gitignore)
- Represents the default/recommended version for new installations
- Local deployments can modify their copy
- Template preserved for reference

**Git Workflow:**
- Feature branch: feature/deployment-config
- Conventional commits with clear, descriptive messages
- Separate commits for: config files, install.sh, documentation, PR description

**Automated PR Creation:**
- Used GitHub CLI (`gh`) for automated PR creation
- PR description from file ensures complete development history
- Labels applied automatically (enhancement, documentation)

</details>

### Testing Performed

<details>
<summary>Click to expand testing details</summary>

[To be filled in during implementation]

**Manual Testing:**
- [ ] Fresh install on clean Amazon Linux 2023 instance
- [ ] Install with custom plugin version (v0.2)
- [ ] Validation with missing deployment.conf
- [ ] Validation with incomplete deployment.conf
- [ ] Documentation walkthrough accuracy

**Edge Cases:**
- [ ] Non-existent git tag handling
- [ ] Invalid repository URL handling
- [ ] Permission issues with SERVICE_USER

</details>

---

## Reviewer Focus Areas

1. **Configuration completeness** - Are all necessary settings captured?
2. **Error handling** - Is validation comprehensive and helpful?
3. **Documentation clarity** - Can admins follow the new process?
4. **Future compatibility** - Does this support planned upgrade script?
5. **Security** - Any concerns with sourcing deployment.conf?

## Breaking Changes

**None** - This is a new feature. Existing installations continue to work, though new installations require deployment.conf.

## Migration Path

For existing deployments: No action needed. This PR only affects fresh installations.

## Related Issues

[If applicable, link to GitHub issues]

## License

Consistent with repository license (same as ColdFront - AGPLv3)

