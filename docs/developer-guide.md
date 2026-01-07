# ORCD Rental Portal - Developer Guide

This guide covers the architecture, local development setup, and customization options for the ORCD Rental Portal.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Local Development Setup](#2-local-development-setup)
3. [Plugin Structure](#3-plugin-structure)
4. [Key Models](#4-key-models)
5. [Authentication Flow](#5-authentication-flow)
6. [Template Overrides](#6-template-overrides)
7. [Signal Handlers](#7-signal-handlers)
8. [REST API](#8-rest-api)
9. [Customization](#9-customization)
10. [Contributing](#10-contributing)

---

## 1. Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ORCD Rental Portal                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────┐    ┌───────────────────────────────────────┐  │
│  │   ColdFront      │    │   ORCD Direct Charge Plugin           │  │
│  │   Core v1.1.7    │◄───┤   (coldfront_orcd_direct_charge)      │  │
│  │                  │    │                                        │  │
│  │  - Projects      │    │  - NodeType, NodeInstance models      │  │
│  │  - Allocations   │    │  - Reservations & billing             │  │
│  │  - Users         │    │  - Cost allocation workflow           │  │
│  │  - Resources     │    │  - Template overrides                 │  │
│  └────────┬─────────┘    └───────────────────────────────────────┘  │
│           │                                                          │
│           ▼                                                          │
│  ┌──────────────────┐                                               │
│  │ Globus OIDC      │──► MIT Okta (via CILogon)                    │
│  │ Authentication   │                                               │
│  └──────────────────┘                                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|-------|------------|
| Framework | Django 4.2.x |
| Database | SQLite (dev) / PostgreSQL (optional prod) |
| Task Queue | Redis + Django Q |
| Web Server | Gunicorn + Nginx |
| Authentication | Globus OIDC via mozilla-django-oidc |
| API | Django REST Framework |
| Frontend | Bootstrap 4, jQuery, DataTables, Flatpickr |

### Repository Structure

```
cf-orcd-rental/                          # Plugin repository
├── coldfront_orcd_direct_charge/
│   ├── __init__.py
│   ├── admin.py                         # Django admin customizations
│   ├── apps.py                          # App config, startup, template injection
│   ├── forms.py                         # Form classes
│   ├── models.py                        # All data models
│   ├── signals.py                       # Signal handlers (auto-config, logging)
│   ├── urls.py                          # URL routes
│   ├── views.py                         # View classes
│   ├── api/                             # REST API
│   │   ├── __init__.py
│   │   ├── serializers.py
│   │   ├── urls.py
│   │   └── views.py
│   ├── fixtures/                        # Initial data
│   │   ├── node_types.json
│   │   ├── gpu_node_instances.json
│   │   └── cpu_node_instances.json
│   ├── management/commands/             # Management commands
│   │   ├── setup_rental_manager.py
│   │   └── setup_billing_manager.py
│   ├── migrations/                      # Database migrations
│   ├── templates/                       # Template overrides
│   │   ├── common/
│   │   ├── portal/
│   │   ├── project/
│   │   ├── user/
│   │   └── coldfront_orcd_direct_charge/
│   └── templatetags/                    # Custom template tags
│       └── project_roles.py
├── pyproject.toml
└── README.md
```

---

## 2. Local Development Setup

### 2.1 Prerequisites

- Python 3.9+
- Git
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### 2.2 Clone Repositories

```bash
mkdir ~/coldfront-dev && cd ~/coldfront-dev

# Clone ColdFront core
git clone https://github.com/coldfront/coldfront.git
cd coldfront
git checkout v1.1.7  # or latest stable

# Clone ORCD plugin
cd ..
git clone https://github.com/christophernhill/cf-orcd-rental.git
```

### 2.3 Set Up Virtual Environment

Using uv (recommended):
```bash
cd coldfront
uv venv
source .venv/bin/activate
uv pip install -e .[dev]
uv pip install -e ../cf-orcd-rental
uv pip install mozilla-django-oidc
```

Using pip:
```bash
cd coldfront
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pip install -e ../cf-orcd-rental
pip install mozilla-django-oidc
```

### 2.4 Create Development Settings

Create `coldfront/local_settings.py`:

```python
from coldfront.config.settings import *

DEBUG = True
SECRET_KEY = 'dev-secret-key-not-for-production'

# Use SQLite for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'coldfront.db',
    }
}

# Session cookies for OAuth redirects (localhost)
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = False

# For local OIDC testing (optional - see oauth-testing setup)
# AUTHENTICATION_BACKENDS = [
#     'globus_oidc_backend.GlobusOIDCAuthenticationBackend',
#     'django.contrib.auth.backends.ModelBackend',
# ]
```

### 2.5 Initialize Database

```bash
export PLUGIN_API=True
export AUTO_PI_ENABLE=True
export AUTO_DEFAULT_PROJECT_ENABLE=True

# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load fixtures (optional)
python manage.py loaddata node_types
python manage.py loaddata gpu_node_instances
python manage.py loaddata cpu_node_instances
```

### 2.6 Run Development Server

```bash
DEBUG=True python manage.py runserver
```

Visit http://localhost:8000

### 2.7 Quick Start Script

Create a helper script `run_dev.sh`:

```bash
#!/bin/bash
cd ~/coldfront-dev/coldfront
source .venv/bin/activate
export PLUGIN_API=True
export AUTO_PI_ENABLE=True
export AUTO_DEFAULT_PROJECT_ENABLE=True
DEBUG=True python manage.py runserver
```

---

## 3. Plugin Structure

### 3.1 App Configuration (`apps.py`)

The plugin uses Django's app configuration to:

1. **Inject templates** at runtime (override ColdFront templates)
2. **Set default settings** for plugin features
3. **Run startup code** for auto-configuration

Key configuration options:

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `PLUGIN_API` | `False` | Enable REST API endpoints |
| `AUTO_PI_ENABLE` | `False` | Make all users PIs automatically |
| `AUTO_DEFAULT_PROJECT_ENABLE` | `False` | Create personal/group projects for users |

### 3.2 URL Routing

Plugin URLs are registered via ColdFront's plugin system. Main routes:

| URL Pattern | View | Description |
|-------------|------|-------------|
| `/` | `HomeView` | Dashboard (replaces ColdFront home) |
| `/nodes/` | `NodeInstanceListView` | Node listing |
| `/nodes/renting/` | `RentalCalendarView` | Rental calendar |
| `/nodes/renting/request/` | `ReservationRequestView` | Submit reservation |
| `/nodes/renting/manage/` | `RentalManagerView` | Manager dashboard |
| `/nodes/my/reservations/` | `MyReservationsView` | User's reservations |
| `/nodes/billing/pending/` | `PendingCostAllocationsView` | Billing manager view |
| `/nodes/billing/invoice/` | `InvoiceListView` | Invoice reports |
| `/nodes/activity-log/` | `ActivityLogView` | Activity audit log |

---

## 4. Key Models

### 4.1 Node Models

```python
class NodeType(models.Model):
    """Defines GPU/CPU node configurations (H200x8, L40Sx4, etc.)"""
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    gpu_count = models.PositiveIntegerField(default=0)
    cpu_cores = models.PositiveIntegerField(default=0)
    memory_gb = models.PositiveIntegerField(default=0)
    hourly_rate = models.DecimalField(max_digits=10, decimal_places=2)

class GpuNodeInstance(models.Model):
    """Individual GPU node instances"""
    node_type = models.ForeignKey(NodeType, on_delete=models.PROTECT)
    node_label = models.CharField(max_length=50, unique=True)
    is_rentable = models.BooleanField(default=False)

class CpuNodeInstance(models.Model):
    """Individual CPU node instances"""
    node_type = models.ForeignKey(NodeType, on_delete=models.PROTECT)
    node_label = models.CharField(max_length=50, unique=True)
```

### 4.2 Reservation Model

```python
class Reservation(models.Model):
    class StatusChoices(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        APPROVED = 'APPROVED', 'Confirmed'  # Display: "Confirmed"
        DECLINED = 'DECLINED', 'Declined'
        CANCELLED = 'CANCELLED', 'Cancelled'

    node_instance = models.ForeignKey(GpuNodeInstance, on_delete=models.PROTECT)
    project = models.ForeignKey('project.Project', on_delete=models.PROTECT)
    requester = models.ForeignKey(User, on_delete=models.PROTECT)
    status = models.CharField(max_length=20, choices=StatusChoices.choices)
    start_date = models.DateField()
    duration_blocks = models.PositiveIntegerField()  # 12-hour blocks
    rental_notes = models.TextField(blank=True)
    processed_by = models.ForeignKey(User, null=True, related_name='processed_reservations')
```

**Time Rules:**
- Start: Always 4:00 PM on start date
- Duration: 12-hour blocks (1-14)
- End cap: 9:00 AM maximum
- Advance booking: 7 days minimum, 3 months maximum

### 4.3 Cost Allocation Models

```python
class ProjectCostAllocation(models.Model):
    """Cost allocation status for a project"""
    project = models.OneToOneField('project.Project', on_delete=models.CASCADE)
    status = models.CharField(max_length=20)  # pending, approved, rejected
    approved_by = models.ForeignKey(User, null=True)
    approved_date = models.DateTimeField(null=True)

class ProjectCostObject(models.Model):
    """Individual cost objects with percentage allocations"""
    cost_allocation = models.ForeignKey(ProjectCostAllocation, on_delete=models.CASCADE)
    cost_object = models.CharField(max_length=100)  # e.g., "WBS-12345"
    percentage = models.DecimalField(max_digits=5, decimal_places=2)

class ProjectMemberRole(models.Model):
    """ORCD-specific roles for project members"""
    class RoleChoices(models.TextChoices):
        OWNER = 'owner', 'Owner'
        FINANCIAL_ADMIN = 'financial_admin', 'Financial Admin'
        TECHNICAL_ADMIN = 'technical_admin', 'Technical Admin'
        MEMBER = 'member', 'Member'

    project = models.ForeignKey('project.Project', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=RoleChoices.choices)
```

### 4.4 User Maintenance Status

```python
class UserMaintenanceStatus(models.Model):
    """Per-user maintenance fee status"""
    class StatusChoices(models.TextChoices):
        INACTIVE = 'inactive', 'Inactive'
        BASIC = 'basic', 'Basic'
        ADVANCED = 'advanced', 'Advanced'

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=StatusChoices.choices)
    billing_project = models.ForeignKey('project.Project', null=True)
```

### 4.5 Activity Log

```python
class ActivityLog(models.Model):
    """Audit log for all site activity"""
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    category = models.CharField(max_length=50)  # auth, reservation, member, etc.
    action = models.CharField(max_length=100)
    description = models.TextField()
    extra_data = models.JSONField(null=True)  # Additional context
```

---

## 5. Authentication Flow

### 5.1 Globus OIDC Flow

```
User clicks Login
       │
       ▼
┌─────────────────────┐
│ Django OIDC View    │──► Redirect to Globus Auth
└─────────────────────┘    (with MIT IdP hint)
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │ Globus Auth             │
                    │ (shows CILogon consent) │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │ MIT Okta                │
                    │ (user authenticates)    │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │ Callback to Django      │
                    │ /oidc/callback/         │
                    └───────────┬─────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────┐
│ GlobusOIDCBackend.authenticate()            │
│  1. Exchange code for tokens                │
│  2. Verify ID token (RS512 fix applied)     │
│  3. Fetch userinfo from Globus              │
│  4. Create/update Django user               │
│  5. Create UserProfile if needed            │
└─────────────────────────────────────────────┘
```

### 5.2 Custom Backend (RS512 Fix)

Globus signs tokens with RS512 but their JWKS metadata claims RS256. The custom backend overrides `retrieve_matching_jwk` to handle this:

```python
class GlobusOIDCBackend(OIDCAuthenticationBackend):
    def retrieve_matching_jwk(self, token):
        """Force accept key despite algorithm mismatch"""
        jwks = requests.get(settings.OIDC_OP_JWKS_ENDPOINT).json()
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        
        for key in jwks['keys']:
            if not kid or key.get('kid') == kid:
                return key  # Force return, ignore alg mismatch
        
        raise SuspiciousOperation("No matching key found")
```

### 5.3 MIT Identity Provider Enforcement

```python
# In settings
MIT_IDP_ID = "67af3d07-a5ff-4445-8404-80ec541411f9"
OIDC_AUTH_REQUEST_EXTRA_PARAMS = {
    'session_required_single_domain': 'mit.edu',
    'identity_provider': MIT_IDP_ID,
}
```

---

## 6. Template Overrides

### 6.1 How Template Injection Works

The plugin's `apps.py` inserts its template directory at the front of Django's template search path:

```python
def ready(self):
    # Inject plugin templates before core ColdFront templates
    plugin_templates = os.path.join(os.path.dirname(__file__), 'templates')
    settings.TEMPLATES[0]['DIRS'].insert(0, plugin_templates)
```

### 6.2 Key Template Overrides

| Template | Override Purpose |
|----------|------------------|
| `common/base.html` | ORCD favicon, title |
| `common/authorized_navbar.html` | Dashboard link, Manage Rentals |
| `portal/authorized_home.html` | Dashboard with cards |
| `project/project_detail.html` | Simplified, reservations button |
| `project/project_list.html` | Accounts/Billing columns |
| `user/user_profile.html` | Maintenance status, API token |

### 6.3 Creating New Template Overrides

To override a ColdFront template:

1. Copy the original from `coldfront/templates/`
2. Place in `coldfront_orcd_direct_charge/templates/` with same path
3. Modify as needed

Example:
```
coldfront/templates/project/project_detail.html  (original)
coldfront_orcd_direct_charge/templates/project/project_detail.html  (override)
```

---

## 7. Signal Handlers

### 7.1 Auto-Configuration Signals

```python
# signals.py

@receiver(post_save, sender=User)
def auto_configure_user(sender, instance, created, **kwargs):
    """Auto-configure new users as PIs with default projects"""
    if created and settings.AUTO_PI_ENABLE:
        instance.userprofile.is_pi = True
        instance.userprofile.save()
        
    if created and settings.AUTO_DEFAULT_PROJECT_ENABLE:
        create_personal_project(instance)
        create_group_project(instance)

@receiver(post_save, sender=Project)
def auto_activate_project(sender, instance, created, **kwargs):
    """Auto-activate new projects (skip approval workflow)"""
    if created and instance.status.name == 'New':
        active_status = ProjectStatusChoice.objects.get(name='Active')
        instance.status = active_status
        instance.save()
```

### 7.2 Activity Logging Signals

```python
@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ActivityLog.objects.create(
        user=user,
        category='auth',
        action='login',
        description=f"User {user.username} logged in"
    )

@receiver(post_save, sender=Reservation)
def log_reservation_change(sender, instance, created, **kwargs):
    action = 'created' if created else 'updated'
    ActivityLog.objects.create(
        user=instance.requester,
        category='reservation',
        action=action,
        description=f"Reservation {instance.id} {action}"
    )
```

---

## 8. REST API

### 8.1 Authentication

API uses token authentication. Users get their token from their profile page.

```bash
curl -H "Authorization: Token YOUR_API_TOKEN" \
     https://rental.your-org.org/nodes/api/rentals/
```

### 8.2 Endpoints

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/nodes/api/rentals/` | GET | Rental Manager | List all rentals |
| `/nodes/api/rentals/<id>/` | GET | Rental Manager | Rental detail |
| `/nodes/api/rentals/<id>/approve/` | POST | Rental Manager | Approve rental |
| `/nodes/api/rentals/<id>/decline/` | POST | Rental Manager | Decline rental |
| `/nodes/api/invoice/` | GET | Billing Manager | List invoice periods |
| `/nodes/api/invoice/YYYY/MM/` | GET | Billing Manager | Invoice detail |
| `/nodes/api/activity-log/` | GET | Manager/Admin | Activity log |

### 8.3 API Response Format

```json
{
    "id": 42,
    "node_instance": "gpu-h200-01",
    "project": "jsmith_personal",
    "requester": "jsmith",
    "status": "APPROVED",
    "start_date": "2025-01-15",
    "duration_blocks": 4,
    "billable_hours": 48,
    "created_at": "2025-01-08T14:30:00Z"
}
```

---

## 9. Customization

### 9.1 Adding New Node Types

Via fixtures:
```json
{
    "model": "coldfront_orcd_direct_charge.nodetype",
    "pk": 5,
    "fields": {
        "name": "A100x4",
        "description": "4x NVIDIA A100 80GB",
        "gpu_count": 4,
        "cpu_cores": 64,
        "memory_gb": 512,
        "hourly_rate": "15.00"
    }
}
```

Or via Django admin at `/admin/coldfront_orcd_direct_charge/nodetype/`

### 9.2 Customizing Reservation Rules

Edit `views.py` `ReservationRequestView`:

```python
# Minimum advance booking (days)
MIN_ADVANCE_DAYS = 7

# Maximum advance booking (months)
MAX_ADVANCE_MONTHS = 3

# Start time
RESERVATION_START_HOUR = 16  # 4 PM

# Block duration (hours)
BLOCK_DURATION_HOURS = 12
```

### 9.3 Adding Custom Template Tags

Create in `templatetags/`:

```python
# templatetags/custom_tags.py
from django import template

register = template.Library()

@register.filter
def my_custom_filter(value):
    return value.upper()
```

Use in templates:
```html
{% load custom_tags %}
{{ some_value|my_custom_filter }}
```

### 9.4 Extending Models

Create a new migration after modifying `models.py`:

```bash
export PLUGIN_API=True
python manage.py makemigrations coldfront_orcd_direct_charge
python manage.py migrate
```

---

## 10. Contributing

### 10.1 Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes with tests
4. Run tests: `python manage.py test coldfront_orcd_direct_charge`
5. Commit with descriptive message
6. Push and create Pull Request

### 10.2 Code Style

- Follow PEP 8
- Use meaningful variable/function names
- Add docstrings to classes and public methods
- Keep functions focused and small

### 10.3 Commit Message Format

```
Short summary (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain the problem this commit solves and why this approach
was chosen.

- Bullet points are okay
- Use present tense: "Add feature" not "Added feature"
```

### 10.4 Testing

```bash
# Run all plugin tests
python manage.py test coldfront_orcd_direct_charge

# Run specific test
python manage.py test coldfront_orcd_direct_charge.tests.test_views

# With coverage
coverage run manage.py test coldfront_orcd_direct_charge
coverage report
```

### 10.5 Release Practices

The ORCD Direct Charge plugin uses git tags to signal releases to downstream deployments.

#### Version Numbering

Use semantic versioning: `vMAJOR.MINOR.PATCH`

| Version Bump | When to Use | Example |
|--------------|-------------|---------|
| MAJOR | Breaking changes, DB migrations requiring manual steps | v1.0 → v2.0 |
| MINOR | New features, backward-compatible changes | v0.1 → v0.2 |
| PATCH | Bug fixes, small improvements | v0.1 → v0.1.1 |

#### Creating a New Release

```bash
# In the plugin repository (cf-orcd-rental / coldfront-orcd-direct-charge)
cd /Users/cnh/projects/cnh_uv_coldfront/coldfront-orcd-direct-charge

# 1. Ensure all changes are committed
git status

# 2. View existing tags
git tag -l

# 3. Create annotated tag with release notes
git tag -a v0.2 -m "Release v0.2 - December 2025

New features:
- Rental Manager dashboard with DataTables sorting/filtering
- Reservation detail page with ID links
- Project reservations page
- Subscription check for reservation requests
- Date range validation matching calendar rules

UI improvements:
- Terminology: Approved → Confirmed for reservations
- Dashboard subscription alert for inactive users
- Cost Object(s) Set/Not Set labels

Bug fixes:
- iOS Safari date picker compatibility
- Project creation with hidden Field of Science"

# 4. Push tag to GitHub
git push origin v0.2
```

#### Deployment Configuration

The deployment repository (`orcd-rental-deployment`) uses `config/deployment.conf` to specify which plugin version to install by default.

When releasing a new plugin version that should become the default for new installations:

1. Update `config/deployment.conf`:
   ```bash
   PLUGIN_VERSION="v0.2"  # Change from v0.1
   ```

2. Document the change in deployment repository's commit message:
   ```
   Update default plugin version to v0.2
   
   This version includes:
   - [List key features from plugin release]
   
   Existing deployments can upgrade by [future: running upgrade.sh]
   or manually updating their deployment.conf and reinstalling.
   ```

3. Existing deployments can adopt new version by:
   - Editing their local `deployment.conf`
   - [Future: running `upgrade.sh`]
   - Or manually: `pip install --upgrade git+...@v0.2`

#### Signaling to Downstream Deployments

After creating a new tag:

1. **Update deployment repository** (`orcd-rental-deployment`):
   - Edit `config/deployment.conf` to update default `PLUGIN_VERSION`
   - Update documentation if needed

2. **Notify administrators** to upgrade:
   ```bash
   # On production server
   cd /srv/coldfront
   source venv/bin/activate
   pip install --upgrade git+https://github.com/christophernhill/cf-orcd-rental.git@v0.2
   export PLUGIN_API=True DJANGO_SETTINGS_MODULE=local_settings
   coldfront migrate
   coldfront collectstatic --noinput
   sudo systemctl restart coldfront
   ```

3. **Document changes** in `developer_docs/CHANGELOG.md`

#### Viewing Tags Locally

```bash
# List all tags
git tag -l

# Show tag details
git show v0.1

# Fetch tags from remote
git fetch --tags
```

---

## Appendix: Common Development Tasks

### Run Django Shell
```bash
export PLUGIN_API=True
python manage.py shell
```

### Create New Migration
```bash
export PLUGIN_API=True
python manage.py makemigrations coldfront_orcd_direct_charge -n descriptive_name
```

### Reset Database (Development Only)
```bash
rm coldfront.db
python manage.py migrate
python manage.py createsuperuser
python manage.py loaddata node_types gpu_node_instances cpu_node_instances
```

### Check for Issues
```bash
export PLUGIN_API=True
python manage.py check
python manage.py check --deploy  # Production checks
```

