# ORCD Rental Portal - User Guide

Welcome to the ORCD Rental Portal! This guide will help you navigate the portal, manage your projects, and make reservations for compute resources.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Dashboard Overview](#2-dashboard-overview)
3. [Managing Your Account](#3-managing-your-account)
4. [Projects](#4-projects)
5. [Making Reservations](#5-making-reservations)
6. [Cost Allocations (Billing)](#6-cost-allocations-billing)
7. [For Financial Admins](#7-for-financial-admins)
8. [For Technical Admins](#8-for-technical-admins)
9. [FAQ](#9-faq)

---

## 1. Getting Started

### 1.1 Logging In

1. Navigate to the portal URL (e.g., `https://rental.your-org.org`)
2. Click **Login**
3. You'll be redirected to authenticate with your institutional credentials
4. After successful authentication, you'll return to the portal dashboard

### 1.2 First-Time Users

When you log in for the first time, the system automatically:
- Creates your user account
- Sets you up as a Principal Investigator (PI)
- Creates two projects for you:
  - **username_personal**: Your personal project for individual reservations
  - **username_group**: A project for collaborating with others

### 1.3 Understanding Your Account Status

Your account has a **Maintenance Subscription Status** that determines what you can do:

| Status | Description | Capabilities |
|--------|-------------|--------------|
| **Inactive** | No active subscription | View-only access, cannot make reservations |
| **Basic** | Basic maintenance subscription | Can make reservations |
| **Advanced** | Advanced maintenance subscription | Can make reservations |

---

## 2. Dashboard Overview

The dashboard is your home page after logging in. It displays four main cards:

### My Rentals
Shows your upcoming, pending, and past reservations:
- **Upcoming**: Confirmed reservations that haven't started yet
- **Pending**: Reservations awaiting manager approval
- **Past**: Completed or expired reservations

Quick actions:
- Click **View All My Reservations** to see complete history
- Click **Request Reservation** to book a new node

### My Projects
Lists projects where you are a member:
- **Owned**: Projects you created/own
- **Member**: Projects where you have a role

Quick actions:
- Click a project name to view details
- Click **Create Project** to start a new project
- Click **View All Projects** for complete list

### My Account
Displays your maintenance subscription status:
- Current status (Inactive/Basic/Advanced)
- Billing project for maintenance fees

Quick actions:
- Click **Edit** to update your subscription status

### My Billing
Shows cost allocation status across your projects:
- **Verified**: Projects with approved cost objects
- **Pending/Needs Attention**: Projects needing cost allocation setup

Quick actions:
- Click project links to set up or edit cost allocations

---

## 3. Managing Your Account

### 3.1 Viewing Your Profile

1. Click your username in the top navigation bar
2. Select **User Profile**

Your profile shows:
- Account information (name, email, username)
- Maintenance subscription status
- API token (for programmatic access)

### 3.2 Updating Maintenance Status

Your maintenance subscription must be active to make reservations:

1. Go to your **User Profile** or click **Edit** on the My Account card
2. Select your subscription level:
   - **Inactive**: Not subscribed
   - **Basic**: Basic tier
   - **Advanced**: Advanced tier
3. Select a **Billing Project** (must have verified cost allocation)
4. Click **Save**

**Note:** Only projects with verified cost allocations appear in the billing project dropdown.

### 3.3 API Token

For programmatic access to the portal API:

1. Go to **User Profile**
2. Your API token is displayed (hidden by default)
3. Click **Show** to reveal the token
4. Click **Copy** to copy to clipboard
5. Click **Regenerate** to create a new token (invalidates old one)

---

## 4. Projects

### 4.1 Project Types

- **Personal Project** (`username_personal`): For your individual work and reservations
- **Group Project** (`username_group`): For collaborating with team members
- **Custom Projects**: Projects you create for specific purposes

### 4.2 Creating a New Project

1. Click **Create Project** from the dashboard or project list
2. Fill in the form:
   - **Title**: Descriptive name for your project
   - **Description**: Brief explanation of the project's purpose
3. Click **Submit**

The project is automatically activated and ready to use.

### 4.3 Project Roles

Each project member has one or more roles:

| Role | Permissions |
|------|-------------|
| **Owner** | Full control: manage members, cost allocations, and reservations |
| **Financial Admin** | Manage billing and cost allocations; add/remove members |
| **Technical Admin** | Manage reservations and technical aspects |
| **Member** | View project, make reservations on behalf of project |

### 4.4 Adding Members to a Project

1. Go to your project's detail page
2. Click **Manage Members** or **Add User**
3. Search for the user by name or email
4. Select their role(s)
5. Click **Add**

### 4.5 Viewing Project Reservations

1. Go to the project detail page
2. Click **View Project Reservations**
3. See all reservations (future and past) for this project

---

## 5. Making Reservations

### 5.1 Prerequisites

Before making a reservation, ensure:
- Your maintenance subscription is **active** (Basic or Advanced)
- The project you're booking under has **verified cost allocation**

### 5.2 Browsing Available Nodes

1. Click **Nodes** in the navigation
2. View the list of available compute nodes
3. Rentable nodes are marked and show their specifications

### 5.3 Viewing the Rental Calendar

1. Click **Rental Calendar** or navigate to `/nodes/renting/`
2. See availability for rentable nodes (e.g., H200x8 GPU nodes)
3. Blue blocks indicate existing reservations
4. White space indicates availability

### 5.4 Requesting a Reservation

1. Click **Request Reservation** from the calendar or dashboard
2. Fill in the reservation form:
   - **Node**: Select the node you want to reserve
   - **Project**: Select which project this is for
   - **Start Date**: When you want the reservation to begin
   - **Duration**: Number of 12-hour blocks (1-14)
   - **Notes**: Optional notes about your reservation
3. Click **Submit Request**

**Timing Rules:**
- Reservations start at **4:00 PM** on the selected date
- Duration is in **12-hour blocks**
- Maximum end time is **9:00 AM**
- You must book at least **7 days** in advance
- You can book up to **3 months** ahead

### 5.5 Reservation Status

| Status | Meaning |
|--------|---------|
| **Pending** | Awaiting manager review |
| **Confirmed** | Approved and scheduled |
| **Declined** | Not approved (see notes) |
| **Cancelled** | Cancelled by user or manager |

### 5.6 Viewing Your Reservations

1. Click **My Reservations** from the dashboard
2. View reservations organized by status:
   - Upcoming (confirmed, not yet started)
   - Pending (awaiting approval)
   - Past (completed)
   - Declined/Cancelled

### 5.7 Cancelling a Reservation

Contact a Rental Manager to cancel a reservation, or if you have appropriate permissions:
1. Go to the reservation detail page
2. Click **Cancel Reservation**
3. Confirm the cancellation

---

## 6. Cost Allocations (Billing)

### 6.1 What is a Cost Allocation?

A cost allocation defines how charges for a project's reservations should be billed. It consists of:
- One or more **cost objects** (e.g., WBS codes, account numbers)
- **Percentage allocation** for each cost object (must total 100%)

### 6.2 Why Cost Allocations Matter

- Reservations **cannot be made** until a project has a verified cost allocation
- Your **maintenance subscription** can only bill to a project with verified cost allocation
- Invoices are generated based on cost allocation settings

### 6.3 Setting Up Cost Allocation

1. Go to your project's detail page
2. Click **Cost Allocation** or **Set Up Billing**
3. Add one or more cost objects:
   - Enter the cost object code (e.g., `WBS-123456-78`)
   - Set the percentage (all must total 100%)
4. Click **Save**
5. Wait for a Billing Manager to verify your cost allocation

### 6.4 Cost Allocation Status

| Status | Meaning |
|--------|---------|
| **Not Set** | No cost objects defined |
| **Pending** | Submitted, awaiting verification |
| **Verified** | Approved and active |
| **Rejected** | Not approved (see comments) |

---

## 7. For Financial Admins

Financial Admins have additional responsibilities for managing project billing.

### 7.1 Your Responsibilities

- Set up and maintain cost allocations for your projects
- Ensure cost objects are correct and current
- Add/remove project members as needed
- Review invoice reports for your projects

### 7.2 Managing Cost Allocations

1. Go to the project detail page
2. Click **Cost Allocation**
3. Add, edit, or remove cost objects
4. Ensure percentages total 100%
5. Submit for verification

### 7.3 Adding Project Members

1. Go to project detail page
2. Click **Manage Members**
3. Search for users and assign appropriate roles
4. To remove a member, click the remove button next to their name

### 7.4 Viewing Invoices

1. Navigate to **Billing** → **Invoice Reports** (if accessible)
2. Select the month/year
3. Filter by your projects if needed
4. Review charges and cost object allocations

---

## 8. For Technical Admins

Technical Admins manage the technical aspects of project reservations.

### 8.1 Your Responsibilities

- Make reservations on behalf of the project
- Manage technical aspects of compute usage
- Coordinate with team members on resource needs

### 8.2 Making Reservations for the Team

As a Technical Admin, you can:
1. Submit reservation requests for the project
2. View all project reservations
3. Coordinate with Financial Admins on billing

---

## 9. FAQ

### General

**Q: I can't log in. What should I do?**
A: Ensure you're using your institutional credentials. If problems persist, contact your system administrator.

**Q: Why don't I see any projects?**
A: Projects are created automatically on first login. If you don't see them, try logging out and back in. Contact support if the issue persists.

**Q: How do I get help?**
A: Email orcd-help@mit.edu for support.

### Reservations

**Q: Why can't I make a reservation?**
A: Check that:
- Your maintenance subscription is active (not "Inactive")
- The project has a verified cost allocation
- You're booking at least 7 days in advance

**Q: How far in advance can I book?**
A: You can book up to 3 months ahead.

**Q: Can I modify a reservation?**
A: Currently, modifications require cancelling and rebooking. Contact a Rental Manager for assistance.

**Q: What happens if my reservation is declined?**
A: You'll see the status change to "Declined." Check the notes for explanation and contact the Rental Manager if you have questions.

### Billing

**Q: What's a cost object?**
A: A cost object is an account code (like a WBS number) that charges are billed to.

**Q: Why must percentages total 100%?**
A: This ensures that all charges are accounted for. You can have one cost object at 100% or split across multiple.

**Q: How long does verification take?**
A: Billing Managers typically review cost allocations within 1-2 business days.

**Q: Why was my cost allocation rejected?**
A: Check the rejection comments. Common reasons include invalid cost object codes or insufficient documentation.

### Account

**Q: How do I change my maintenance subscription?**
A: Go to User Profile → Edit maintenance status. Select your level and a billing project.

**Q: Why can't I select a billing project?**
A: Only projects with verified cost allocations can be used as billing projects. Set up cost allocation for a project first.

**Q: What's an API token for?**
A: The API token allows programmatic access to the portal for automation and scripting. Most users don't need this.

---

## Getting Help

For additional support:
- **Email:** orcd-help@mit.edu
- **Documentation:** Check the admin and developer guides for technical details
- **Portal Help:** Click the (?) icons on dashboard cards for quick help

