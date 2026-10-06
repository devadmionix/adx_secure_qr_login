# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Role names, event names and internal reason codes.

Single source of truth so that DocType permission rows, controllers and APIs all
refer to the same literals.
"""

import frappe

# ---------------------------------------------------------------------- roles
ROLE_ADMIN = "QR Admin"
ROLE_MANAGER = "QR Manager"
QR_ROLES = (ROLE_ADMIN, ROLE_MANAGER)

# Frappe v16 grants every desk user the role "Desk User", NOT a role named
# "System User":
#
#     frappe/permissions.py:35   SYSTEM_USER_ROLE = "Desk User"
#     frappe/permissions.py:561  roles.append(SYSTEM_USER_ROLE)  # if is_system_user
#
# A Role record named "System User" does exist in the database, but nothing ever
# assigns it and `get_roles()` never returns it. A DocPerm row targeting it is
# silently inert -- no error, no warning, just no access. DocType permissions that
# should apply to any authenticated desk user must name "Desk User".
DESK_USER_ROLE = "Desk User"

# ------------------------------------------------------------------ statuses
CREDENTIAL_STATUS_ACTIVE = "Active"
CREDENTIAL_STATUS_EXPIRED = "Expired"
CREDENTIAL_STATUS_REVOKED = "Revoked"
CREDENTIAL_STATUS_SUPERSEDED = "Superseded"

CREDENTIAL_STATUSES = (
	CREDENTIAL_STATUS_ACTIVE,
	CREDENTIAL_STATUS_EXPIRED,
	CREDENTIAL_STATUS_REVOKED,
	CREDENTIAL_STATUS_SUPERSEDED,
)

# -------------------------------------------------------------------- events
EVENT_LOGIN_SUCCESS = "QR Login Success"
EVENT_GENERATED = "QR Generated"
EVENT_DOWNLOADED = "QR Downloaded"
EVENT_REGENERATED = "QR Regenerated"
EVENT_REVOKED = "QR Revoked"
EVENT_EXPIRED = "QR Expired"
EVENT_INVALID_CREDENTIAL = "Invalid Credential"
EVENT_EXPIRED_CREDENTIAL = "Expired Credential"
EVENT_REVOKED_CREDENTIAL = "Revoked Credential"
EVENT_INACTIVE_USER = "Inactive User"
EVENT_USER_DISABLED = "User Disabled"
EVENT_RATE_LIMITED = "Rate Limited"
EVENT_SESSION_REVOKED = "Session Revoked"
EVENT_SETTING_CHANGED = "Security Setting Changed"
EVENT_UNAUTHORIZED_MANAGEMENT = "Unauthorized QR Management"
EVENT_SECURITY_VALIDATION_FAILED = "Security Validation Failed"

# Order must match the `event` Select options in qr_login_audit.json exactly:
# frappe validates the value on insert.
EVENTS = (
	EVENT_LOGIN_SUCCESS,
	EVENT_GENERATED,
	EVENT_DOWNLOADED,
	EVENT_REGENERATED,
	EVENT_REVOKED,
	EVENT_EXPIRED,
	EVENT_INVALID_CREDENTIAL,
	EVENT_EXPIRED_CREDENTIAL,
	EVENT_REVOKED_CREDENTIAL,
	EVENT_INACTIVE_USER,
	EVENT_USER_DISABLED,
	EVENT_RATE_LIMITED,
	EVENT_SESSION_REVOKED,
	EVENT_SETTING_CHANGED,
	EVENT_UNAUTHORIZED_MANAGEMENT,
	EVENT_SECURITY_VALIDATION_FAILED,
)

# ------------------------------------------------------------------- reasons
# Internal codes. These are safe to persist in the audit trail because they
# never contain credential material or user-identifying detail beyond the user id.
REASON_INVALID_CREDENTIAL = "INVALID_CREDENTIAL"
REASON_EXPIRED_CREDENTIAL = "EXPIRED_CREDENTIAL"
REASON_REVOKED_CREDENTIAL = "REVOKED_CREDENTIAL"
REASON_SUPERSEDED_CREDENTIAL = "SUPERSEDED_CREDENTIAL"
REASON_INACTIVE_USER = "INACTIVE_USER"
REASON_RATE_LIMITED = "RATE_LIMITED"
REASON_UNAUTHORIZED = "UNAUTHORIZED"
REASON_SECURITY_VALIDATION_FAILED = "SECURITY_VALIDATION_FAILED"
REASON_OK = "OK"

# Internal reason code -> user-facing message.
#
# Every entry is deliberately vague and generic. The login page returns a single
# uniform failure message regardless of which code fired, so these strings are
# only used in the authenticated desk UI (where the viewer already has rights)
# and must never be echoed back to an anonymous scanner.
REASON_MESSAGES = {
	REASON_INVALID_CREDENTIAL: frappe._("This QR credential is not recognised."),
	REASON_EXPIRED_CREDENTIAL: frappe._("This QR credential has expired. Please contact the QR administrator."),
	REASON_REVOKED_CREDENTIAL: frappe._("This QR credential has been revoked. Please contact the QR administrator."),
	REASON_SUPERSEDED_CREDENTIAL: frappe._("This QR credential has been replaced. Please contact the QR administrator."),
	REASON_INACTIVE_USER: frappe._("This account is not active. Please contact your administrator."),
	REASON_RATE_LIMITED: frappe._("Too many attempts. Please wait and try again."),
	REASON_UNAUTHORIZED: frappe._("You are not permitted to perform this action."),
	REASON_SECURITY_VALIDATION_FAILED: frappe._("This QR credential could not be validated."),
}

# The single message returned to an anonymous caller for every failure mode.
# Uniform messaging prevents an attacker from distinguishing "no such user" from
# "revoked" from "expired", which would otherwise leak credential existence.
GENERIC_LOGIN_FAILURE_MESSAGE = frappe._(
	"Could not sign you in with that QR credential. Please try again or use your password."
)

# --------------------------------------------------------------- field names
TOKEN_HASH_FIELD = "token_hash"
TOKEN_PREFIX_LENGTH = 8
