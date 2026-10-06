# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Row-level scoping for Weekly Security Report.

Aggregate security figures: QR Admin and System Manager see all rows;
ordinary desk users see nothing. Mirrors the audit-trail pattern.
"""

import frappe

from adx_secure_qr_login.security.weekly_report import _can_access_report


def get_permission_query_conditions(user: str | None = None) -> str | None:
	user = user or frappe.session.user
	if user == "Administrator" or _can_access_report(user):
		return None
	return "1 = 0"


def has_permission(doc, ptype: str, user: str | None = None) -> bool:
	user = user or frappe.session.user
	if user == "Administrator":
		return True
	return _can_access_report(user)
