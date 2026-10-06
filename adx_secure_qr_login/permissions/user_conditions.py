# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Row-level company isolation for core User documents.

ERPNext does not isolate the `User` list by company natively, which lets
Company A users search or open Company B users. These helpers apply the
same company boundary as the QR credential layer:

- System Manager / QR Admin: see all companies (they are the multi-company
  administrators, consistent with the QR model).
- Everyone else: only the company stored in the session user's `company`
  field (derived from the existing Custom Field).
"""

import frappe

from adx_secure_qr_login.security.rbac import can_manage_credentials, is_qr_admin
from adx_secure_qr_login.secure_qr_login.constants import ROLE_MANAGER


def _current_company() -> str | None:
	try:
		return frappe.db.get_value("User", frappe.session.user, "company")
	except Exception:
		return None


def _target_company(doc) -> str | None:
	try:
		return doc.get("company") or frappe.db.get_value("User", doc.get("name"), "company")
	except Exception:
		return None


def is_unrestricted(user: str | None = None) -> bool:
	user = user or frappe.session.user
	return (
		user in ("Administrator", "Guest")
		or is_qr_admin(user)
		or "System Manager" in set(frappe.get_roles(user) or [])
	)


def get_permission_query_conditions(user: str | None = None) -> str | None:
	user = user or frappe.session.user
	if is_unrestricted(user):
		return None

	company = _current_company()
	if not company:
		# Strict default for a normal user with no company context.
		return "1 = 0"
	return f"(`tabUser`.`company` = {frappe.db.escape(company)})"


def has_permission(doc, ptype: str, user: str | None = None) -> bool:
	user = user or frappe.session.user
	if is_unrestricted(user):
		return True

	company = _current_company()
	if not company:
		return False
	return _target_company(doc) == company
