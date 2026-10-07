# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""My QR: self-service view / generate / revoke for the signed-in user.

Every endpoint acts on `frappe.session.user` and takes no user argument, so
there is no parameter an attacker could change to reach another account. Minting
and revoking reuse `qr_manage._issue_credential` / `_revoke_credential`, the same
code the administrator buttons run; this module only decides who may call them
and under which setting.

Viewing, downloading and printing reuse the existing `get_qr_data_uri`,
`download_qr_image` and `download_qr_svg`, which already enforce the
"Allow Users To Download Own QR" rule.
"""

import frappe

from adx_secure_qr_login.api import qr_manage
from adx_secure_qr_login.security import rbac, validation
from adx_secure_qr_login.secure_qr_login.constants import CREDENTIAL_STATUS_ACTIVE
from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
	get_settings,
)

TRIGGER = "self_service"


def _me() -> str:
	user = frappe.session.user
	if not user or user == "Guest":
		frappe.throw(frappe._("Please sign in."), frappe.PermissionError)
	return user


def _eligible(user: str) -> tuple[bool, str | None]:
	"""Whether `user` may hold a QR at all, with a reason when not."""
	if user == "Administrator":
		return False, frappe._("The Administrator account cannot use QR login.")
	enabled, user_type = frappe.db.get_value("User", user, ["enabled", "user_type"]) or (0, None)
	if not enabled or user_type != "System User":
		return False, frappe._("QR login is only available to enabled System Users.")
	if not validation._is_user_qr_enabled(user):
		return False, frappe._("QR login is disabled for your account.")
	if validation.user_has_company_field() and not validation.get_user_company(user):
		return False, frappe._("No Company is set on your account. Ask your administrator.")
	return True, None


def _flags(settings) -> dict:
	return {
		"can_download": bool(settings.allow_self_download),
		"generate_enabled": bool(settings.allow_self_generate_qr),
		"revoke_enabled": bool(settings.allow_self_revoke_qr),
	}


@frappe.whitelist(methods=["GET"])
def get_my_qr() -> dict:
	"""The caller's own QR state. Contains no token material."""
	user = _me()
	settings = get_settings()
	eligible, reason = _eligible(user)

	today = frappe.utils.nowdate()
	rows = frappe.get_all(
		"QR Login Credential",
		filters={"user": user},
		fields=["name", "status", "issued_on", "expires_on", "last_used", "generation"],
		order_by="creation desc",
		limit_page_length=20,
	)
	for r in rows:
		if r.status == CREDENTIAL_STATUS_ACTIVE and r.expires_on and str(r.expires_on) < today:
			r.status = "Expired"

	active = next((r for r in rows if r.status == CREDENTIAL_STATUS_ACTIVE), None)
	flags = _flags(settings)

	return {
		"user": user,
		"eligible": eligible,
		"reason": reason,
		"qr_login_enabled": bool(settings.qr_login_enabled),
		"credentials": rows,
		"active": active,
		**flags,
		"can_generate": bool(eligible and flags["generate_enabled"]),
		"can_revoke": bool(active and flags["revoke_enabled"]),
	}


@frappe.whitelist(methods=["POST"])
def generate_my_qr() -> dict:
	"""Issue a QR credential for the caller. Requires the self-generate setting."""
	user = _me()

	if not get_settings().allow_self_generate_qr:
		rbac._deny("generate_my_qr", user, detail="self_generate_disabled")

	eligible, reason = _eligible(user)
	if not eligible:
		frappe.throw(reason, frappe.ValidationError)

	result = qr_manage._issue_credential(user, trigger=TRIGGER)
	# The image is shown once; the secret is never sent as text.
	result.pop("one_time_token", None)
	return result


@frappe.whitelist(methods=["POST"])
def revoke_my_qr(credential: str, reason: str | None = None) -> dict:
	"""Revoke one of the caller's own active credentials."""
	user = _me()

	if not get_settings().allow_self_revoke_qr:
		rbac._deny("revoke_my_qr", user, detail="self_revoke_disabled")

	row = frappe.db.get_value(
		"QR Login Credential", credential, ["user", "status"], as_dict=True
	)
	# Same answer for "does not exist" and "belongs to someone else".
	if not row or row.user != user:
		rbac._deny("revoke_my_qr", user, detail="not_owner")

	if row.status != CREDENTIAL_STATUS_ACTIVE:
		frappe.throw(
			frappe._("Only an active QR can be revoked."), frappe.ValidationError
		)

	return qr_manage._revoke_credential(
		credential, reason or frappe._("Revoked by the user"), trigger=TRIGGER
	)
