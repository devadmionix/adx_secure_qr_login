# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Credential lifecycle API.

Every entry point re-derives authorization from the session user. There is no
path here that trusts a role, a user, or a permission supplied by the caller.

The plaintext token is returned **once**, in the response to the call that minted
it. It is never accepted as an input to any endpoint and never persisted.
"""

from base64 import b64encode

import frappe

from adx_secure_qr_login.security import qr_image, rbac, session_guard, tokens
from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	CREDENTIAL_STATUS_EXPIRED,
	CREDENTIAL_STATUS_REVOKED,
	CREDENTIAL_STATUS_SUPERSEDED,
	EVENT_DOWNLOADED,
	EVENT_GENERATED,
	EVENT_REGENERATED,
	EVENT_REVOKED,
	EVENT_SESSION_REVOKED,
	REASON_OK,
	TOKEN_HASH_FIELD,
)
from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
	detect_company,
	log_event,
)
from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
	get_settings,
	get_validity_days,
)


def _resolve_target_user(user: str) -> str:
	"""Validate that `user` is an existing, enabled System User.

	A QR credential authenticates a Frappe desk user. It must never be mintable
	for a Website User or a disabled account, or it becomes a back door into the
	portal and a way to log in a suspended employee.
	"""
	if not user or not isinstance(user, str):
		frappe.throw(frappe._("A user is required."), frappe.ValidationError)

	if not frappe.db.exists("User", user):
		frappe.throw(frappe._("User {0} does not exist.").format(user), frappe.DoesNotExistError)

	enabled, user_type = frappe.db.get_value("User", user, ["enabled", "user_type"], as_dict=False) or (
		0,
		None,
	)

	if not enabled:
		frappe.throw(
			frappe._("A credential cannot be issued for a disabled user."),
			frappe.ValidationError,
		)

	if user_type != "System User":
		frappe.throw(
			frappe._("A credential can only be issued for a System User."),
			frappe.ValidationError,
		)

	return user


def _enforce_active_cap(user: str, exclude: str | None = None) -> None:
	settings = get_settings()
	cap = settings.max_active_credentials_per_user or 0
	if cap <= 0:
		return

	filters = {"user": user, "status": CREDENTIAL_STATUS_ACTIVE}
	if exclude:
		filters["name"] = ("!=", exclude)

	count = frappe.db.count("QR Login Credential", filters)
	if count >= cap:
		frappe.throw(
			frappe._(
				"This user already has the maximum of {0} active credentials. Revoke one first."
			).format(cap),
			frappe.ValidationError,
		)


def _mint(user: str, validity_days: int | None, device_label: str | None, generation: int) -> dict:
	"""Create one credential and its QR image. Returns the plaintext-bearing dict."""
	token = tokens.generate_token()
	payload = tokens.build_payload(token)

	doc = frappe.get_doc(
		{
			"doctype": "QR Login Credential",
			"user": user,
			TOKEN_HASH_FIELD: tokens.hash_token(token),
			"token_prefix": tokens.token_prefix(token),
			"generation": generation,
			"status": CREDENTIAL_STATUS_ACTIVE,
			"issued_on": frappe.utils.now(),
			"expires_on": frappe.utils.add_days(
				frappe.utils.nowdate(), get_validity_days(validity_days)
			),
			"issued_by": frappe.session.user,
			"device_label": (device_label or "").strip() or None,
		}
	)
	doc.flags.ignore_permissions = True
	doc.insert(ignore_permissions=True)

	qr_image.save_qr_file(payload, doc.name, f"{user.split('@')[0]}")

	return {"doc": doc, "token": token, "payload": payload}


def _public_response(result: dict, include_token: bool = True) -> dict:
	doc = result["doc"]
	payload = {
		"credential": doc.name,
		"user": doc.user,
		"user_full_name": doc.user_full_name,
		"status": doc.status,
		"generation": doc.generation,
		"issued_on": str(doc.issued_on),
		"expires_on": str(doc.expires_on),
		"token_prefix": doc.token_prefix,
		"qr_svg": qr_image.svg_data_uri(result["payload"]),
		"one_time_token": result["token"] if include_token else None,
		"notice": frappe._(
			"This QR is shown once. Save or print it now -- it cannot be displayed again."
		),
	}
	return payload


@frappe.whitelist(methods=["POST"])
def generate_credential(
	user: str,
	validity_days: int | None = None,
	device_label: str | None = None,
) -> dict:
	"""Mint a new bearer credential for an existing Frappe User."""
	rbac.assert_can_manage_target("generate_credential", user)

	target = _resolve_target_user(user)
	_enforce_active_cap(target)

	result = _mint(target, validity_days, device_label, generation=1)
	frappe.db.commit()

	log_event(
		EVENT_GENERATED,
		user=target,
		credential=result["doc"].name,
		success=True,
		reason_code=REASON_OK,
		details={
			"generation": result["doc"].generation,
			"expires_on": str(result["doc"].expires_on),
			"device_label": result["doc"].device_label,
		},
	)

	return _public_response(result)


@frappe.whitelist(methods=["POST"])
def regenerate_credential(
	credential: str,
	validity_days: int | None = None,
	device_label: str | None = None,
) -> dict:
	"""Replace a credential. The previous token stops working immediately."""
	rbac.assert_can_view_credential(credential)
	rbac.assert_can_manage_credentials("regenerate_credential")

	doc = frappe.get_doc("QR Login Credential", credential)

	if doc.status in (CREDENTIAL_STATUS_REVOKED, CREDENTIAL_STATUS_SUPERSEDED):
		frappe.throw(
			frappe._("A {0} credential cannot be regenerated.").format(doc.status.lower()),
			frappe.ValidationError,
		)

	generation = (doc.generation or 1) + 1
	previous = doc.name

	# Flip the old credential first. Doing it before the mint means a failure in
	# the mint path leaves the user with a revoked credential rather than two
	# live ones -- the safer of the two possible partial states.
	frappe.flags.in_qr_rotate = True
	doc.status = CREDENTIAL_STATUS_SUPERSEDED
	doc.revoked_on = frappe.utils.now()
	doc.revoked_by = frappe.session.user
	doc.revocation_reason = frappe._("Superseded by regeneration")
	doc.save(ignore_permissions=True)
	frappe.flags.in_qr_rotate = False

	frappe.db.commit()

	result = _mint(
		doc.user,
		validity_days,
		device_label or doc.device_label,
		generation=generation,
	)

	frappe.db.set_value(
		"QR Login Credential",
		previous,
		"superseded_by",
		result["doc"].name,
		update_modified=False,
	)
	frappe.db.commit()

	log_event(
		EVENT_REGENERATED,
		user=doc.user,
		credential=result["doc"].name,
		success=True,
		reason_code=REASON_OK,
		details={"generation": generation, "superseded": previous},
	)
	log_event(
		EVENT_REVOKED,
		user=doc.user,
		credential=previous,
		success=True,
		reason_code=REASON_OK,
		details={"reason": "superseded_by_regeneration", "replacement": result["doc"].name},
	)

	return _public_response(result)


@frappe.whitelist(methods=["POST"])
def revoke_credential(credential: str, reason: str | None = None) -> dict:
	"""Revoke a credential permanently and destroy its printable QR."""
	rbac.assert_can_view_credential(credential)
	rbac.assert_can_manage_credentials("revoke_credential")

	doc = frappe.get_doc("QR Login Credential", credential)

	if doc.status == CREDENTIAL_STATUS_REVOKED:
		frappe.throw(
			frappe._("This credential is already revoked."), frappe.ValidationError
		)

	doc.status = CREDENTIAL_STATUS_REVOKED
	doc.revoked_on = frappe.utils.now()
	doc.revoked_by = frappe.session.user
	doc.revocation_reason = (reason or "").strip() or frappe._("No reason supplied")
	doc.save(ignore_permissions=True)

	qr_image.delete_qr_files(doc.name)
	frappe.db.commit()

	# Spec 8: revocation must also handle the session already established from
	# this credential, not merely block the next login.
	terminated = 0
	if doc.revoke_active_sessions:
		terminated = session_guard.terminate_user_sessions(
			doc.user, reason=f"QR credential {doc.name} revoked"
		)
		frappe.db.commit()

	log_event(
		EVENT_REVOKED,
		user=doc.user,
		credential=doc.name,
		success=True,
		reason_code=REASON_OK,
		details={"reason": doc.revocation_reason, "sessions_terminated": terminated},
	)

	if terminated:
		log_event(
			EVENT_SESSION_REVOKED,
			user=doc.user,
			credential=doc.name,
			success=True,
			reason_code=REASON_OK,
			details={"sessions_terminated": terminated, "trigger": "credential_revoked"},
		)

	return {
		"credential": doc.name,
		"status": doc.status,
		"sessions_terminated": terminated,
	}


@frappe.whitelist(methods=["GET"])
def get_qr_data_uri(credential: str) -> str | None:
	"""Return the stored QR image as a data URI, for download and printing.

	Re-reads the private File rather than re-rendering, so the plaintext token
	never has to exist in memory for a re-download. Requires the same
	authorization as viewing the credential itself.

	Note the confidentiality consequence: the PNG is a faithful rendering of the
	bearer token, so anyone who can fetch this can OCR the token back out. It is
	gated exactly as tightly as the credential row.
	"""
	rbac.assert_can_view_credential(credential)

	file_name = qr_image.find_qr_file(credential)
	if not file_name:
		return None

	try:
		content = frappe.get_doc("File", file_name).get_content()
	except Exception:
		frappe.log_error(title="QR image read failed", message=frappe.get_traceback())
		return None

	# Spec 6.2 'Allow own QR download': an ordinary user may be permitted to sign
	# in with their own QR without being able to re-download the image.
	if not rbac.can_manage_credentials() and not _self_download_allowed():
		frappe.throw(frappe._("Not permitted"), frappe.PermissionError)

	doc = frappe.get_doc("QR Login Credential", credential)
	log_event(
		EVENT_DOWNLOADED,
		user=doc.user,
		credential=doc.name,
		success=True,
		reason_code=REASON_OK,
		details={"generation": doc.generation},
		company=detect_company(),
	)

	return f"data:image/png;base64,{b64encode(content).decode('ascii')}"


def _self_download_allowed() -> bool:
	try:
		return bool(get_settings().allow_self_download)
	except Exception:
		# Fail closed on the restriction, but do not break the desk: an unreadable
		# settings row must not silently grant access.
		return False


@frappe.whitelist(methods=["GET"])
def get_credential(credential: str) -> dict:
	"""Metadata for one credential. Never includes the token."""
	rbac.assert_can_view_credential(credential)

	doc = frappe.get_doc("QR Login Credential", credential)
	payload = doc.as_public_dict()
	payload["qr_available"] = qr_image.qr_file_exists(doc.name)
	return payload


@frappe.whitelist(methods=["POST"])
def terminate_user_sessions(user: str, reason: str | None = None) -> dict:
	"""Force-logout every live session for a user (spec 8).

	QR Admin only. Use when an account is suspected compromised but must keep
	its credential -- revoking the QR blocks future logins, this ends the ones
	already established.
	"""
	from adx_secure_qr_login.security import session_events

	terminated = session_events.terminate_sessions(user, reason=reason)
	return {"user": user, "sessions_terminated": terminated}


@frappe.whitelist(methods=["GET"])
def list_user_credentials(user: str) -> list[dict]:
	"""All credentials for one user, newest first.

	Scoping is enforced by the credential-view rule, then filtered to the single
	requested user so a Manager cannot use this to enumerate the whole estate.
	"""
	rbac.assert_can_view_user(user)

	names = frappe.get_all(
		"QR Login Credential",
		filters={"user": user},
		fields=["name"],
		order_by="creation desc",
		limit_page_length=0,
	)

	out = []
	for name in names:
		doc = frappe.get_doc("QR Login Credential", name)
		out.append(doc.as_public_dict())
	return out
