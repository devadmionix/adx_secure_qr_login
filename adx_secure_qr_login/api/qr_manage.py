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


def _qr_content(token: str) -> str:
	"""What gets encoded into QR *images*: a login URL any camera can open.

	Derived from the site base URL at mint time (never hard-coded). Falls
	back to the bare payload when no base URL is configured.
	"""
	try:
		return tokens.build_login_url(frappe.utils.get_url(), token)
	except Exception:
		return tokens.build_payload(token)


def _mint(user: str, validity_days: int | None, device_label: str | None, generation: int) -> dict:
	"""Create one credential and its QR image. Returns the plaintext-bearing dict."""
	token = tokens.generate_token()
	payload = tokens.build_payload(token)
	qr_content = _qr_content(token)

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

	qr_image.save_qr_file(qr_content, doc.name, f"{user.split('@')[0]}")

	return {"doc": doc, "token": token, "payload": payload, "qr_content": qr_content}


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
		"qr_svg": qr_image.svg_data_uri(result.get("qr_content") or result["payload"]),
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


def issue_credential_for_new_user(doc, method=None) -> dict | None:
	"""Auto-issue a QR credential + welcome email when a User is created.

	Hooked to `User.after_insert` (see hooks.py). Strictly opt-in via the
	`auto_issue_credential_on_user_create` setting, and strictly scoped:

	* skipped in tests (`frappe.flags.in_test`) so suites never send mail,
	* skipped for Administrator/Guest, Website Users and disabled accounts,
	* skipped when the new user has no explicit company -- a credential
	  without a company could never pass login validation, so minting one
	  would only mail a dead code.

	Idempotent: if the user already holds an Active credential (double-fired
	hook, retried request), no second credential is minted and no second mail
	is queued -- the existing credential is returned.

	Failure-safe: minting happens inside try/except. If anything fails, the
	error is logged (administrator-visible via Error Log) and User creation
	still succeeds with no mail claiming a QR is ready. A mail failure alone
	never removes the credential; use `resend_welcome_email` to retry.

	Runs inside the User's save transaction: no commit here, the outer save
	commits credential, audit row and queued email together.

	On success this also suppresses Frappe core's "Complete your registration"
	welcome mail (`User.on_update` -> `send_password_notification` runs *after*
	`after_insert` on the same doc object, so setting `doc.flags` here wins).
	The user then receives exactly one welcome mail -- the QR one below,
	which carries the QR *and* the password-setup link, so no core
	functionality is lost by the suppression.
	"""
	if getattr(frappe.flags, "in_test", False):
		return None

	try:
		settings = get_settings()
		if not settings.auto_issue_credential_on_user_create:
			return None
	except Exception:
		return None

	user = doc.name
	if user in ("Administrator", "Guest"):
		return None
	if not doc.enabled or getattr(doc, "user_type", None) != "System User":
		return None

	from adx_secure_qr_login.security import validation

	company = validation.get_user_company(user)
	if not company:
		return None

	# Propagate the company boundary into ERPNext's native User Permissions.
	# Without this, the custom `User.company` field only gates QR login while
	# standard docs (Customer, Sales Order, etc.) are never company-limited.
	try:
		frappe.permissions.add_user_permission(
			"Company", company, user, ignore_permissions=True
		)
	except Exception:
		frappe.log_error(
			title="Company User Permission failed", message=frappe.get_traceback()
		)

	existing = frappe.db.get_value(
		"QR Login Credential",
		{"user": user, "status": CREDENTIAL_STATUS_ACTIVE},
		"name",
		order_by="creation desc",
	)
	if existing:
		return {"credential": existing, "user": user, "already_existed": True}

	try:
		_enforce_active_cap(user)

		result = _mint(
			user,
			None,
			device_label=frappe._("Auto-issued on user creation"),
			generation=1,
		)

		log_event(
			EVENT_GENERATED,
			user=user,
			credential=result["doc"].name,
			success=True,
			reason_code=REASON_OK,
			details={
				"generation": result["doc"].generation,
				"expires_on": str(result["doc"].expires_on),
				"trigger": "user_created",
			},
			company=company,
			commit=False,
		)

		_mail_welcome_qr(user, company, result, reset_link=_new_user_reset_link(doc))
	except Exception:
		# User creation must survive a QR failure. The Error Log entry is the
		# administrator-visible signal; mint manually via generate_credential.
		frappe.log_error(
			title="QR auto-issue failed", message=frappe.get_traceback()
		)
		return None

	# Our QR mail replaces core's "Complete your registration" mail.
	# Both flags: `no_welcome_mail` is the documented opt-out checked by
	# `send_password_notification`; `email_sent` is its re-entry guard.
	doc.flags.no_welcome_mail = 1
	doc.flags.email_sent = 1
	return {"credential": result["doc"].name, "user": user}


def _new_user_reset_link(doc) -> str | None:
	"""Mint a password-setup link for a freshly created User.

	Replaces the link Frappe core would have mailed via its own welcome mail,
	which we suppress when our QR mail goes out. Returns None (mail goes
	out without the link; QR login still works) rather than failing creation.
	"""
	try:
		return doc._reset_password()
	except Exception:
		frappe.log_error(
			title="QR welcome mail: reset link failed", message=frappe.get_traceback()
		)
		return None


def _mail_welcome_qr(user: str, company: str, result: dict, reset_link: str | None = None) -> None:
	"""Queue the welcome email per the feature spec structure.

	Layout (see design reference):
	  brand header -> green-dot "Welcome to {company}" -> "Hello {name},"
	  -> welcome copy -> "Your Login QR Code"
	  -> scan instructions -> centred QR card -> status/expiry caption
	  -> [Download My QR Code] [Login with QR] buttons
	  -> security note -> login URL [+ set-password link].

	The QR is shown inline (base64 data URI) for instant scanning AND kept
	as a PNG attachment for printing. Never contains a password or any other
	secret -- only the QR login payload rendering plus links.
	"""
	try:
		png = qr_image.render_png(result.get("qr_content") or result["payload"])
		_send_welcome_mail(
			user=user,
			company=company,
			credential_name=result["doc"].name,
			expires_on=result["doc"].expires_on,
			png=png,
			reset_link=reset_link,
		)
	except Exception:
		frappe.log_error(
			title="QR welcome email failed", message=frappe.get_traceback()
		)


def _send_welcome_mail(
	user: str,
	company: str,
	credential_name: str,
	expires_on,
	png: bytes | None,
	reset_link: str | None = None,
) -> None:
	"""Compose and queue one welcome mail. Shared by auto-issue and resend.

	Raises on send failure (callers decide whether to swallow it): the
	auto-issue hook logs and keeps the user, the resend endpoint surfaces it.
	"""
	inline_images = None

	full_name = (
		frappe.db.get_value("User", user, "full_name")
		or frappe.db.get_value("User", user, "first_name")
		or user
	)
	try:
		valid_until = frappe.utils.formatdate(expires_on, "MMMM d, yyyy")
	except Exception:
		valid_until = frappe.utils.formatdate(expires_on)

	try:
		base_url = frappe.utils.get_url()
	except Exception:
		base_url = ""
	qr_login_url = f"{base_url}/login" if base_url else "/login"
	download_url = (
		f"{base_url}/api/method/adx_secure_qr_login.api.qr_manage.download_qr_image"
		f"?credential={credential_name}"
		if base_url
		else None
	)

	qr_file_name = f"{user.split('@')[0]}-qr.png"
	if png:
		inline_images = [{"filename": qr_file_name, "filecontent": png}]
		qr_img_tag = (
			f'<img embed="{qr_file_name}" alt="Your login QR code" '
			'width="200" height="200" '
			'style="display:block;width:200px;height:200px;'
			'margin:0 auto;border:0;outline:none;" />'
		)
	else:
		qr_img_tag = (
			f'<p style="font-size:13px;color:#4b5563;margin:0;">'
			'Your QR image could not be generated. Contact your administrator.</p>'
		)

	brand = (company or "").strip() or "ERPNext"
	password_row = ""
	if reset_link:
		password_row = (
			'<p style="font-size:13px;color:#4b5563;margin:8px 0 0;">'
			f'New here? <a href="{reset_link}" style="color:#111827;">'
			"Set your password</a> to also enable email + password login.</p>"
		)
	buttons = f"""\
    <p style="margin:0 0 20px;">
      <a href="{qr_login_url}" style="display:inline-block;background:#111827;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;padding:10px 22px;border-radius:6px;margin-right:8px;">Login with QR</a>"""
	if download_url:
		buttons += f"""
      <a href="{download_url}" style="display:inline-block;background:#ffffff;color:#111827;font-size:14px;font-weight:600;text-decoration:none;padding:9px 22px;border-radius:6px;border:1px solid #111827;">Download My QR Code</a>"""
	buttons += "\n    </p>"

	message = f"""\
<div style="background:#f3f4f6;padding:32px 16px;font-family:-apple-system,'Segoe UI',Arial,sans-serif;">
  <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:8px;padding:32px 36px;">
    <div style="margin-bottom:20px;font-size:22px;font-weight:700;">
      <span style="color:#111827;">&#9673; {brand}</span>
    </div>
    <div style="font-size:19px;font-weight:700;color:#111827;margin-bottom:16px;">
      <span style="color:#22c55e;font-size:13px;vertical-align:middle;">&#9679;</span>
      Welcome to {brand}
    </div>
    <p style="font-size:14px;color:#111827;margin:0 0 12px;">Hello {full_name},</p>
    <p style="font-size:14px;color:#111827;margin:0 0 12px;">Welcome to {brand}.</p>
    <p style="font-size:14px;color:#111827;margin:0 0 12px;">Your Secure QR Login credential has been created successfully.</p>
    <p style="font-size:14px;color:#111827;margin:0 0 20px;">You can use the QR code below to securely log in to ERPNext.</p>
    <p style="font-size:14px;font-weight:700;color:#111827;margin:0 0 4px;">Your Login QR Code</p>
    <p style="font-size:13px;color:#4b5563;margin:0 0 20px;">Scan with your phone camera to log in instantly. You can also save or download it using the button below.</p>
    <div style="text-align:center;margin:0 0 8px;">
      <div style="display:inline-block;border:1px solid #e5e7eb;border-radius:8px;padding:12px;background:#ffffff;">
        {qr_img_tag}
      </div>
    </div>
    <p style="text-align:center;font-size:12px;color:#4b5563;margin:0 0 4px;">Credential Status: <strong>Active</strong> &middot; Expiration Date: {valid_until}</p>
    <p style="text-align:center;font-size:12px;color:#9ca3af;margin:0 0 20px;">Keep this code private</p>
{buttons}
    <p style="font-size:13px;color:#4b5563;margin:0;">Please keep your QR code secure. Anyone who has access to your active QR credential may be able to authenticate as you.</p>
    <p style="font-size:13px;color:#4b5563;margin:8px 0 0;">If you did not expect this account or QR credential, please contact your administrator.</p>
    <p style="font-size:13px;color:#4b5563;margin:8px 0 0;">Or log in with your email at <a href="{qr_login_url}" style="color:#111827;">{qr_login_url}</a></p>
    {password_row}
    <p style="font-size:14px;color:#111827;margin:16px 0 0;">Regards,<br />{brand}</p>
  </div>
</div>"""
	frappe.sendmail(
		recipients=[user],
		subject=frappe._("Welcome to {0} - Your Secure QR Login").format(brand),
		message=message,
		inline_images=inline_images,
		now=False,
	)


@frappe.whitelist(methods=["GET"])
def download_qr_image(credential: str):
	"""Download the stored QR PNG for a credential (used by the email button).

	Serves the private stored image as a file download. Gated exactly like a
	credential view, plus the self-download rule, so the bearer image never
	becomes a public URL. If the requester has no session, Frappe redirects
	to login first; the PNG attachment in the mail covers offline saving.
	"""
	rbac.assert_can_view_credential(credential)

	# Spec 6.2 'Allow own QR download': same rule as get_qr_data_uri.
	if not rbac.can_manage_credentials() and not _self_download_allowed():
		frappe.throw(frappe._("Not permitted"), frappe.PermissionError)

	doc = frappe.get_doc("QR Login Credential", credential)

	file_name = qr_image.find_qr_file(credential)
	if not file_name:
		frappe.throw(
			frappe._("No printable QR is stored for this credential."),
			frappe.DoesNotExistError,
		)
	try:
		content = frappe.get_doc("File", file_name).get_content()
	except Exception:
		frappe.log_error(title="QR image read failed", message=frappe.get_traceback())
		frappe.throw(
			frappe._("The QR image could not be read."), frappe.ValidationError
		)

	log_event(
		EVENT_DOWNLOADED,
		user=doc.user,
		credential=doc.name,
		success=True,
		reason_code=REASON_OK,
		details={"generation": doc.generation, "via": "download_endpoint"},
		company=detect_company(),
	)

	stem = (doc.user or "qr").split("@")[0]
	frappe.local.response["filename"] = f"{stem}-qr.png"
	frappe.local.response["filecontent"] = content
	frappe.local.response["type"] = "download"


@frappe.whitelist(methods=["GET"])
def get_mail_status(credential: str) -> dict:
	"""Latest email delivery state for this credential's owner, for the form UI."""
	rbac.assert_can_view_credential(credential)
	doc = frappe.get_doc("QR Login Credential", credential)
	row = frappe.db.sql(
		"""SELECT eq.status FROM `tabEmail Queue Recipient` r
		   JOIN `tabEmail Queue` eq ON eq.name = r.parent
		   WHERE r.recipient = %s ORDER BY r.creation DESC LIMIT 1""",
		(doc.user,),
		as_dict=True,
	)
	return {"status": row[0].status if row else "Not Sent"}


@frappe.whitelist(methods=["GET"])
def download_qr_svg(credential: str):
	"""Download the stored SVG rendering of the QR."""
	rbac.assert_can_view_credential(credential)
	if not rbac.can_manage_credentials() and not _self_download_allowed():
		frappe.throw(frappe._("Not permitted"), frappe.PermissionError)

	doc = frappe.get_doc("QR Login Credential", credential)
	file_name = qr_image.find_qr_svg_file(credential)
	if not file_name:
		frappe.throw(
			frappe._(
				"No SVG is stored for this credential. Regenerate it to re-mint with an SVG twin."
			),
			frappe.DoesNotExistError,
		)
	try:
		content = frappe.get_doc("File", file_name).get_content()
	except Exception:
		frappe.log_error(title="QR SVG read failed", message=frappe.get_traceback())
		frappe.throw(
			frappe._("The SVG image could not be read."), frappe.ValidationError
		)

	log_event(
		EVENT_DOWNLOADED,
		user=doc.user,
		credential=doc.name,
		success=True,
		reason_code=REASON_OK,
		details={"generation": doc.generation, "via": "download_svg_endpoint"},
		company=detect_company(),
	)
	stem = (doc.user or "qr").split("@")[0]
	frappe.local.response["filename"] = f"{stem}-qr.svg"
	frappe.local.response["filecontent"] = content
	frappe.local.response["type"] = "download"


@frappe.whitelist(methods=["POST"])
def resend_welcome_email(credential: str) -> dict:
	"""Re-send the welcome mail for an existing Active credential.

	Admin/Manager action (also the Desk "Resend Welcome Email" button). Uses
	the *stored* printable PNG -- the plaintext token is never persisted, so
	this is the only re-sendable representation. Never mints a new
	credential: the same `credential` stays live.
	"""
	rbac.assert_can_view_credential(credential)
	rbac.assert_can_manage_credentials("resend_welcome_email")

	doc = frappe.get_doc("QR Login Credential", credential)
	if doc.status != CREDENTIAL_STATUS_ACTIVE:
		frappe.throw(
			frappe._("Only an Active credential can be re-mailed."),
			frappe.ValidationError,
		)

	file_name = qr_image.find_qr_file(credential)
	if not file_name:
		frappe.throw(
			frappe._(
				"No printable QR is stored for this credential. Regenerate it first."
			),
			frappe.DoesNotExistError,
		)
	try:
		png = frappe.get_doc("File", file_name).get_content()
	except Exception:
		frappe.log_error(title="QR image read failed", message=frappe.get_traceback())
		frappe.throw(
			frappe._("The QR image could not be read."), frappe.ValidationError
		)

	from adx_secure_qr_login.security import validation

	_send_welcome_mail(
		user=doc.user,
		company=validation.get_user_company(doc.user),
		credential_name=doc.name,
		expires_on=doc.expires_on,
		png=png,
		reset_link=None,
	)
	return {"credential": doc.name, "user": doc.user, "mailed": True}
