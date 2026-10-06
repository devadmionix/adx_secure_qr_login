# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe
from frappe.model.document import Document

from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	CREDENTIAL_STATUS_EXPIRED,
	TOKEN_HASH_FIELD,
)


class QRLoginCredential(Document):
	# DocType: QR Login Credential, DocType: QR Login Credential

	def before_validate(self):
		self.set_expiry_if_missing()

	def validate(self):
		self.enforce_immutable_fields()
		self.sync_user_full_name()

	def on_update(self):
		self.sync_status_to_expiry()

	# ------------------------------------------------------------------ guards

	def enforce_immutable_fields(self):
		"""Fields that may only be written by server-side code."""
		if self.is_new() or frappe.flags.in_install:
			return

		previous = frappe.get_doc("QR Login Credential", self.name)

		if previous.token_hash != self.token_hash:
			frappe.throw(
				frappe._("Credential material cannot be modified directly."),
				frappe.PermissionError,
			)

		if previous.user != self.user and not frappe.flags.in_qr_rotate:
			frappe.throw(
				frappe._("A credential cannot be reassigned to a different user."),
				frappe.PermissionError,
			)

	def sync_user_full_name(self):
		if not self.user:
			return
		self.user_full_name = frappe.db.get_value(
			"User", self.user, "full_name", cache=True
		) or self.user

	def set_expiry_if_missing(self):
		if self.expires_on:
			return
		from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
			get_validity_days,
		)

		self.expires_on = frappe.utils.add_days(frappe.utils.nowdate(), get_validity_days())

	def sync_status_to_expiry(self):
		"""Flip Active -> Expired once the expiry date has passed.

		Server-side validation in Phase 4 does not rely on this field; it recomputes
		expiry on every authentication attempt. This only keeps list views honest.
		"""
		if self.status != CREDENTIAL_STATUS_ACTIVE or not self.expires_on:
			return
		if frappe.utils.getdate(self.expires_on) < frappe.utils.getdate():
			self.db_set("status", CREDENTIAL_STATUS_EXPIRED, notify=False, commit=False)

	# ------------------------------------------------------------- presentation

	def get_token_material(self):
		"""Return the stored hash. Server-side use only.

		Kept as an explicit accessor so that every read of `token_hash` is a
		deliberate act rather than an incidental dict lookup.
		"""
		return self.get(TOKEN_HASH_FIELD)

	def is_usable(self, on_date=None) -> bool:
		if self.status != CREDENTIAL_STATUS_ACTIVE:
			return False
		if not self.expires_on:
			return False
		return frappe.utils.getdate(self.expires_on) >= (on_date or frappe.utils.getdate())

	def as_public_dict(self) -> dict:
		"""Shape safe to send to a client or write into an audit row."""
		return {
			"name": self.name,
			"user": self.user,
			"user_full_name": self.user_full_name,
			"status": self.status,
			"token_prefix": self.token_prefix,
			"generation": self.generation,
			"issued_on": self.issued_on,
			"expires_on": self.expires_on,
			"last_used": self.last_used,
			"use_count": self.use_count,
			"device_label": self.device_label,
		}


@frappe.whitelist()
def get_credential_summary(name: str) -> dict:
	"""Client-facing read that cannot leak `token_hash`.

	Exposed instead of relying on DocType field permissions, because `hidden` on a
	field is only a UI hint and would still be returned by the REST payload.
	"""
	if not frappe.has_permission("QR Login Credential", "read", doc=name):
		frappe.throw(frappe._("Not permitted"), frappe.PermissionError)

	doc = frappe.get_doc("QR Login Credential", name)
	return doc.as_public_dict()
