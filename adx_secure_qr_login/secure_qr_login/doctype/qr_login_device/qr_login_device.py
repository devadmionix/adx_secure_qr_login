# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe
from frappe.model.document import Document


class QRLoginDevice(Document):
	"""Device tracking for QR logins.

	Device *identification* -- deriving the id from the request, deciding whether
	a device is trusted, and recording a successful login -- lives in
	`adx_secure_qr_login.security.devices`. That module is the single
	implementation, shared by the login endpoint and the REST API.

	This controller only enforces invariants that must hold no matter which path
	created the row, including a row inserted by hand through the desk form or a
	Data Import.
	"""

	def validate(self):
		self.require_subject()
		self.enforce_immutable_identity()

	def require_subject(self):
		"""A device always belongs to a user.

		`user` is already mandatory at the DocType level; this guards the case
		where the field is written blank by a raw API call, which would otherwise
		produce a device nobody can ever be scoped to.
		"""
		if not self.user:
			frappe.throw(
				frappe._("A device must belong to a user."),
				frappe.ValidationError,
			)

	def enforce_immutable_identity(self):
		"""`device_id` and `user` are the device's identity and never change.

		Changing them would silently re-point an existing device's history (and its
		trusted/revoked state) at a different user, which is a privilege-relevant
		change and must go through revocation instead.
		"""
		if self.is_new() or frappe.flags.in_install:
			return

		previous = frappe.get_doc("QR Login Device", self.name)

		if previous.device_id != self.device_id or previous.user != self.user:
			frappe.throw(
				frappe._(
					"A device's identity cannot be changed. Revoke it and register a new one instead."
				),
				frappe.PermissionError,
			)

	def before_insert(self):
		if not self.first_seen:
			self.first_seen = frappe.utils.now()
		if not self.last_seen:
			self.last_seen = self.first_seen

	def on_trash(self):
		"""Keep the session registry honest if a device row is purged.

		A device row can be deleted by a privileged user. The concurrent-session
		registry is keyed on sid rather than device, so nothing has to be undone
		here; the hook exists to make that explicit rather than incidental.
		"""