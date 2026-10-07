# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Device management API for QR Login.

Provides endpoints for listing, viewing, and revoking devices.
Device management respects company isolation:
- Company A administrators cannot manage Company B devices.
- QR Managers can only manage devices for users in their company scope.
"""

import frappe

from adx_secure_qr_login.security import devices, rbac


@frappe.whitelist()
def list_devices(user: str | None = None) -> list[dict]:
	"""List devices, optionally filtered by user.

	Scoping is enforced by the device-view rule, then filtered to the single
	requested user so a Manager cannot use this to enumerate the whole estate.
	"""
	if user:
		rbac.assert_can_view_user(user)
		filters = {"user": user}
	else:
		filters = {}

	devices = frappe.get_all(
		"QR Login Device",
		filters=filters,
		fields=[
			"name",
			"device_id",
			"device_name",
			"user",
			"company",
			"browser",
			"operating_system",
			"ip_address",
			"trusted",
			"revoked",
			"first_seen",
			"last_seen",
		],
		order_by="last_seen desc",
		limit_page_length=100,
	)

	return devices


@frappe.whitelist()
def get_device(device: str) -> dict:
	"""Get a single device by name."""
	rbac.assert_can_view_device(device)

	doc = frappe.get_doc("QR Login Device", device)
	return {
		"name": doc.name,
		"device_id": doc.device_id,
		"device_name": doc.device_name,
		"user": doc.user,
		"company": doc.company,
		"browser": doc.browser,
		"operating_system": doc.operating_system,
		"ip_address": doc.ip_address,
		"trusted": doc.trusted,
		"revoked": doc.revoked,
		"first_seen": doc.first_seen,
		"last_seen": doc.last_seen,
	}


@frappe.whitelist()
def revoke_device(device: str) -> dict:
	"""Revoke a device.

	Only QR Admin or QR Manager can revoke devices. QR Managers can only
	revoke devices for users in their company scope.
	"""
	rbac.assert_can_manage_device(device, "revoke_device")

	if frappe.db.get_value("QR Login Device", device, "revoked"):
		frappe.throw(
			frappe._("This device is already revoked."),
			frappe.ValidationError,
		)

	# The mutation and its audit row live in `security.devices` so the desk form
	# and this endpoint cannot diverge in what they write.
	devices.revoke_device(device)
	frappe.db.commit()

	return {"device": device, "status": "revoked"}


@frappe.whitelist()
def trust_device(device: str) -> dict:
	"""Mark a device as trusted."""
	rbac.assert_can_manage_device(device, "trust_device")

	doc = frappe.get_doc("QR Login Device", device)
	doc.trusted = 1
	doc.save(ignore_permissions=True)

	frappe.db.commit()

	return {"device": device, "trusted": True}


@frappe.whitelist()
def untrust_device(device: str) -> dict:
	"""Remove trusted status from a device."""
	rbac.assert_can_manage_device(device, "untrust_device")

	doc = frappe.get_doc("QR Login Device", device)
	doc.trusted = 0
	doc.save(ignore_permissions=True)

	frappe.db.commit()

	return {"device": device, "trusted": False}
