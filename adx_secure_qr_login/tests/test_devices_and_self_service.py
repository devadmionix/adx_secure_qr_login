"""Devices & Sessions actions and My QR self-service.

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_devices_and_self_service
"""

import json
from unittest import mock

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.tests import cleanup_test_users, require_companies, site_companies

COMPANY = (site_companies() or [None])[0]
ADMIN = "qrtest.dev.admin@test.local"
MANAGER_A = "qrtest.dev.mgr_a@test.local"
OWNER = "qrtest.dev.owner@test.local"
OTHER = "qrtest.dev.other@test.local"
ALL = [ADMIN, MANAGER_A, OWNER, OTHER]


def _make_user(email, roles=("Stock User",), company=COMPANY):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{"doctype": "User", "email": email, "first_name": "DevSS", "send_welcome_email": 0}
		).insert(ignore_permissions=True)
	doc = frappe.get_doc("User", email)
	doc.set("roles", [{"role": r} for r in roles])
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	frappe.db.set_value("User", email, "company", company)
	return email


def _device(user, device_id="dev-1", company=COMPANY, **kw):
	doc = frappe.get_doc(
		{
			"doctype": "QR Login Device",
			"device_id": device_id,
			"device_name": "Test device",
			"user": user,
			"company": company,
			**kw,
		}
	)
	doc.insert(ignore_permissions=True)
	frappe.db.commit()
	return doc.name


def _events(user, event):
	return frappe.get_all(
		"QR Login Audit", filters={"user": user, "event": event}, pluck="name"
	)


class _Base(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users(ALL)
		_make_user(ADMIN, roles=("Stock User", "QR Admin"))
		_make_user(OWNER)
		_make_user(OTHER)
		frappe.db.commit()

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.set_single_value("QR Security Settings", "allow_self_generate_qr", 0)
		frappe.db.set_single_value("QR Security Settings", "allow_self_revoke_qr", 0)
		frappe.db.set_single_value("QR Security Settings", "device_verification", "log_only")
		frappe.db.commit()
		cleanup_test_users(ALL)


class TestDeviceActions(_Base):
	def test_trust_and_untrust_are_audited(self):
		from adx_secure_qr_login.api import qr_device

		device = _device(OWNER)
		frappe.set_user(ADMIN)

		self.assertTrue(qr_device.trust_device(device)["trusted"])
		self.assertEqual(frappe.db.get_value("QR Login Device", device, "trusted"), 1)
		self.assertTrue(_events(OWNER, "Device Trusted"))

		self.assertFalse(qr_device.untrust_device(device)["trusted"])
		self.assertEqual(frappe.db.get_value("QR Login Device", device, "trusted"), 0)
		self.assertTrue(_events(OWNER, "Device Untrusted"))

	def test_revoke_marks_device_ends_sessions_and_audits(self):
		from adx_secure_qr_login.api import qr_device

		device = _device(OWNER)
		frappe.set_user(ADMIN)

		with mock.patch(
			"adx_secure_qr_login.security.session_guard.terminate_user_sessions",
			return_value=2,
		) as terminate:
			res = qr_device.revoke_device(device)

		terminate.assert_called_once()
		self.assertEqual(terminate.call_args.args[0], OWNER)
		self.assertEqual(res["sessions_terminated"], 2)
		row = frappe.db.get_value(
			"QR Login Device", device, ["revoked", "revoked_by"], as_dict=True
		)
		self.assertEqual(row.revoked, 1)
		self.assertEqual(row.revoked_by, ADMIN)
		self.assertTrue(_events(OWNER, "Device Revoked"))
		self.assertTrue(_events(OWNER, "Session Revoked"))

	def test_revoked_device_cannot_be_trusted_or_revoked_twice(self):
		from adx_secure_qr_login.api import qr_device

		device = _device(OWNER)
		frappe.set_user(ADMIN)
		with mock.patch(
			"adx_secure_qr_login.security.session_guard.terminate_user_sessions",
			return_value=0,
		):
			qr_device.revoke_device(device)
			with self.assertRaises(frappe.ValidationError):
				qr_device.revoke_device(device)
		with self.assertRaises(frappe.ValidationError):
			qr_device.trust_device(device)

	def test_plain_user_cannot_trust_untrust_or_revoke(self):
		from adx_secure_qr_login.api import qr_device

		device = _device(OWNER)
		frappe.set_user(OWNER)
		for fn in (qr_device.trust_device, qr_device.untrust_device, qr_device.revoke_device):
			with self.subTest(fn=fn.__name__):
				with self.assertRaises(frappe.PermissionError):
					fn(device)

	def test_manager_cannot_trust_other_company_device(self):
		company_a, company_b = require_companies(2)[:2]
		_make_user(MANAGER_A, roles=("Stock User", "QR Manager"), company=company_a)
		_make_user(OTHER, company=company_b)
		# Company User Permissions are what scope a user in ERPNext; the QR layer
		# reads them. A user with none is treated as unrestricted.
		for who, company in ((MANAGER_A, company_a), (OTHER, company_b)):
			frappe.get_doc(
				{
					"doctype": "User Permission",
					"user": who,
					"allow": "Company",
					"for_value": company,
					"apply_to_all_doctypes": 1,
				}
			).insert(ignore_permissions=True)
		device = _device(OTHER, "dev-b", company=company_b)

		from adx_secure_qr_login.api import qr_device

		frappe.set_user(MANAGER_A)
		for fn in (qr_device.trust_device, qr_device.revoke_device):
			with self.subTest(fn=fn.__name__):
				with self.assertRaises(frappe.PermissionError):
					fn(device)
		frappe.db.sql("delete from `tabUser Permission` where user in (%s, %s)", (MANAGER_A, OTHER))
		frappe.db.commit()

	def test_policy_refuses_revoked_device_only_in_require_trusted(self):
		from adx_secure_qr_login.security import devices

		device = _device(OWNER, "dev-policy")
		frappe.db.set_value("QR Login Device", device, "revoked", 1)
		frappe.db.set_single_value("QR Security Settings", "device_verification", "log_only")
		self.assertTrue(devices.is_trusted_for(OWNER, "dev-policy"))

		frappe.db.set_single_value("QR Security Settings", "device_verification", "require_trusted")
		self.assertFalse(devices.is_trusted_for(OWNER, "dev-policy"))
		self.assertTrue(devices.is_trusted_for(OWNER, "never-seen"))


class TestMyQR(_Base):
	def _enable(self, generate=0, revoke=0):
		frappe.db.set_single_value("QR Security Settings", "allow_self_generate_qr", generate)
		frappe.db.set_single_value("QR Security Settings", "allow_self_revoke_qr", revoke)
		frappe.db.commit()

	def test_generate_refused_when_setting_off(self):
		from adx_secure_qr_login.api import qr_my

		self._enable(generate=0)
		frappe.set_user(OWNER)
		with self.assertRaises(frappe.PermissionError):
			qr_my.generate_my_qr()
		frappe.set_user("Administrator")
		self.assertEqual(frappe.db.count("QR Login Credential", {"user": OWNER}), 0)

	def test_generate_for_self_has_no_token_and_is_audited(self):
		from adx_secure_qr_login.api import qr_my

		self._enable(generate=1)
		frappe.set_user(OWNER)
		res = qr_my.generate_my_qr()

		self.assertNotIn("one_time_token", res)
		self.assertNotIn("token_hash", json.dumps(res))
		doc = frappe.get_doc("QR Login Credential", res["credential"])
		self.assertEqual(doc.user, OWNER)
		audit = frappe.get_all(
			"QR Login Audit", filters={"credential": res["credential"]}, fields=["details"]
		)
		self.assertTrue(audit)
		self.assertIn("self_service", json.dumps([a.details for a in audit]))

	def test_summary_is_only_own_data_and_secret_free(self):
		from adx_secure_qr_login.api import qr_manage, qr_my

		frappe.set_user("Administrator")
		qr_manage.generate_credential(OTHER)
		self._enable(generate=1, revoke=1)

		frappe.set_user(OWNER)
		qr_my.generate_my_qr()
		data = qr_my.get_my_qr()

		self.assertEqual(data["user"], OWNER)
		self.assertTrue(data["active"])
		self.assertTrue(data["can_revoke"])
		self.assertEqual(
			{c["name"] for c in data["credentials"]},
			set(frappe.get_all("QR Login Credential", filters={"user": OWNER}, pluck="name")),
		)
		blob = json.dumps(data, default=str).lower()
		for forbidden in ("token_hash", "one_time", "payload", "secret"):
			self.assertNotIn(forbidden, blob)

	def test_cannot_revoke_someone_elses_qr(self):
		from adx_secure_qr_login.api import qr_manage, qr_my

		frappe.set_user("Administrator")
		other_cred = qr_manage.generate_credential(OTHER)["credential"]
		self._enable(revoke=1)

		frappe.set_user(OWNER)
		with self.assertRaises(frappe.PermissionError):
			qr_my.revoke_my_qr(other_cred)
		self.assertEqual(
			frappe.db.get_value("QR Login Credential", other_cred, "status"), "Active"
		)

	def test_revoke_refused_when_setting_off_and_works_when_on(self):
		from adx_secure_qr_login.api import qr_manage, qr_my

		frappe.set_user("Administrator")
		cred = qr_manage.generate_credential(OWNER)["credential"]

		self._enable(revoke=0)
		frappe.set_user(OWNER)
		with self.assertRaises(frappe.PermissionError):
			qr_my.revoke_my_qr(cred)

		frappe.set_user("Administrator")
		self._enable(revoke=1)
		frappe.set_user(OWNER)
		with mock.patch(
			"adx_secure_qr_login.security.session_guard.terminate_user_sessions", return_value=0
		):
			res = qr_my.revoke_my_qr(cred)
		self.assertEqual(res["status"], "Revoked")

	def test_guest_is_refused(self):
		from adx_secure_qr_login.api import qr_my

		frappe.set_user("Guest")
		for fn in (qr_my.get_my_qr, qr_my.generate_my_qr):
			with self.assertRaises(frappe.PermissionError):
				fn()
