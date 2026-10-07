"""Self-service login QR (login page generation) tests.

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_qr_self_service
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.api import qr_self_service
from adx_secure_qr_login.secure_qr_login.constants import EVENT_GENERATED
from adx_secure_qr_login.tests import cleanup_test_users, require_companies

# Discovered from the site, not hardcoded -- see `require_companies`.
COMPANY_A = require_companies(1)[0]


def _make_user(email):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "QRSelfSvc",
				"send_welcome_email": 0,
			}
		).insert(ignore_permissions=True)
	doc = frappe.get_doc("User", email)
	doc.flags.ignore_permissions = True
	doc.set("roles", [{"role": "Stock User"}])
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	return doc.name


class TestQRSelfService(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users(
			[
				"qrtest.selfsvc@test.local",
				"qrtest.selfsvc.disabled@test.local",
				"qrtest.selfsvc.nocomp@test.local",
			]
		)
		self.user = _make_user("qrtest.selfsvc@test.local")
		frappe.db.set_value("User", self.user, "company", COMPANY_A)
		# Fresh rate-limit budget for every test (cache survives rollback).
		# NOTE: pass RAW keys -- frappe.cache.delete_value namespaces them
		# internally, so a pre-namespaced key would delete nothing.
		import hashlib

		frappe.cache.delete_value(f"qr_selfsvc:ip:{qr_self_service._request_ip()}")
		frappe.cache.delete_value(
			"qr_selfsvc:em:" + hashlib.sha256(self.user.encode()).hexdigest()[:16]
		)

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users(
			[
				"qrtest.selfsvc@test.local",
				"qrtest.selfsvc.disabled@test.local",
				"qrtest.selfsvc.nocomp@test.local",
			]
		)

	def _request(self, email):
		return qr_self_service.request_login_qr(email)

	# -- enumeration resistance ------------------------------------------

	def test_unknown_disabled_and_companyless_share_one_message(self):
		_nouser = "qrtest.nobody-here@test.local"
		assert not frappe.db.exists("User", _nouser)

		with self.assertRaises(frappe.ValidationError) as a:
			self._request(_nouser)

		_make_user("qrtest.selfsvc.disabled@test.local")
		frappe.db.set_value("User", "qrtest.selfsvc.disabled@test.local", "enabled", 0)
		with self.assertRaises(frappe.ValidationError) as b:
			self._request("qrtest.selfsvc.disabled@test.local")

		_make_user("qrtest.selfsvc.nocomp@test.local")
		frappe.db.set_value("User", "qrtest.selfsvc.nocomp@test.local", "company", None)
		with self.assertRaises(frappe.ValidationError) as c:
			self._request("qrtest.selfsvc.nocomp@test.local")

		# Identical wording: the page cannot be used to probe accounts.
		self.assertEqual(a.exception.args[0], b.exception.args[0])
		self.assertEqual(a.exception.args[0], c.exception.args[0])

	# -- happy path --------------------------------------------------------

	def test_valid_request_returns_svg_and_caches_code(self):
		result = self._request(self.user)
		self.assertIn("<svg", result["svg"])
		self.assertEqual(result["expires_in"], qr_self_service.EXPIRY_SECONDS)

		audit = frappe.get_all(
			"QR Login Audit",
			filters={"event": EVENT_GENERATED, "user": self.user},
			fields=["details", "company"],
			order_by="creation desc",
			limit=1,
		)
		self.assertTrue(audit)
		self.assertIn("self_service", audit[0].details)
		self.assertEqual(audit[0].company, COMPANY_A)

	def test_consume_signs_in_and_redirects(self):
		calls = []
		original = qr_self_service._sign_in_and_redirect
		qr_self_service._sign_in_and_redirect = lambda user: calls.append(user)
		try:
			# Drive consume through a planted code (mint keys are random).
			key = frappe.generate_hash()
			frappe.cache.set_value(
				qr_self_service._cache_key(key),
				self.user,
				expires_in_sec=qr_self_service.EXPIRY_SECONDS,
			)
			qr_self_service.consume_login_qr(key)
			self.assertEqual(calls, [self.user])
		finally:
			qr_self_service._sign_in_and_redirect = original

	def test_consume_unknown_code_rejected(self):
		frappe.cache.delete_value(qr_self_service._cache_key("no-such-key"))
		name = qr_self_service.consume_login_qr("no-such-key")
		self.assertIsNone(name)
		response = frappe.local.response
		self.assertEqual(response.get("http_status_code"), 403)

	# -- abuse resistance -----------------------------------------------------

	def test_email_rate_limit(self):
		for _ in range(qr_self_service.GENERATE_EMAIL_LIMIT):
			try:
				self._request(self.user)
			except frappe.ValidationError:
				pass
		with self.assertRaises(frappe.ValidationError):
			self._request(self.user)

	def test_disabled_when_setting_off(self):
		frappe.db.set_single_value("QR Security Settings", "allow_self_service_qr", 0)
		try:
			with self.assertRaises(frappe.ValidationError):
				self._request(self.user)
		finally:
			frappe.db.set_single_value(
				"QR Security Settings", "allow_self_service_qr", 1
			)

	def test_availability_flag(self):
		# Self-service generation ships disabled by default (it trades enumeration
		# resistance for convenience), so the suite turns it on explicitly rather
		# than assuming the production default.
		frappe.db.set_single_value("QR Security Settings", "allow_self_service_qr", 1)
		try:
			self.assertTrue(qr_self_service.self_service_is_available()["available"])
		finally:
			frappe.db.set_single_value("QR Security Settings", "allow_self_service_qr", 0)
