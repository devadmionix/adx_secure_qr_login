# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Sign in from a scanned QR on the server, so the login page never renders.

A QR scanned by a phone camera opens ``{base}/login?qr=<payload>``. Handled purely
client-side, the browser must first download and render the entire login page,
then run ``consumeQrParam()`` to POST the token, then follow the redirect -- so
the user watches the login form flash up before the desk appears.

This handles the request server-side instead, as a custom page renderer
registered on the ``page_renderer`` hook. Three outcomes, deliberately different:

* **success** -- the session is created and a redirect to the default path is
  raised. The login page is never rendered.
* **``otp_required``** -- delegates to the ordinary ``TemplatePage`` so the
  existing client-side OTP prompt still works. ``qr_exchange`` mints a challenge
  without recording a credential failure, and the client re-submitting only mints
  a second challenge, so nothing is double-counted.
* **failure** -- redirects to a clean ``/login``, dropping the token.

Why a renderer rather than a ``before_request`` hook: ``before_request`` runs
inside ``frappe.app.init_request``, which sits *outside* the website renderer's
exception handling. A redirect there has to be expressed as
``frappe.local.response["type"] = "redirect"``, but
``frappe.website.utils.build_response`` -- the function the page renderers
actually call -- ignores that key entirely, so the page renders as HTTP 200 and
the redirect is silently dropped. And raising ``frappe.Redirect`` is not an
option there either: it is a plain ``Exception``
(``frappe/exceptions.py:76``), so it would reach ``frappe.app.handle_exception``
and render a 500 error page.

``page_renderer`` handlers are invoked from ``PathResolver.resolve`` -> ``render``
(``frappe/website/path_resolver.py:70-84``), which runs *inside*
``frappe.website.serve.get_response``. That is the frame where
``handle_exception`` maps ``frappe.Redirect`` onto ``RedirectPage``, i.e. a real
HTTP redirect. Custom renderers are also tried before ``TemplatePage``, so this
one can take over the request and defer explicitly.

Why the failure path redirects rather than falling through: a rejection
increments ``failed_attempts`` on the credential row
(``validation.register_credential_failure``) and the lockout default is 5
attempts. Letting the client re-POST the same rejected token would burn two
attempts per bad scan and lock a credential out at roughly half the intended
threshold. Dropping the token also keeps it out of browser history, which the
client-side path had to work around with ``history.replaceState``. The cost is
that the generic failure message is not shown -- the user lands on the normal
login page and rescans, which matches the module's stance that failure messaging
is deliberately uninformative.
"""

import frappe
from frappe.website.page_renderers.base_renderer import BaseRenderer
from frappe.website.page_renderers.template_page import TemplatePage

LOGIN_PATH = "login"
CLEAN_LOGIN = "/login"


class QrFastLoginPage(BaseRenderer):
	"""Takes over ``/login?qr=<token>`` only; every other path defers."""

	def can_render(self) -> bool:
		if self.path != LOGIN_PATH:
			return False

		if frappe.request is None or frappe.request.method != "GET":
			return False

		# Already signed in: defer, so a signed-in user merely visiting /login is
		# not logged in again and no credential is consumed.
		if frappe.session.user not in ("", "Guest"):
			return False

		return bool(self._token())

	def render(self):
		token = self._token()

		from adx_secure_qr_login.api.qr_auth import qr_exchange

		try:
			result = qr_exchange(qr_token=token) or {}
		except Exception:
			# A whitelisted call can still raise (CSRF, permission, a defect).
			# The ordinary login page still works, so log and defer rather than
			# hand the user an error page.
			frappe.log_error(
				title="QR fast login failed", message=frappe.get_traceback()
			)
			return self._render_login_page()

		status = result.get("status")

		if status == "success":
			self._redirect(result.get("redirect_to") or "/desk")

		if status == "otp_required":
			# Two-factor is required; the client needs the page to collect the code.
			return self._render_login_page()

		# Rejected. Redirect to a clean login so the token is not resubmitted and
		# the failure is not counted twice.
		self._redirect(CLEAN_LOGIN)

	def _render_login_page(self):
		"""Hand the request back to the stock login renderer."""
		return TemplatePage(LOGIN_PATH, self.http_status_code).render()

	def _redirect(self, location: str):
		"""Emit a real HTTP redirect.

		``RedirectPage`` reads ``frappe.flags.redirect_location`` first and falls
		back to ``frappe.local.response["location"]``
		(``frappe/website/page_renderers/redirect_page.py:19``). The latter is set
		here because ``frappe.flags.redirect_location`` is shared state that other
		redirect handling in the same request may already have claimed.
		"""
		frappe.local.response["location"] = location
		raise frappe.Redirect

	def _token(self) -> str:
		# `make_form_dict` runs before page resolution, so the query string is
		# already parsed. Read the raw args as a fallback for the odd path where
		# it is not.
		token = frappe.form_dict.get("qr")
		if not token and frappe.request is not None:
			token = (frappe.request.args.get("qr") or "")
		return (token or "").strip()