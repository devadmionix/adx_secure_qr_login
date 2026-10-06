// Secure QR Login -- login page integration.
//
// Adds a "Login with QR" option to the ERPNext login page without modifying any
// Frappe file. Two mechanisms are used:
//
//   * `web_include_js` / `web_include_css` hooks get this file onto every website
//     page (frappe/website/doctype/website_settings/website_settings.py:231,231
//     rendered at templates/base.html:105-107).
//   * The UI is injected into the existing DOM at runtime. login.html is left
//     untouched, so a Frappe upgrade cannot silently shadow it with a stale copy.
//
// The scanner library is loaded straight from Frappe's own node_modules
// (`/assets/frappe/node_modules/html5-qrcode/html5-qrcode.min.js`), the same file
// frappe/public/js/frappe/scanner/index.js uses. It is deliberately not bundled,
// because `frappe.require` is not reliable outside the desk bundle and this runs
// on the pre-auth website context.
//
// Failure messaging is intentionally vague. The server returns one generic
// message for every rejection and this file must not try to be smarter than it,
// or the login page becomes an enumeration oracle.

(function () {
	"use strict";

	var HTML5_QR_SRC = "/assets/frappe/node_modules/html5-qrcode/html5-qrcode.min.js";
	var SCAN_CONFIG = {
		// Camera capture only, not a file picker: a shared terminal should not
		// accept a QR image dragged in from elsewhere.
		fps: 10,
		qrbox: { width: 220, height: 220 },
		aspectRatio: 1.0,
	};

	var scanner = null;
	var scannerLoaded = false;
	var active = false;
	var pendingTmpId = null;
	// Retained so the OTP step can re-submit the same credential instead of
	// asking the user to scan again.
	var lastToken = null;

	// ----------------------------------------------------------------- utils

	function t(key, fallback) {
		if (frappe && frappe._) {
			try {
				return frappe._(key);
			} catch (e) {
				/* fall through */
			}
		}
		return fallback;
	}

	function setStatus(message, kind) {
		var $el = $("#adx_qr_status");
		if (!$el.length) return;
		$el
			.text(message || "")
			.removeClass("is-error is-working")
			.addClass(kind ? "is-" + kind : "");
	}

	function loadScannerLib() {
		if (scannerLoaded) return Promise.resolve();
		if (window.Html5Qrcode) {
			scannerLoaded = true;
			return Promise.resolve();
		}
		return new Promise(function (resolve, reject) {
			var s = document.createElement("script");
			s.src = HTML5_QR_SRC;
			s.async = true;
			s.onload = function () {
				scannerLoaded = true;
				resolve();
			};
			s.onerror = function () {
				reject(new Error("scanner library failed to load"));
			};
			document.head.appendChild(s);
		});
	}

	// -------------------------------------------------------------- template

	function panelHtml() {
		return [
			'<div class="adx-qr-panel" id="adx_qr_panel" hidden>',
			'  <div id="adx_qr_reader" class="adx-qr-reader"></div>',
			'  <div class="adx-qr-status" id="adx_qr_status"></div>',
			'  <div class="adx-qr-otp" id="adx_qr_otp_wrap" hidden>',
			'    <input type="text" id="adx_qr_otp" inputmode="numeric" autocomplete="one-time-code" maxlength="8" placeholder="000000">',
			'    <button class="btn btn-sm btn-primary" id="adx_qr_otp_submit">',
			t("Verify", "Verify"),
			"    </button>",
			"  </div>",
			'  <details class="adx-qr-fallback" id="adx_qr_fallback">',
			"    <summary>",
			t("Enter code manually", "Enter code manually"),
			"    </summary>",
			'    <input type="text" id="adx_qr_manual" class="form-control mt-2"',
			'      placeholder="ADXQR1..." autocomplete="off" spellcheck="false">',
			'    <button class="btn btn-sm btn-default btn-block mt-2" id="adx_qr_manual_submit">',
			t("Sign in", "Sign in"),
			"    </button>",
			"  </details>",
			'  <div class="adx-qr-actions">',
			'    <button class="btn btn-sm btn-default btn-block" id="adx_qr_back">',
			t("Back to sign in", "Back to sign in"),
			"    </button>",
			"  </div>",
			"</div>",
		].join("\n");
	}

	// ------------------------------------------------------------------ scan

	function startScanner() {
		var $reader = $("#adx_qr_reader");
		if (!$reader.length) return;

		// getUserMedia is only available in a secure context. On plain http to a
		// LAN address the camera cannot be opened at all, so say so and rely on
		// the manual field instead of showing an empty box.
		if (!window.isSecureContext && location.hostname !== "localhost" && location.hostname !== "127.0.0.1") {
			$reader.html(
				'<div class="adx-qr-unsupported">' +
					t(
						"Camera scanning needs a secure (https) connection. Use the manual code field below.",
						"Camera scanning needs a secure (https) connection. Use the manual code field below."
					) +
					"</div>"
			);
			return;
		}

		loadScannerLib()
			.then(function () {
				scanner = new window.Html5Qrcode("adx_qr_reader", { verbose: false });
				return scanner.start(
					{ facingMode: "environment" },
					SCAN_CONFIG,
					function (decodedText) {
						if (!active) return;
						onDecoded(decodedText);
					},
					function () {
						/* per-frame decode miss: expected while aiming */
					}
				);
			})
			.catch(function (err) {
				scanner = null;
				$reader.html("");
				var message = String((err && err.message) || err || "");
				if (/NotAllowedError|Permission/i.test(message)) {
					setStatus(
						t(
							"Camera permission was denied. Allow access, or use the manual code field.",
							"Camera permission was denied. Allow access, or use the manual code field."
						),
						"error"
					);
				} else if (/NotFoundError|DevicesNotFound/i.test(message)) {
					setStatus(
						t("No camera was found on this device.", "No camera was found on this device."),
						"error"
					);
				} else {
					setStatus(
						t(
							"The camera could not be started. Use the manual code field below.",
							"The camera could not be started. Use the manual code field below."
						),
						"error"
					);
				}
			});
	}

	function stopScanner() {
		active = false;
		if (!scanner) return;
		try {
			scanner.stop().then(function () {
				scanner.clear();
			});
		} catch (e) {
			/* already stopped */
		}
		scanner = null;
		$("#adx_qr_reader").empty();
	}

	function onDecoded(text) {
		if (!active) return;
		stopScanner();
		lastToken = text;
		setStatus(t("Verifying…", "Verifying…"), "working");
		submit(text);
	}

	// --------------------------------------------------------------- requests

	function submit(token, otp) {
		var args = { qr_token: token };
		if (otp) {
			args.otp = otp;
			args.tmp_id = pendingTmpId;
		}

		frappe
			.call({
				method: "adx_secure_qr_login.api.qr_auth.qr_exchange",
				args: args,
				btn: $("#adx_qr_manual_submit"),
			})
			.then(function (r) {
				handle(r && r.message);
			})
			.catch(function (xhr) {
				// A thrown frappe exception means the server refused outright
				// (rate limit, CSRF, disabled). Show the server's message if it
				// sent one, otherwise stay generic.
				var message = (xhr && xhr.responseJSON && xhr.responseJSON.message) || null;
				showFailure(
					message ||
						t("Could not sign you in. Please try again.", "Could not sign you in. Please try again.")
				);
			});
	}

	function handle(res) {
		if (!res) {
			showFailure(t("Could not sign you in.", "Could not sign you in."));
			return;
		}

		if (res.status === "success") {
			setStatus(t("Signed in. Redirecting…", "Signed in. Redirecting…"), "working");
			window.location.href = res.redirect_to || "/desk";
			return;
		}

		if (res.status === "otp_required") {
			pendingTmpId = res.tmp_id;
			$("#adx_qr_otp_wrap").prop("hidden", false);
			$("#adx_qr_otp").val("").trigger("focus");
			setStatus(
				res.message || t("Enter the code from your authenticator app.", "Enter the verification code."),
				"working"
			);
			return;
		}

		showFailure(res.message || t("Could not sign you in. Please try again.", "Could not sign you in. Please try again."));
	}

	function showFailure(message) {
		pendingTmpId = null;
		$("#adx_qr_otp_wrap").prop("hidden", true);
		setStatus(message, "error");

		// Re-arm so the user can retry without reloading: a new camera start and
		// a cleared manual field.
		$("#adx_qr_manual").val("");
		if (window.isSecureContext || location.hostname === "localhost" || location.hostname === "127.0.0.1") {
			active = true;
			startScanner();
		}
	}

	// ----------------------------------------------------------------- wiring

	function openPanel() {
		var $panel = $("#adx_qr_panel");
		if (!$panel.length) return;

		$("section:visible form.form-login").hide();
		$panel.prop("hidden", false);
		pendingTmpId = null;
		$("#adx_qr_otp_wrap").prop("hidden", true);
		active = true;
		setStatus("", null);
		startScanner();
	}

	function closePanel() {
		stopScanner();
		pendingTmpId = null;
		$("#adx_qr_panel").prop("hidden", true);
		$("section:visible form.form-login").show();
	}

	function bindPanel() {
		$("#adx_qr_back").on("click", function (e) {
			e.preventDefault();
			closePanel();
		});

		$("#adx_qr_manual_submit").on("click", function (e) {
			e.preventDefault();
			var value = ($("#adx_qr_manual").val() || "").trim();
			if (!value) {
				setStatus(t("Enter a code first.", "Enter a code first."), "error");
				return;
			}
			stopScanner();
			lastToken = value;
			setStatus(t("Verifying…", "Verifying…"), "working");
			submit(value);
		});

		$("#adx_qr_manual").on("keydown", function (e) {
			if (e.key === "Enter") {
				e.preventDefault();
				$("#adx_qr_manual_submit").trigger("click");
			}
		});

		$("#adx_qr_otp_submit").on("click", function (e) {
			e.preventDefault();
			var code = ($("#adx_qr_otp").val() || "").trim();
			if (!code) return;
			setStatus(t("Verifying…", "Verifying…"), "working");
			submit(lastToken, code);
		});

		$("#adx_qr_otp").on("keydown", function (e) {
			if (e.key === "Enter") {
				e.preventDefault();
				$("#adx_qr_otp_submit").trigger("click");
			}
		});
	}

	function injectButton() {
		var $actions = $("section:visible .page-card-actions").first();
		if (!$actions.length || $("#adx_qr_option").length) return;

		$actions.append(
			'<a href="#" id="adx_qr_option" class="btn btn-block btn-default btn-sm btn-login-option">' +
				t("Login with QR", "Login with QR") +
				"</a>" +
				panelHtml()
		);

		$("#adx_qr_option").on("click", function (e) {
			e.preventDefault();
			openPanel();
		});

		bindPanel();
	}

	function init() {
		frappe
			.call({
				method: "adx_secure_qr_login.api.qr_auth.qr_is_available",
				type: "GET",
			})
			.then(function (r) {
				var message = (r && r.message) || {};
				if (!message.available) return;
				injectButton();
			})
			.catch(function () {
				// Availability check failed: show nothing rather than a button
				// that cannot work.
			});
	}

	$(function () {
		init();
	});
})();
