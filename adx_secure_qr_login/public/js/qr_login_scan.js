// Secure QR Login -- login page integration.
//
// Adds "Login with QR" and "Generate QR Code" options to the ERPNext login
// page without modifying any Frappe file. Two mechanisms are used:
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
	var cameraOn = false;
	var pendingTmpId = null;
	// Retained so the OTP step can re-submit the same credential instead of
	// asking the user to scan again.
	var lastToken = null;
	var generateTimer = null;

	// ----------------------------------------------------------------- utils

	function t(key, fallback) {
		if (window.frappe && frappe._) {
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
			.removeClass("is-error is-working is-info")
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

	function cardHtml() {
		return [
			'<div class="adx-qr-card" id="adx_qr_card" hidden>',
			'  <a href="#" class="adx-qr-close" id="adx_qr_close">',
			t("Close", "Close"),
			"  </a>",
			'  <h4 class="adx-qr-title">',
			t("Scan your QR credential", "Scan your QR credential"),
			"  </h4>",
			'  <p class="adx-qr-desc">',
			t(
				"No password needed. Point this device's camera at the QR code on your card - or paste your token below.",
				"No password needed. Point this device's camera at the QR code on your card - or paste your token below."
			),
			"  </p>",
			'  <div class="adx-qr-status is-info" id="adx_qr_status">',
			t("Point your camera at the QR code.", "Point your camera at the QR code."),
			"  </div>",
			'  <div id="adx_qr_reader" class="adx-qr-reader"></div>',
			'  <button class="btn btn-dark btn-block mt-2" id="adx_qr_start">',
			t("Start Camera", "Start Camera"),
			"  </button>",
			'  <div class="adx-qr-otp" id="adx_qr_otp_wrap" hidden>',
			'    <input type="text" id="adx_qr_otp" inputmode="numeric" autocomplete="one-time-code" maxlength="8" placeholder="000000">',
			'    <button class="btn btn-sm btn-primary" id="adx_qr_otp_submit">',
			t("Verify", "Verify"),
			"    </button>",
			"  </div>",
			'  <label class="adx-qr-token-label" for="adx_qr_manual">',
			t("Or paste your token", "Or paste your token"),
			"  </label>",
			'  <input type="text" id="adx_qr_manual" class="form-control"',
			'    placeholder="Paste code from email" autocomplete="off" spellcheck="false">',
			'  <button class="btn btn-primary btn-block mt-2" id="adx_qr_manual_submit">',
			t("Sign in with QR", "Sign in with QR"),
			"  </button>",
			'  <details class="adx-qr-generate" id="adx_qr_generate_wrap" hidden>',
			"    <summary>",
			t("Generate a QR code for my email", "Generate a QR code for my email"),
			"    </summary>",
			'    <div id="adx_qr_generate_form">',
			'      <input type="email" id="adx_qr_generate_email" class="form-control mt-2"',
			'        autocomplete="email" spellcheck="false" placeholder="you@example.com">',
			'      <button class="btn btn-sm btn-primary btn-block mt-2" id="adx_qr_generate_submit">',
			t("Generate QR Code", "Generate QR Code"),
			"      </button>",
			"    </div>",
			'    <div id="adx_qr_generate_show" hidden>',
			'      <div id="adx_qr_generate_svg" class="adx-qr-generated-svg"></div>',
			'      <div class="adx-qr-timer">',
			t("Expires in", "Expires in"),
			'        <span id="adx_qr_generate_countdown">5:00</span>',
			"      </div>",
			'      <button class="btn btn-sm btn-default btn-block mt-2" id="adx_qr_generate_again">',
			t("Generate New QR Code", "Generate New QR Code"),
			"      </button>",
			"    </div>",
			"</details>",
			"</div>",
		].join("\n");
	}

	// ------------------------------------------------------------------ scan

	function startScanner() {
		var $reader = $("#adx_qr_reader");
		if (!$reader.length || scanner) return;

		// getUserMedia is only available in a secure context. On plain http to a
		// LAN address the camera cannot be opened at all, so say so and rely on
		// the token field instead of showing an empty box.
		if (!window.isSecureContext && location.hostname !== "localhost" && location.hostname !== "127.0.0.1") {
			$reader.html(
				'<div class="adx-qr-unsupported">' +
					t(
						"Camera scanning needs a secure (https) connection. Use the token field below.",
						"Camera scanning needs a secure (https) connection. Use the token field below."
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
						if (!cameraOn) return;
						onDecoded(decodedText);
					},
					function () {
						/* per-frame decode miss: expected while aiming */
					}
				);
			})
			.then(function () {
				cameraOn = true;
				$("#adx_qr_start").text(t("Stop Camera", "Stop Camera"));
			})
			.catch(function (err) {
				scanner = null;
				cameraOn = false;
				$reader.html("");
				var message = String((err && err.message) || err || "");
				if (/NotAllowedError|Permission/i.test(message)) {
					setStatus(
						t(
							"Camera permission was denied. Allow access, or paste your token below.",
							"Camera permission was denied. Allow access, or paste your token below."
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
							"The camera could not be started. Paste your token below.",
							"The camera could not be started. Paste your token below."
						),
						"error"
					);
				}
			});
	}

	function stopScanner() {
		cameraOn = false;
		$("#adx_qr_start").text(t("Start Camera", "Start Camera"));
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
		if (!cameraOn) return;
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

		// Re-arm the token field for another attempt. The camera restarts only
		// if it was running, so a deliberate stop stays stopped.
		$("#adx_qr_manual").val("");
		if (cameraOn) {
			stopScanner();
			startScanner();
		}
	}

	// ------------------------------------------------------------- generate

	function stopGenerateTimer() {
		if (generateTimer) {
			clearInterval(generateTimer);
			generateTimer = null;
		}
	}

	function showGenerateForm() {
		stopGenerateTimer();
		$("#adx_qr_generate_show").prop("hidden", true);
		$("#adx_qr_generate_form").show();
	}

	function requestGenerateQr() {
		var email = ($("#adx_qr_generate_email").val() || "").trim();
		if (!email) {
			setStatus(t("Enter your email first.", "Enter your email first."), "error");
			return;
		}
		var $btn = $("#adx_qr_generate_submit");
		setStatus(t("Generating…", "Generating…"), "working");

		frappe
			.call({
				method: "adx_secure_qr_login.api.qr_self_service.request_login_qr",
				args: { email: email },
				btn: $btn,
			})
			.then(function (r) {
				var message = (r && r.message) || {};
				if (!message.svg) {
					setStatus(
						t("Unable to generate QR code. Please check your email address.", "Unable to generate QR code. Please check your email address."),
						"error"
					);
					return;
				}
				$("#adx_qr_generate_form").hide();
				$("#adx_qr_generate_svg").html(message.svg);
				$("#adx_qr_generate_show").prop("hidden", false);
				setStatus(
					t("Scan this code with your phone to sign in.", "Scan this code with your phone to sign in."),
					"working"
				);
				var remaining = message.expires_in || 300;
				var $countdown = $("#adx_qr_generate_countdown");
				stopGenerateTimer();
				generateTimer = setInterval(function () {
					remaining -= 1;
					if (remaining <= 0) {
						stopGenerateTimer();
						showGenerateForm();
						setStatus(
							t("That code expired. Generate a new one.", "That code expired. Generate a new one."),
							"error"
						);
						return;
					}
					var m = Math.floor(remaining / 60);
					var s = ("0" + (remaining % 60)).slice(-2);
					$countdown.text(m + ":" + s);
				}, 1000);
			})
			.catch(function () {
				// Same generic message for every failure: the login page must
				// not reveal whether an address exists.
				setStatus(
					t("Unable to generate QR code. Please check your email address.", "Unable to generate QR code. Please check your email address."),
					"error"
				);
			});
	}

	// ----------------------------------------------------------------- wiring

	function scrollToCard() {
		var $card = $("#adx_qr_card");
		$card.prop("hidden", false);
		var el = document.getElementById("adx_qr_card");
		if (el && el.scrollIntoView) {
			el.scrollIntoView({ behavior: "smooth", block: "start" });
		}
	}

	function closeCard() {
		stopScanner();
		stopGenerateTimer();
		pendingTmpId = null;
		$("#adx_qr_otp_wrap").prop("hidden", true);
		$("#adx_qr_card").prop("hidden", true);
		setStatus("", null);
	}

	function bindCard() {
		$("#adx_qr_close").on("click", function (e) {
			e.preventDefault();
			closeCard();
		});

		$("#adx_qr_start").on("click", function (e) {
			e.preventDefault();
			if (scanner || cameraOn) {
				stopScanner();
				setStatus(
					t("Point your camera at the QR code.", "Point your camera at the QR code."),
					"info"
				);
				return;
			}
			setStatus(t("Starting camera…", "Starting camera…"), "working");
			startScanner();
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

		$("#adx_qr_generate_submit").on("click", function (e) {
			e.preventDefault();
			requestGenerateQr();
		});

		$("#adx_qr_generate_email").on("keydown", function (e) {
			if (e.key === "Enter") {
				e.preventDefault();
				requestGenerateQr();
			}
		});

		$("#adx_qr_generate_again").on("click", function (e) {
			e.preventDefault();
			showGenerateForm();
			setStatus("", null);
		});
	}

	function injectButtons() {
		var $actions = $("section:visible .page-card-actions").first();
		if (!$actions.length || $("#adx_qr_option").length) return;

		$actions.append(
			'<a href="#" id="adx_qr_option" class="btn btn-block btn-default btn-sm btn-login-option">' +
				t("Login with QR", "Login with QR") +
				"</a>" +
				'<a href="#" id="adx_qr_generate_option" class="btn btn-block btn-default btn-sm btn-login-option">' +
				t("Generate QR Code", "Generate QR Code") +
				"</a>"
		);

		// The scan card lives below the buttons. The email-based generator
		// sits inside the card as an expandable section.
		$actions.after(cardHtml());

		$("#adx_qr_option").on("click", function (e) {
			e.preventDefault();
			scrollToCard();
			$("#adx_qr_manual").trigger("focus");
		});

		$("#adx_qr_generate_option").on("click", function (e) {
			e.preventDefault();
			scrollToCard();
			$("#adx_qr_generate_wrap").prop("open", true);
			var $email = $("#adx_qr_generate_email");
			var preset = $("section:visible #login_email").val() || "";
			if (!$email.val() && preset) $email.val(preset);
			$email.trigger("focus");
		});

		updateGenerateVisibility();
		bindCard();
	}

	// Show the in-card generator only when self-service is enabled.
	function updateGenerateVisibility() {
		frappe
			.call({
				method: "adx_secure_qr_login.api.qr_self_service.self_service_is_available",
				type: "GET",
			})
			.then(function (g) {
				var on = !!(g && g.message && g.message.available);
				$("#adx_qr_generate_option").toggle(on);
				$("#adx_qr_generate_wrap").prop("hidden", !on);
			})
			.catch(function () {
				$("#adx_qr_generate_option").hide();
				$("#adx_qr_generate_wrap").prop("hidden", true);
			});
	}

	// A QR scanned by any generic camera (phone, Lens) opens
	// {base}/login?qr=<payload>. Auto-submit it over POST, then strip it
	// from history so the bearer token does not linger in the URL bar.
	function consumeQrParam() {
		var params;
		try {
			params = new URLSearchParams(window.location.search);
		} catch (e) {
			return;
		}
		var code = (params.get("qr") || "").trim();
		if (!code) return;
		try {
			var url = window.location.pathname + window.location.hash;
			window.history.replaceState(null, document.title, url);
		} catch (e) {
			/* history unavailable: the code still works, just stays visible */
		}
		scrollToCard();
		lastToken = code;
		setStatus(t("Verifying…", "Verifying…"), "working");
		submit(code);
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
				injectButtons();
				consumeQrParam();
			})
			.catch(function () {
				// Availability check failed: show nothing rather than buttons
				// that cannot work.
			});
	}

	$(function () {
		init();
	});
})();
