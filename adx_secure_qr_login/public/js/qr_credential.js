// Credential form actions: download QR, print, regenerate, revoke.
//
// The plaintext token is only ever available in the response that mints a
// credential, so download/print work from either that response or the stored QR
// image. Nothing here ever renders `token_hash`, and the field is hidden server
// side regardless.

frappe.provide("adx.qr_credential");

adx.qr_credential = {
	/** Download the QR shown in the current form, as PNG. */
	download: function (frm) {
		const name = frm.doc.name;
		if (!name) return;

		frappe
			.call({
				method: "adx_secure_qr_login.api.qr_manage.get_qr_data_uri",
				args: { credential: name },
			})
			.then((r) => {
				const uri = (r && r.message) || null;
				if (!uri) {
					frappe.show_alert({
						message: __("No QR image is available for this credential."),
						indicator: "orange",
					});
					return;
				}
				const stamp = (frm.doc.token_prefix || "qr").replace(/[^A-Za-z0-9_-]/g, "");
				const a = document.createElement("a");
				// Filename carries only the non-secret prefix and the subject's
				// local part, never the token or the credential docname.
				a.href = uri;
				a.download = `qr-login-${stamp}.png`;
				document.body.appendChild(a);
				a.click();
				document.body.removeChild(a);
			});
	},

	/** Open the print view for the card print format. */
	print: function (frm) {
		if (!frm.doc.name) return;
		const url = `/printview?doctype=${encodeURIComponent("QR Login Credential")}` +
			`&name=${encodeURIComponent(frm.doc.name)}` +
			`&format=${encodeURIComponent("QR Login Credential Card")}` +
			"&no_letterhead=1&trigger_print=1";
		window.open(url, "_blank", "noopener");
	},

	regenerate(frm) {
		frappe.confirm(
			__("The current QR will stop working immediately. Continue?"),
			() => {
				frappe.call({
					method: "adx_secure_qr_login.api.qr_manage.regenerate_credential",
					args: { credential: frm.doc.name },
					btn: frm.page.wrapper.find(".qr-regenerate"),
				}).then((r) => {
					const msg = (r && r.message) || null;
					if (!msg || !msg.one_time_token) return;
					adx.qr_credential.showOnce(msg, frm);
					frm.reload_doc();
				});
			}
		);
	},

	revoke(frm) {
		frappe.prompt(
			[
				{
					fieldname: "reason",
					label: __("Reason"),
					fieldtype: "Small Text",
					reqd: 1,
				},
			],
			(values) => {
				frappe.call({
					method: "adx_secure_qr_login.api.qr_manage.revoke_credential",
					args: { credential: frm.doc.name, reason: values.reason },
				}).then(() => {
					frappe.show_alert({ message: __("Credential revoked."), indicator: "green" });
					frm.reload_doc();
				});
			},
			__("Revoke credential"),
			__("Revoke")
		);
	},

	/**
	 * Render the one-time token and its QR, with an explicit warning.
	 *
	 * Deliberately not written to the clipboard automatically and not stored: the
	 * server keeps only a hash, so this is the single opportunity to save it.
	 */
	showOnce(payload) {
		const html = `
			<div class="qr-preview">
				${payload.qr_svg || ""}
			</div>
			<div class="qr-once-notice">
				<strong>${frappe._("Shown once.")}</strong><br>
				${frappe._("Download or print this QR now. It cannot be displayed again.")}
			</div>
			<div style="margin-top:10px">
				<button class="btn btn-sm btn-primary" id="qr_dl_once">
					${frappe._("Download QR")}
				</button>
				<button class="btn btn-sm btn-default" id="qr_copy_hint">
					${frappe._("Copy code instead")}
				</button>
			</div>
			<div id="qr_manual_code" style="display:none;margin-top:10px">
				<code style="font-size:11px;word-break:break-all">${
					frappe.utils.escape_html(payload.one_time_token || "")
				}</code>
			</div>`;

		const d = new frappe.ui.Dialog({
			title: frappe.__("QR credential ready"),
			fields: [{ fieldtype: "HTML", fieldname: "body" }],
			primary_action_label: frappe._("Done"),
			primary_action: () => d.hide(),
		});

		d.fields.get_field("body").$wrapper.html(html);
		d.show();

		d.$wrapper.find("#qr_dl_once").on("click", () => {
			const a = document.createElement("a");
			a.href = payload.qr_svg;
			a.download = `qr-login-${(payload.token_prefix || "qr").replace(
				/[^A-Za-z0-9_-]/g,
				""
			)}.svg`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
		});

		d.$wrapper.find("#qr_copy_hint").on("click", function () {
			$("#qr_manual_code").toggle();
		});
	},
};

frappe.ui.form.on("QR Login Credential", {
	refresh(frm) {
		if (frm.is_new()) return;

		const status = frm.doc.status;
		const actions = [];

		if (status === "Active") {
			actions.push(
				`<button class="btn btn-sm btn-default qr-download">${frappe._("Download QR")}</button>`,
				`<button class="btn btn-sm btn-default qr-print">${frappe._("Print QR")}</button>`,
				`<button class="btn btn-sm btn-warning qr-regenerate">${frappe._("Regenerate")}</button>`,
				`<button class="btn btn-sm btn-danger qr-revoke">${frappe._("Revoke")}</button>`
			);
		} else {
			// Expired / Revoked / Superseded cards carry no scannable image, so
			// download and print are hidden rather than offered and failing.
			actions.push(
				`<span class="text-muted" style="font-size:12px">${frappe._(
					"No QR is issued for a {0} credential.",
					[frappe._(String(status).toLowerCase())]
				)}</span>`
			);
		}

		frm.add_custom_button(
			frappe._("Download QR"),
			() => adx.qr_credential.download(frm),
			"QR"
		);
		frm.add_custom_button(frappe._("Print QR"), () => adx.qr_credential.print(frm), "QR");
		if (status === "Active" || status === "Expired") {
			frm.add_custom_button(
				frappe._("Regenerate"),
				() => adx.qr_credential.regenerate(frm),
				"QR"
			);
		}
		if (status !== "Revoked") {
			frm.add_custom_button(
				frappe._("Revoke"),
				() => adx.qr_credential.revoke(frm),
				"QR"
			);
		}

		frm.dashboard.clear_headline();
		frm.dashboard.set_headline_alert(
			`<div class="qr-credential-actions">${actions.join(" ")}</div>`
		);

		frm.page.wrapper.find(".qr-download").on("click", () =>
			adx.qr_credential.download(frm)
		);
		frm.page.wrapper.find(".qr-print").on("click", () =>
			adx.qr_credential.print(frm)
		);
		frm.page.wrapper.find(".qr-regenerate").on("click", () =>
			adx.qr_credential.regenerate(frm)
		);
		frm.page.wrapper.find(".qr-revoke").on("click", () =>
			adx.qr_credential.revoke(frm)
		);
	},
});
