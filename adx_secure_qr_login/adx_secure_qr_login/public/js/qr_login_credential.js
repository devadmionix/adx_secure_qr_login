// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// QR Login Credential form: Resend/Revoke/Regenerate actions, download
// buttons, print card and the stored QR rendered inline.
//
// The image comes from `qr_manage.get_qr_data_uri` / `download_qr_image`,
// which enforce the same read/self-download rules as the credential itself.
// This script never touches token material, only the printable PNG/SVG.
//
// UI restrictions: admin-only buttons (Regenerate, Revoke, Email) are hidden
// from normal users. The server-side checks will still deny these actions
// even if the buttons were shown, but the UI should reflect the user's role.

frappe.ui.form.on("QR Login Credential", {
	refresh(frm) {
		if (frm.is_new()) {
			const field = frm.fields_dict.qr_code_display;
			if (field) {
				field.$wrapper.html(
					`<div class="text-muted">${__(
						"Save this credential to view its QR code."
					)}</div>`
				);
			}
			return;
		}

		const field = frm.fields_dict.qr_code_display;
		if (!field) return;

		const badge = (value, current) =>
			`<span style="display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;margin:0 2px;background:${
				value === current ? "#4f2cc9" : "#f1f1f1"
			};color:${value === current ? "#fff" : "#888"};">${value}</span>`;

		const status = frm.doc.status || "Active";
		const statusChips = ["Active", "Revoked", "Expired"]
			.map((v) => badge(v, status))
			.join("");

		// Determine which actions the current user may perform.
		// Normal users (Desk User without QR Login Admin/Manager role) may only
		// view, download, and print their own credential. Admin buttons are hidden.
		const isManager = frappe.user_roles.includes("QR Login Admin") ||
			frappe.user_roles.includes("QR Login Manager");
		const canDownload = frappe.user_roles.includes("QR Login Admin") ||
			frappe.user_roles.includes("QR Login Manager") ||
			frappe.boot.qr_self_download_allowed;

		field.$wrapper.html(`
		<div class="adx-qr-actions" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;">
			${isManager ? `<button type="button" class="btn btn-sm btn-primary" data-adx-action="regenerate">${__("Regenerate")}</button>
			<button type="button" class="btn btn-sm btn-danger" data-adx-action="revoke">${__("Revoke")}</button>` : ""}
			${canDownload ? `<button type="button" class="btn btn-sm btn-default" data-adx-action="download-svg">${__("Download SVG")}</button>
			<button type="button" class="btn btn-sm btn-default" data-adx-action="download-png">${__("Download PNG")}</button>
			<button type="button" class="btn btn-sm btn-default" data-adx-action="print">${__("Print Card")}</button>` : ""}
			${isManager ? `<button type="button" class="btn btn-sm btn-default" data-adx-action="email">${__("Email QR")}</button>` : ""}
		</div>
		<div class="adx-qr-chips" style="display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px;">
			<div>${statusChips}</div>
			<div class="adx-qr-mail-chips">
				${["Not Sent", "Queued", "Sent", "Failed"].map((v) => badge(v, "…")).join("")}
			</div>
		</div>
		<div class="adx-qr-media" style="text-align:center;margin-bottom:12px;">
			<div style="display:inline-block;border:1px solid #e2e2e2;border-radius:8px;padding:12px;background:#ffffff;">
				<span class="text-muted">${__("Loading QR code…")}</span>
			</div>
		</div>`);

		// Button wiring (all endpoints re-validate authorization server-side).
		field.$wrapper.find("[data-adx-action]").each(function () {
			$(this).on("click", function (e) {
				e.preventDefault();
				const action = $(this).attr("data-adx-action");
				if (action === "regenerate") {
					frappe.confirm(
						__("Mint a new QR credential? The previous token stops working immediately."),
						() => {
							frappe
								.call({
									method: "adx_secure_qr_login.api.qr_manage.regenerate_credential",
									args: { credential: frm.doc.name },
								})
								.then((r) => {
									if (r && r.message && r.message.credential) {
										frappe.set_route("Form", "QR Login Credential", r.message.credential);
									}
								});
						}
					);
				} else if (action === "revoke") {
					frappe.prompt(
						[
							{fieldname: "reason", fieldtype: "Data", label: __("Reason"), reqd: 1},
						],
						(values) => {
							frappe
								.call({
									method: "adx_secure_qr_login.api.qr_manage.revoke_credential",
									args: { credential: frm.doc.name, reason: values.reason },
								})
								.then(() => frm.reload_doc());
						},
						__("Revoke Credential")
					);
				} else if (action === "download-svg") {
					window.location.href = `/api/method/adx_secure_qr_login.api.qr_manage.download_qr_svg?credential=${encodeURIComponent(frm.doc.name)}`;
				} else if (action === "download-png") {
					window.location.href = `/api/method/adx_secure_qr_login.api.qr_manage.download_qr_image?credential=${encodeURIComponent(frm.doc.name)}`;
				} else if (action === "print") {
					frappe.utils.print(
						frm.doctype,
						frm.doc.name,
						"QR Login Credential Card",
						null,
						null
					);
				} else if (action === "email") {
					frappe.confirm(
						__("Re-send the welcome email with this credential's QR code? No new credential will be created."),
						() => {
							frappe
								.call({
									method: "adx_secure_qr_login.api.qr_manage.resend_welcome_email",
									args: { credential: frm.doc.name },
								})
								.then((r) => {
									if (r && r.message && r.message.mailed) {
										frappe.msgprint({
											title: __("Email queued"),
											message: __("The welcome email was sent to {0}.", [r.message.user]),
											indicator: "green",
										});
										updateMailChips();
									}
								});
						}
					);
				}
			});
		});

		const updateMailChips = () => {
			frappe
				.call({
					method: "adx_secure_qr_login.api.qr_manage.get_mail_status",
					args: { credential: frm.doc.name },
					type: "GET",
				})
				.then((r) => {
					const s = (r && r.message && r.message.status) || "Not Sent";
					field.$wrapper
						.find(".adx-qr-mail-chips")
						.html(
							["Not Sent", "Queued", "Sent", "Failed"]
								.map((v) => badge(v, s))
								.join("")
						);
				});
		};
		updateMailChips();

		frappe
			.call({
				method: "adx_secure_qr_login.api.qr_manage.get_qr_data_uri",
				args: { credential: frm.doc.name },
				type: "GET",
			})
			.then((r) => {
				const uri = r && r.message;
				if (!uri) {
					field.$wrapper.find(".adx-qr-media").html(
						`<div class="text-muted">${__(
							"No printable QR is stored for this credential. It may predate image storage, or it was removed on revoke."
						)}</div>`
					);
					return;
				}
				field.$wrapper.find(".adx-qr-media").html(`
					<div style="display:inline-block;border:1px solid #e2e2e2;border-radius:8px;padding:12px;background:#ffffff;">
						<img src="${uri}" style="max-width:240px;display:block;" />
					</div>
					<div class="text-muted" style="margin-top:6px;">${__(
						'Anyone holding this image can sign in as this user until the credential expires or is revoked. Print it, don\'t forward it.'
					)}</div>`);
			})
			.catch(() => {
				field.$wrapper.find(".adx-qr-media").html(
					`<div class="text-muted">${__(
						"You are not permitted to view this QR code."
					)}</div>`
				);
			});
	},
});
