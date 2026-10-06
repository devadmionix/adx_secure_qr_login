// Security dashboard for QR Login.
//
// Reads one endpoint, api/qr_stats.dashboard_data, which is role-gated
// server-side. Every figure on screen comes from that response -- nothing is
// computed here, so the dashboard cannot disagree with the weekly report.

frappe.provide("adx.qr_dashboard");

adx.qr_dashboard.render = function (container) {
	const $wrap = $(container);
	$wrap.html('<div class="adx-dash-loading text-muted">' + __("Loading…") + "</div>");

	frappe
		.call({
			method: "adx_secure_qr_login.api.qr_stats.dashboard_data",
			args: adx.qr_dashboard.filters(),
		})
		.then((r) => {
			const msg = (r && r.message) || null;
			if (!msg) {
				$wrap.html(
					'<div class="alert alert-warning">' +
						frappe._("Could not load QR security statistics.") +
						"</div>"
				);
				return;
			}
			$wrap.html(adx.qr_dashboard.template(msg));
		})
		.catch(() => {
			// A PermissionError here is the expected result for a user without a
			// QR role, so say so plainly rather than showing an empty page.
			$wrap.html(
				'<div class="alert alert-warning">' +
					frappe._("You are not permitted to view QR security statistics.") +
					"</div>"
			);
		});
};

// Display filters of spec 17. These only narrow the view; what a user may see
// at all is decided server-side by the DocType permission query conditions, so
// sending a filter for someone else reveals nothing.
adx.qr_dashboard.filters = function () {
	const read = (id) => {
		const el = document.getElementById(id);
		return el && el.value ? el.value : null;
	};
	return {
		frm: read("adx_qr_dash_from"),
		to: read("adx_qr_dash_to"),
		user: read("adx_qr_dash_user"),
		company: read("adx_qr_dash_company"),
	};
};

adx.qr_dashboard.filterBar = function () {
	const input = (id, placeholder, type) =>
		'<input id="' +
		id +
		'" type="' +
		(type || "text") +
		'" class="form-control" placeholder="' +
		placeholder +
		'" style="height:32px">';

	const companyOptions = (frappe.defaults && frappe.defaults.companies) || [];
	const companySelect = companyOptions.length
		? '<select id="adx_qr_dash_company" class="form-control" style="height:32px">' +
			'<option value="">' +
			frappe._("All companies") +
			"</option>" +
			companyOptions
				.map((c) => '<option value="' + frappe.utils.escape_html(c) + '">' + frappe.utils.escape_html(c) + "</option>")
				.join("") +
			"</select>"
		: input("adx_qr_dash_company", frappe._("Company"));

	return (
		'<div class="adx-dash-filters" style="margin-bottom:14px">' +
		'<div class="row">' +
		'<div class="col-md-2">' + input("adx_qr_dash_from", frappe._("From"), "date") + "</div>" +
		'<div class="col-md-2">' + input("adx_qr_dash_to", frappe._("To"), "date") + "</div>" +
		'<div class="col-md-3">' + input("adx_qr_dash_user", frappe._("User (email)")) + "</div>" +
		'<div class="col-md-3">' + companySelect + "</div>" +
		'<div class="col-md-2">' +
		'<button class="btn btn-primary btn-sm" style="height:32px" onclick="adx.qr_dashboard.reload()">' +
		frappe._("Apply") +
		"</button> " +
		'<button class="btn btn-default btn-sm" style="height:32px" onclick="adx.qr_dashboard.clearFilters()">' +
		frappe._("Clear") +
		"</button>" +
		"</div></div></div>"
	);
};

adx.qr_dashboard.reload = function () {
	const el = document.querySelector(".qr-security-dashboard[data-dashboard='adx-qr-security']");
	if (el) adx.qr_dashboard.render(el);
};

adx.qr_dashboard.clearFilters = function () {
	["adx_qr_dash_from", "adx_qr_dash_to", "adx_qr_dash_user", "adx_qr_dash_company"].forEach(
		(id) => {
			const el = document.getElementById(id);
			if (el) el.value = "";
		}
	);
	adx.qr_dashboard.reload();
};

adx.qr_dashboard.card = function (label, value, tone) {
	return (
		'<div class="col-md-4 col-xs-6" style="margin-bottom:12px">' +
		'<div class="qr-stat-card" data-tone="' +
		(tone || "grey") +
		'">' +
		'<div class="qr-stat-value">' +
		frappe.format(value || 0, {"df": null}) +
		"</div>" +
		'<div class="qr-stat-label">' +
		frappe._(label) +
		"</div>" +
		"</div></div>"
	);
};

adx.qr_dashboard.template = function (d) {
	const c = d.credentials || {};
	const a = d.authentication || {};
	const s = d.security || {};

	const filterBar = adx.qr_dashboard.filterBar();
	// Re-apply whatever is already set, so the 60s refresh does not wipe a filter.
	const active = a.filters || {};
	["from", "to", "user", "company"].forEach((k) => {
		const el = document.getElementById("adx_qr_dash_" + k);
		if (el && active[{"from": "frm"}[k] || k]) el.value = active[{"from": "frm"}[k] || k];
	});

	const cards = [
		adx.qr_dashboard.card("Active credentials", c.active, "green"),
		adx.qr_dashboard.card("Expired credentials", c.expired, "orange"),
		adx.qr_dashboard.card("Revoked credentials", c.revoked, "red"),
		adx.qr_dashboard.card("Successful QR logins", a.successful_logins, "blue"),
		adx.qr_dashboard.card("Failed attempts", a.failed_attempts, "red"),
		adx.qr_dashboard.card("Rate-limited attempts", a.rate_limited_attempts, "red"),
		adx.qr_dashboard.card("Security events", s.security_events, "orange"),
	].join("");

	const window_ =
		'<p class="text-muted" style="font-size:12px">' +
		frappe._("Window: {0} to {1}", [
			frappe.datetime.str_to_user((a.window || []).join("") || ""),
		]) +
		"</p>";

	let reasonTable = '<p class="text-muted">' + frappe._("No failures recorded.") + "</p>";
	if (s.by_reason && Object.keys(s.by_reason).length) {
		const rows = Object.keys(s.by_reason)
			.sort((x, y) => s.by_reason[y] - s.by_reason[x])
			.slice(0, 8)
			.map(
				(r) =>
					"<tr><td>" +
					frappe._(r.replace(/_/g, " ").toLowerCase()) +
					"</td><td class='text-right'>" +
					s.by_reason[r] +
					"</td></tr>"
			)
			.join("");
		reasonTable =
			"<table class='table table-sm' style='max-width:420px'>" +
			"<thead><tr><th>" +
			frappe._("Reason") +
			"</th><th class='text-right'>" +
			frappe._("Count") +
			"</th></tr></thead><tbody>" +
			rows +
			"</tbody></table>";
	}

	return (
		filterBar +
		'<div class="row">' +
		cards +
		"</div>" +
		'<div class="row"><div class="col-md-6">' +
		'<h5 style="margin-top:8px">' +
		frappe._("Failure reasons") +
		"</h5>" +
		reasonTable +
		'</div><div class="col-md-6">' +
		'<h5 style="margin-top:8px">' +
		frappe._("Recent failures") +
		"</h5>" +
		adx.qr_dashboard.auditTable(d.recent_failures || []) +
		"</div></div>" +
		window_
	);
};

adx.qr_dashboard.auditTable = function (rows) {
	if (!rows.length) {
		return '<p class="text-muted">' + frappe._("Nothing to show.") + "</p>";
	}
	const body = rows
		.map((r) => {
			const tone = r.reason_code === "RATE_LIMITED" ? "orange" : "red";
			return (
				"<tr>" +
				"<td>" +
				(r.user || frappe._("unknown")) +
				"</td>" +
				"<td><span class='indicator " +
				tone +
				"'>" +
				frappe._(String(r.event || "").toLowerCase()) +
				"</span></td>" +
				"<td>" +
				frappe.datetime.str_to_user(r.occurred_on || "") +
				"</td>" +
				"<td class='text-muted' style='font-size:11px'>" +
				(r.ip_address || "") +
				"</td>" +
				"</tr>"
			);
		})
		.join("");

	return (
		"<table class='table table-sm' style='max-width:520px'>" +
		"<thead><tr><th>" +
		frappe._("User") +
		"</th><th>" +
		frappe._("Outcome") +
		"</th><th>" +
		frappe._("When") +
		"</th><th>" +
		frappe._("IP") +
		"</th></tr></thead><tbody>" +
		body +
		"</tbody></table>"
	);
};

frappe.ready(function () {
	const $target = $(".qr-security-dashboard[data-dashboard='adx-qr-security']");
	if (!$target.length) return;

	const target = $target[0];
	adx.qr_dashboard.render(target);

	// Keep the view current without a manual refresh, but stop when hidden.
	let timer = null;
	const start = () => {
		if (timer) return;
		timer = setInterval(() => {
			if (!document.hidden) adx.qr_dashboard.render(target);
		}, 60000);
	};
	const stop = () => {
		if (timer) clearInterval(timer);
		timer = null;
	};

	$(document).on("visibilitychange", () => (document.hidden ? stop() : start()));
	$(window).on("beforeunload", stop);
	start();
});
