// Written by tests/support/mod.rs; see tests/snapshot.rs.

/// A generated function taking values in field order.
pub type Glue = fn(&mut String, &[&dyn ::sibuna_html::Value]) -> Result;

type Result = ::core::fmt::Result;

include!("audit-detail.rs");
include!("audit-filters.rs");
include!("audit-footer.rs");
include!("audit-header.rs");
include!("audit-revert.rs");
include!("country-form.rs");
include!("dashboard-scope.rs");
include!("field.rs");
include!("filter-input.rs");
include!("globe-definitions.rs");
include!("globe-incidents.rs");
include!("globe-mode.rs");
include!("inspection-footer.rs");
include!("inspection-header.rs");
include!("kiosk-grant-code.rs");
include!("kiosk-grant-form.rs");
include!("message.rs");
include!("nodes-controls.rs");
include!("nodes-header.rs");
include!("nodes-member.rs");
include!("nodes-status.rs");
include!("notification-form.rs");
include!("notification-row.rs");
include!("page-editor.rs");
include!("peer-observation.rs");
include!("policies-decision.rs");
include!("policies-header.rs");
include!("policies-row.rs");
include!("policies-summary.rs");
include!("policies-test.rs");
include!("policy-change-actions.rs");
include!("policy-change-rebase.rs");
include!("policy-change-review.rs");
include!("policy-editor-header.rs");
include!("policy-extra-fields.rs");
include!("policy-form.rs");
include!("policy-header-fields.rs");
include!("policy-history-row.rs");
include!("policy-id-existing.rs");
include!("policy-id-new.rs");
include!("policy-import.rs");
include!("policy-import-all.rs");
include!("policy-limits.rs");
include!("policy-managed-row.rs");
include!("policy-manager-header.rs");
include!("policy-manager-summary.rs");
include!("policy-name.rs");
include!("policy-network-fields.rs");
include!("policy-preview-fields.rs");
include!("policy-replay-row.rs");
include!("policy-restore-notice.rs");
include!("policy-select.rs");
include!("ranking-history-form.rs");
include!("ranking-row.rs");
include!("reputation-form.rs");
include!("reputation-row.rs");
include!("rule-hit-form.rs");
include!("rule-hit-header.rs");
include!("setting-row.rs");
include!("settings-header.rs");
include!("shell-content.rs");
include!("shell-header.rs");
include!("shell-item.rs");
include!("similarity-control.rs");
include!("similarity-footer.rs");
include!("similarity-header.rs");
include!("similarity-match.rs");
include!("similarity-status.rs");
include!("statistics-tabs.rs");
include!("tokens-create.rs");
include!("tokens-expiry.rs");
include!("tokens-header.rs");
include!("tokens-revoke.rs");
include!("tokens-scope.rs");
include!("tokens-secret.rs");
include!("users-access.rs");
include!("users-create.rs");
include!("users-header.rs");
include!("users-revoke.rs");
include!("users-secret.rs");
include!("zig-attributes.rs");
include!("zig-capacity.rs");
include!("zig-repeated.rs");
include!("zig-no-slots.rs");
include!("zig-scalars.rs");
include!("zig-wide.rs");
include!("zig-literals.rs");
include!("zig-ascii.rs");
include!("zig-keywords.rs");

/// Every generated function by snippet stem.
pub const GOLDEN: &[(&str, Glue)] = &[
    ("audit-detail", golden_audit_detail),
    ("audit-filters", golden_audit_filters),
    ("audit-footer", golden_audit_footer),
    ("audit-header", golden_audit_header),
    ("audit-revert", golden_audit_revert),
    ("country-form", golden_country_form),
    ("dashboard-scope", golden_dashboard_scope),
    ("field", golden_field),
    ("filter-input", golden_filter_input),
    ("globe-definitions", golden_globe_definitions),
    ("globe-incidents", golden_globe_incidents),
    ("globe-mode", golden_globe_mode),
    ("inspection-footer", golden_inspection_footer),
    ("inspection-header", golden_inspection_header),
    ("kiosk-grant-code", golden_kiosk_grant_code),
    ("kiosk-grant-form", golden_kiosk_grant_form),
    ("message", golden_message),
    ("nodes-controls", golden_nodes_controls),
    ("nodes-header", golden_nodes_header),
    ("nodes-member", golden_nodes_member),
    ("nodes-status", golden_nodes_status),
    ("notification-form", golden_notification_form),
    ("notification-row", golden_notification_row),
    ("page-editor", golden_page_editor),
    ("peer-observation", golden_peer_observation),
    ("policies-decision", golden_policies_decision),
    ("policies-header", golden_policies_header),
    ("policies-row", golden_policies_row),
    ("policies-summary", golden_policies_summary),
    ("policies-test", golden_policies_test),
    ("policy-change-actions", golden_policy_change_actions),
    ("policy-change-rebase", golden_policy_change_rebase),
    ("policy-change-review", golden_policy_change_review),
    ("policy-editor-header", golden_policy_editor_header),
    ("policy-extra-fields", golden_policy_extra_fields),
    ("policy-form", golden_policy_form),
    ("policy-header-fields", golden_policy_header_fields),
    ("policy-history-row", golden_policy_history_row),
    ("policy-id-existing", golden_policy_id_existing),
    ("policy-id-new", golden_policy_id_new),
    ("policy-import", golden_policy_import),
    ("policy-import-all", golden_policy_import_all),
    ("policy-limits", golden_policy_limits),
    ("policy-managed-row", golden_policy_managed_row),
    ("policy-manager-header", golden_policy_manager_header),
    ("policy-manager-summary", golden_policy_manager_summary),
    ("policy-name", golden_policy_name),
    ("policy-network-fields", golden_policy_network_fields),
    ("policy-preview-fields", golden_policy_preview_fields),
    ("policy-replay-row", golden_policy_replay_row),
    ("policy-restore-notice", golden_policy_restore_notice),
    ("policy-select", golden_policy_select),
    ("ranking-history-form", golden_ranking_history_form),
    ("ranking-row", golden_ranking_row),
    ("reputation-form", golden_reputation_form),
    ("reputation-row", golden_reputation_row),
    ("rule-hit-form", golden_rule_hit_form),
    ("rule-hit-header", golden_rule_hit_header),
    ("setting-row", golden_setting_row),
    ("settings-header", golden_settings_header),
    ("shell-content", golden_shell_content),
    ("shell-header", golden_shell_header),
    ("shell-item", golden_shell_item),
    ("similarity-control", golden_similarity_control),
    ("similarity-footer", golden_similarity_footer),
    ("similarity-header", golden_similarity_header),
    ("similarity-match", golden_similarity_match),
    ("similarity-status", golden_similarity_status),
    ("statistics-tabs", golden_statistics_tabs),
    ("tokens-create", golden_tokens_create),
    ("tokens-expiry", golden_tokens_expiry),
    ("tokens-header", golden_tokens_header),
    ("tokens-revoke", golden_tokens_revoke),
    ("tokens-scope", golden_tokens_scope),
    ("tokens-secret", golden_tokens_secret),
    ("users-access", golden_users_access),
    ("users-create", golden_users_create),
    ("users-header", golden_users_header),
    ("users-revoke", golden_users_revoke),
    ("users-secret", golden_users_secret),
    ("zig-attributes", golden_zig_attributes),
    ("zig-capacity", golden_zig_capacity),
    ("zig-repeated", golden_zig_repeated),
    ("zig-no-slots", golden_zig_no_slots),
    ("zig-scalars", golden_zig_scalars),
    ("zig-wide", golden_zig_wide),
    ("zig-literals", golden_zig_literals),
    ("zig-ascii", golden_zig_ascii),
    ("zig-keywords", golden_zig_keywords),
];
