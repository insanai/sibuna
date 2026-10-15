//! Version 1 of the console schema on SQLite, the normative text of SID 0013 ("Tables").

/// The SQLite script of version 1. Every table is `STRICT`; small rows with a composite or
/// text key are `WITHOUT ROWID`.
pub(super) const V1: &str = "
CREATE INDEX console_policies_order ON policies (priority, name, id);
CREATE INDEX console_incidents_category
    ON security_incidents (violation_category, recorded_at, id);
CREATE INDEX console_incidents_campaign ON security_incidents (campaign_id, recorded_at, id);
CREATE INDEX console_incidents_client ON security_incidents (client_ip, recorded_at, id);

CREATE TABLE console_users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE CHECK (length(CAST(username AS BLOB)) BETWEEN 1 AND 64),
    password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 255),
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    must_change INTEGER NOT NULL DEFAULT 0 CHECK (must_change IN (0, 1)),
    password_expires_at INTEGER CHECK (password_expires_at >= 0),
    last_login_at INTEGER CHECK (last_login_at >= 0),
    modified_by INTEGER REFERENCES console_users (id),
    modified_at INTEGER NOT NULL CHECK (modified_at >= 0)) STRICT;

CREATE TABLE console_sessions (
    digest BLOB NOT NULL PRIMARY KEY CHECK (length(digest) = 32),
    user_id INTEGER NOT NULL REFERENCES console_users (id),
    user_revision INTEGER NOT NULL CHECK (user_revision >= 1),
    kind TEXT NOT NULL CHECK (kind IN ('browser', 'kiosk')),
    csrf_digest BLOB NOT NULL CHECK (length(csrf_digest) = 32),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL,
    idle_expires_at INTEGER NOT NULL,
    client_ip TEXT CHECK (length(client_ip) BETWEEN 1 AND 48),
    user_agent_digest BLOB CHECK (length(user_agent_digest) = 32),
    CHECK (expires_at > created_at AND expires_at - created_at <= 43200),
    CHECK (idle_expires_at > created_at AND idle_expires_at <= expires_at)) STRICT, WITHOUT ROWID;
CREATE INDEX console_sessions_user ON console_sessions (user_id);
CREATE INDEX console_sessions_deadline ON console_sessions (idle_expires_at);

CREATE TABLE console_totp (
    user_id INTEGER PRIMARY KEY REFERENCES console_users (id),
    envelope BLOB NOT NULL CHECK (length(envelope) = 60),
    key_id BLOB NOT NULL CHECK (length(key_id) = 32),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    enroll_by INTEGER NOT NULL CHECK (enroll_by >= 0),
    last_step INTEGER CHECK (last_step >= 0),
    recovery_digests BLOB CHECK (length(recovery_digests) = 320),
    recovery_used INTEGER NOT NULL DEFAULT 0 CHECK (recovery_used BETWEEN 0 AND 1023),
    modified_at INTEGER NOT NULL CHECK (modified_at >= 0),
    CHECK (enabled = 0 OR recovery_digests IS NOT NULL)) STRICT;

CREATE TABLE console_kiosk_grants (
    digest BLOB NOT NULL PRIMARY KEY CHECK (length(digest) = 32),
    user_id INTEGER NOT NULL REFERENCES console_users (id),
    user_revision INTEGER NOT NULL CHECK (user_revision >= 1),
    label TEXT NOT NULL DEFAULT '' CHECK (length(CAST(label AS BLOB)) <= 64),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    use_by INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    CHECK (use_by = created_at + 600 AND expires_at = created_at + 43200),
    CHECK (consumed_at IS NULL OR consumed_at BETWEEN created_at AND use_by))
    STRICT, WITHOUT ROWID;
CREATE INDEX console_kiosk_outstanding ON console_kiosk_grants (use_by)
    WHERE consumed_at IS NULL;

CREATE TABLE console_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
    label TEXT NOT NULL CHECK (length(CAST(label AS BLOB)) BETWEEN 1 AND 64),
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    scopes INTEGER NOT NULL CHECK (scopes BETWEEN 1 AND 255),
    created_by INTEGER NOT NULL REFERENCES console_users (id),
    creator_revision INTEGER NOT NULL CHECK (creator_revision >= 1),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER CHECK (expires_at > created_at),
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    modified_by INTEGER NOT NULL REFERENCES console_users (id),
    modified_at INTEGER NOT NULL CHECK (modified_at >= 0)) STRICT;
CREATE INDEX console_tokens_creator ON console_tokens (created_by, id);

CREATE TABLE console_audit (
    id INTEGER PRIMARY KEY CHECK (id >= 1),
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
    actor INTEGER CHECK (actor >= 1),
    actor_role TEXT CHECK (actor_role IN ('viewer', 'operator', 'admin')),
    action TEXT NOT NULL CHECK (action IN (
        'user.create', 'user.disable', 'user.enable', 'user.role', 'user.password_reset',
        'user.password_change', 'user.revoke', 'session.create', 'session.logout',
        'session.denied', 'totp.enable', 'token.create', 'token.revoke', 'token.remove',
        'kiosk.grant', 'kiosk.exchange', 'geoip.activate', 'policy.edit', 'policy.order',
        'policy.import', 'inspection.edit', 'reputation.edit', 'reputation.remove',
        'reputation.country', 'page.edit', 'page.reset', 'setting.change',
        'notification.create', 'notification.change', 'notification.remove',
        'notification.delivery', 'notification.test', 'notification.test_result',
        'node.command.intent', 'node.command.applied', 'node.command.rejected',
        'events.export_prepared', 'audit.export')),
    subject INTEGER CHECK (subject >= 0),
    target TEXT CHECK (length(CAST(target AS BLOB)) BETWEEN 1 AND 128),
    client_ip TEXT CHECK (length(client_ip) BETWEEN 1 AND 48),
    before_summary TEXT CHECK (CASE WHEN json_valid(before_summary)
        THEN json_type(before_summary) = 'object' AND length(before_summary) <= 2048
        ELSE before_summary IS NULL END),
    after_summary TEXT CHECK (CASE WHEN json_valid(after_summary)
        THEN json_type(after_summary) = 'object' AND length(after_summary) <= 2048
        ELSE after_summary IS NULL END)) STRICT;
CREATE INDEX console_audit_time ON console_audit (recorded_at, id);
CREATE INDEX console_audit_action ON console_audit (action, id);
CREATE INDEX console_audit_actor ON console_audit (actor, id);

CREATE TABLE console_audit_cursor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_id INTEGER NOT NULL CHECK (last_id BETWEEN 0 AND 9223372036854775807)) STRICT;
INSERT INTO console_audit_cursor (id, last_id) VALUES (1, 0);

CREATE TABLE console_settings (
    key TEXT NOT NULL PRIMARY KEY CHECK (key IN ('notify.spike_factor', 'notify.spike_minimum',
        'retention.minutes', 'retention.rankings', 'retention.incidents', 'retention.audit')),
    value INTEGER NOT NULL CHECK (value >= 1 AND value <= CASE key
        WHEN 'notify.spike_factor' THEN 1000000 WHEN 'notify.spike_minimum' THEN 1000000
        WHEN 'retention.minutes' THEN 90 WHEN 'retention.rankings' THEN 7
        WHEN 'retention.incidents' THEN 30 WHEN 'retention.audit' THEN 365 END),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    updated_by INTEGER NOT NULL REFERENCES console_users (id)) STRICT, WITHOUT ROWID;

CREATE TABLE console_job_leases (
    job TEXT NOT NULL PRIMARY KEY CHECK (job IN ('retention', 'notifier')),
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    fence INTEGER NOT NULL CHECK (fence >= 1),
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0)) STRICT, WITHOUT ROWID;

CREATE TABLE console_policy_history (
    policy_id TEXT NOT NULL CHECK (length(CAST(policy_id AS BLOB)) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    kind TEXT NOT NULL CHECK (kind IN ('baseline', 'edit')),
    actor INTEGER REFERENCES console_users (id),
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
    document TEXT NOT NULL CHECK (CASE WHEN json_valid(document)
        THEN json_type(document) = 'object' AND length(CAST(document AS BLOB)) <= 4096
        ELSE 0 END),
    PRIMARY KEY (policy_id, revision),
    CHECK ((kind = 'baseline') = (actor IS NULL))) STRICT;
CREATE INDEX console_policy_history_time ON console_policy_history (recorded_at);

CREATE TABLE console_inspection_history (
    revision INTEGER PRIMARY KEY CHECK (revision >= 1),
    actor INTEGER NOT NULL REFERENCES console_users (id),
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
    path_traversal TEXT NOT NULL CHECK (path_traversal IN ('disabled', 'audit', 'enforce')),
    sqli TEXT NOT NULL CHECK (sqli IN ('disabled', 'audit', 'enforce')),
    xss TEXT NOT NULL CHECK (xss IN ('disabled', 'audit', 'enforce')),
    rce TEXT NOT NULL CHECK (rce IN ('disabled', 'audit', 'enforce')),
    previous_path_traversal TEXT NOT NULL
        CHECK (previous_path_traversal IN ('disabled', 'audit', 'enforce')),
    previous_sqli TEXT NOT NULL CHECK (previous_sqli IN ('disabled', 'audit', 'enforce')),
    previous_xss TEXT NOT NULL CHECK (previous_xss IN ('disabled', 'audit', 'enforce')),
    previous_rce TEXT NOT NULL CHECK (previous_rce IN ('disabled', 'audit', 'enforce'))) STRICT;

CREATE TABLE console_reputation_sources (
    ip_or_cidr TEXT NOT NULL PRIMARY KEY
        REFERENCES ip_reputation (ip_or_cidr) ON DELETE CASCADE,
    country TEXT CHECK (country GLOB '[A-Z][A-Z]'),
    geo_generation BLOB CHECK (length(geo_generation) = 32),
    note TEXT NOT NULL DEFAULT '' CHECK (length(CAST(note AS BLOB)) <= 128),
    CHECK ((country IS NULL) = (geo_generation IS NULL)),
    CHECK (country IS NULL OR note = '')) STRICT, WITHOUT ROWID;
CREATE INDEX console_reputation_country ON console_reputation_sources (country, ip_or_cidr)
    WHERE country IS NOT NULL;

CREATE TABLE console_country_chunks (
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 1023),
    prefix TEXT NOT NULL CHECK (length(prefix) BETWEEN 1 AND 48),
    recorded_at INTEGER NOT NULL CHECK (recorded_at >= 0),
    PRIMARY KEY (digest, ordinal),
    UNIQUE (digest, prefix)) STRICT, WITHOUT ROWID;

CREATE TABLE console_pages (
    kind TEXT NOT NULL PRIMARY KEY
        CHECK (kind IN ('challenge', 'denied', 'rate_limited', 'banned', 'overloaded')),
    html TEXT NOT NULL CHECK (length(CAST(html AS BLOB)) <= 16384),
    sha256 BLOB NOT NULL CHECK (length(sha256) = 32),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    updated_by INTEGER NOT NULL REFERENCES console_users (id)) STRICT;

CREATE TABLE console_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('webhook', 'syslog')),
    transport TEXT NOT NULL CHECK (transport IN ('udp', 'tcp')),
    label TEXT NOT NULL CHECK (length(CAST(label AS BLOB)) BETWEEN 1 AND 64),
    target TEXT NOT NULL CHECK (length(CAST(target AS BLOB)) BETWEEN 1 AND 256),
    target_host TEXT NOT NULL CHECK (length(CAST(target_host AS BLOB)) <= 128),
    secret_envelope BLOB CHECK (length(secret_envelope) BETWEEN 1 AND 128),
    events INTEGER NOT NULL CHECK (events BETWEEN 1 AND 15),
    cooldown_seconds INTEGER NOT NULL CHECK (cooldown_seconds BETWEEN 0 AND 86400),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_by INTEGER NOT NULL REFERENCES console_users (id),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    modified_by INTEGER NOT NULL REFERENCES console_users (id),
    modified_at INTEGER NOT NULL CHECK (modified_at >= 0),
    last_attempt_at INTEGER CHECK (last_attempt_at >= 0),
    last_outcome TEXT CHECK (last_outcome IN ('delivered', 'failed')),
    last_detail TEXT CHECK (length(CAST(last_detail AS BLOB)) <= 96)) STRICT;

CREATE TABLE console_notification_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    event TEXT NOT NULL
        CHECK (event IN ('denial_spike', 'ban', 'node_unhealthy', 'leader_change')),
    raised_at INTEGER NOT NULL CHECK (raised_at >= 0),
    detail TEXT NOT NULL CHECK (length(CAST(detail AS BLOB)) <= 128),
    completed_at INTEGER CHECK (completed_at >= raised_at),
    UNIQUE (node, boot, sequence)) STRICT;
CREATE INDEX console_notification_completed
    ON console_notification_events (completed_at, id) WHERE completed_at IS NOT NULL;
CREATE INDEX console_notification_pending
    ON console_notification_events (id) WHERE completed_at IS NULL;

CREATE TABLE console_notification_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL
        REFERENCES console_notification_events (id) ON DELETE CASCADE,
    destination_id INTEGER REFERENCES console_notifications (id) ON DELETE SET NULL,
    destination_revision INTEGER NOT NULL CHECK (destination_revision >= 1),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sending', 'delivered', 'failed', 'skipped')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
    claim_fence INTEGER CHECK (claim_fence >= 1),
    claim_expires_at INTEGER,
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0),
    detail TEXT NOT NULL DEFAULT '' CHECK (length(CAST(detail AS BLOB)) <= 96),
    UNIQUE (event_id, destination_id),
    CHECK (state <> 'sending' OR (claim_fence IS NOT NULL AND claim_expires_at IS NOT NULL)),
    CHECK (destination_id IS NOT NULL OR state IN ('delivered', 'failed', 'skipped'))) STRICT;
CREATE INDEX console_delivery_due
    ON console_notification_deliveries (state, next_attempt_at, id);
CREATE INDEX console_delivery_destination
    ON console_notification_deliveries (destination_id, destination_revision, state);

CREATE TABLE console_nodes (
    node INTEGER PRIMARY KEY CHECK (node BETWEEN 1 AND 8388607),
    address TEXT NOT NULL CHECK (length(CAST(address AS BLOB)) BETWEEN 1 AND 64),
    console_url TEXT NOT NULL DEFAULT '' CHECK (length(CAST(console_url AS BLOB)) <= 128),
    version TEXT NOT NULL CHECK (length(CAST(version AS BLOB)) BETWEEN 1 AND 32),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    first_seen INTEGER NOT NULL CHECK (first_seen >= 0),
    last_seen INTEGER NOT NULL,
    applied_revision INTEGER NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    control_revision INTEGER NOT NULL DEFAULT 0 CHECK (control_revision >= 0),
    draining INTEGER NOT NULL DEFAULT 0 CHECK (draining IN (0, 1)),
    CHECK (last_seen >= first_seen)) STRICT;

CREATE TABLE console_commands (
    id BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    node INTEGER NOT NULL REFERENCES console_nodes (node),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    kind TEXT NOT NULL CHECK (kind IN ('drain', 'resume', 'clear_local_bans')),
    actor INTEGER NOT NULL REFERENCES console_users (id),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('operator', 'admin')),
    expected_revision INTEGER NOT NULL CHECK (expected_revision >= 0),
    state TEXT NOT NULL DEFAULT 'intent' CHECK (state IN ('intent', 'applied', 'rejected')),
    requested_at INTEGER NOT NULL CHECK (requested_at >= 0),
    completed_at INTEGER,
    applied_revision INTEGER CHECK (applied_revision >= 0),
    cleared_entries INTEGER CHECK (cleared_entries >= 0),
    CHECK ((state = 'intent') = (completed_at IS NULL)),
    CHECK (completed_at IS NULL OR completed_at >= requested_at),
    CHECK (cleared_entries IS NULL OR kind = 'clear_local_bans')) STRICT, WITHOUT ROWID;
CREATE INDEX console_commands_node ON console_commands (node, requested_at, id);

CREATE TABLE console_geo_generations (
    digest BLOB NOT NULL PRIMARY KEY CHECK (length(digest) = 32),
    provider TEXT NOT NULL CHECK (provider IN ('dbip', 'user-country')),
    source_version TEXT NOT NULL CHECK (length(source_version) BETWEEN 1 AND 10),
    source_digests BLOB CHECK (length(source_digests) IN (32, 64)),
    ranges INTEGER NOT NULL CHECK (ranges BETWEEN 1 AND 1048576),
    actor INTEGER NOT NULL REFERENCES console_users (id),
    created_at INTEGER NOT NULL CHECK (created_at >= 0)) STRICT;

CREATE TABLE console_geo_chunks (
    digest BLOB NOT NULL REFERENCES console_geo_generations (digest) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 10485),
    ranges BLOB NOT NULL
        CHECK (length(ranges) BETWEEN 34 AND 3400 AND length(ranges) % 34 = 0),
    PRIMARY KEY (digest, ordinal)) STRICT;

CREATE TABLE console_geo_active (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    digest BLOB REFERENCES console_geo_generations (digest),
    loaded_at INTEGER CHECK (loaded_at >= 0),
    actor INTEGER REFERENCES console_users (id),
    CHECK ((digest IS NULL) = (loaded_at IS NULL)),
    CHECK ((digest IS NULL) = (actor IS NULL)),
    CHECK ((digest IS NULL) = (revision = 0))) STRICT;
INSERT INTO console_geo_active (id, revision) VALUES (1, 0);

CREATE TABLE console_minutes (
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 4294967295),
    minute INTEGER NOT NULL CHECK (minute >= 0),
    start_ms INTEGER NOT NULL CHECK (start_ms >= 0),
    end_ms INTEGER NOT NULL,
    sealed INTEGER NOT NULL CHECK (sealed IN (0, 1)),
    payload BLOB NOT NULL
        CHECK (length(payload) = 176 AND substr(payload, 1, 4) = X'53424D32'),
    PRIMARY KEY (node, boot, epoch, minute),
    CHECK (end_ms > start_ms)) STRICT, WITHOUT ROWID;
CREATE INDEX console_minutes_time ON console_minutes (minute, node, boot, epoch);
CREATE INDEX console_minutes_node_time ON console_minutes (node, minute, boot, epoch);

CREATE TABLE console_challenge_minutes (
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 4294967295),
    minute INTEGER NOT NULL CHECK (minute >= 0),
    start_ms INTEGER NOT NULL CHECK (start_ms >= 0),
    end_ms INTEGER NOT NULL,
    sealed INTEGER NOT NULL CHECK (sealed IN (0, 1)),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 128 AND 896
        AND (length(payload) - 128) % 96 = 0 AND substr(payload, 1, 4) = X'53424331'),
    PRIMARY KEY (node, boot, epoch, minute),
    CHECK (end_ms > start_ms)) STRICT, WITHOUT ROWID;
CREATE INDEX console_challenge_minutes_time
    ON console_challenge_minutes (minute, node, boot, epoch);
CREATE INDEX console_challenge_minutes_node_time
    ON console_challenge_minutes (node, minute, boot, epoch);

CREATE TABLE console_challenge_records (
    id INTEGER PRIMARY KEY,
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    second INTEGER NOT NULL CHECK (second >= 0),
    ip TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 48),
    outcome TEXT NOT NULL CHECK (outcome IN ('issued', 'accepted', 'rejected')),
    cause INTEGER CHECK (cause BETWEEN 0 AND 12),
    algorithm TEXT NOT NULL CHECK (algorithm IN ('hashcash', 'posw')),
    parameter INTEGER NOT NULL CHECK (parameter BETWEEN 0 AND 255),
    openings INTEGER NOT NULL CHECK (openings BETWEEN 0 AND 255),
    duration_ms INTEGER CHECK (duration_ms BETWEEN 0 AND 4294967295),
    CHECK ((outcome = 'rejected') = (cause IS NOT NULL))) STRICT;
CREATE INDEX console_challenge_records_time ON console_challenge_records (second, id);
CREATE INDEX console_challenge_records_cause
    ON console_challenge_records (cause, second, id);
CREATE INDEX console_challenge_records_ip ON console_challenge_records (ip, second, id);

CREATE TABLE console_challenge_difficulty (
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    second INTEGER NOT NULL CHECK (second >= 0),
    previous_bits INTEGER NOT NULL CHECK (previous_bits BETWEEN 0 AND 255),
    bits INTEGER NOT NULL CHECK (bits BETWEEN 0 AND 255),
    rate_256 INTEGER NOT NULL CHECK (rate_256 >= 0),
    PRIMARY KEY (node, boot, second)) STRICT, WITHOUT ROWID;
CREATE INDEX console_challenge_difficulty_time
    ON console_challenge_difficulty (second, node, boot);

CREATE TABLE console_rank_usage (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    charged_bytes INTEGER NOT NULL CHECK (charged_bytes BETWEEN 0 AND 536870912)) STRICT;
INSERT INTO console_rank_usage (id, charged_bytes) VALUES (1, 0);

CREATE TABLE console_rank_archives (
    digest BLOB NOT NULL PRIMARY KEY CHECK (length(digest) = 32),
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    minute INTEGER NOT NULL CHECK (minute >= 0),
    bytes BLOB NOT NULL CHECK (length(bytes) BETWEEN 92 AND 48536),
    charge INTEGER NOT NULL CHECK (charge = (length(bytes) + 2047) / 2048 * 8192 + 1024),
    stored_at INTEGER NOT NULL CHECK (stored_at >= 0),
    UNIQUE (node, boot, minute)) STRICT;
CREATE INDEX console_rank_minute ON console_rank_archives (minute, digest);
CREATE INDEX console_rank_node ON console_rank_archives (node, minute, digest);

CREATE TABLE console_rule_hits (
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    rule_key TEXT NOT NULL CHECK (length(CAST(rule_key AS BLOB)) BETWEEN 1 AND 160),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) <= 128),
    minute INTEGER NOT NULL CHECK (minute >= 0),
    utc_start INTEGER NOT NULL CHECK (utc_start >= 0),
    utc_end INTEGER NOT NULL,
    start_ms INTEGER NOT NULL CHECK (start_ms >= 0),
    end_ms INTEGER NOT NULL,
    observed_ms INTEGER NOT NULL CHECK (observed_ms >= 0),
    observations INTEGER NOT NULL CHECK (observations >= 0),
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    gap INTEGER NOT NULL CHECK (gap IN (0, 1)),
    unconfirmed INTEGER NOT NULL CHECK (unconfirmed >= 0),
    hits INTEGER CHECK (hits >= 0),
    PRIMARY KEY (node, boot, sequence, rule_key),
    CHECK (utc_end >= utc_start AND end_ms >= start_ms)) STRICT;
CREATE INDEX console_rule_hits_history
    ON console_rule_hits (rule_key, node, minute, boot, sequence);
CREATE INDEX console_rule_hits_revision
    ON console_rule_hits (rule_key, node, revision, minute, boot, sequence);
CREATE INDEX console_rule_hits_retention ON console_rule_hits (minute);

CREATE TABLE console_rule_hit_rollups (
    grain INTEGER NOT NULL CHECK (grain IN (60, 1440)),
    node INTEGER NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BLOB NOT NULL CHECK (length(boot) = 16),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    rule_key TEXT NOT NULL CHECK (length(CAST(rule_key AS BLOB)) BETWEEN 1 AND 160),
    bucket INTEGER NOT NULL CHECK (bucket >= 0 AND bucket % grain = 0),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    name TEXT NOT NULL CHECK (length(CAST(name AS BLOB)) <= 128),
    hits INTEGER CHECK (hits >= 0),
    observed_ms INTEGER NOT NULL CHECK (observed_ms >= 0),
    intervals INTEGER NOT NULL CHECK (intervals >= 1),
    complete INTEGER NOT NULL CHECK (complete >= 0),
    gaps INTEGER NOT NULL CHECK (gaps >= 0),
    unconfirmed INTEGER NOT NULL CHECK (unconfirmed >= 0),
    through_minute INTEGER NOT NULL
        CHECK (through_minute >= bucket AND through_minute < bucket + grain),
    PRIMARY KEY (grain, node, boot, generation, rule_key, bucket)) STRICT;
CREATE INDEX console_rule_rollup_history
    ON console_rule_hit_rollups (rule_key, node, grain, bucket, boot, generation);
CREATE INDEX console_rule_rollup_retention ON console_rule_hit_rollups (bucket, grain);

CREATE TABLE console_incident_evidence (
    incident_id INTEGER PRIMARY KEY REFERENCES security_incidents (id) ON DELETE CASCADE,
    selected_status INTEGER NOT NULL CHECK (selected_status BETWEEN 100 AND 599),
    query_bytes INTEGER NOT NULL CHECK (query_bytes BETWEEN 0 AND 4294967295),
    body_bytes INTEGER NOT NULL CHECK (body_bytes BETWEEN 0 AND 4294967295),
    declared_body_bytes INTEGER NOT NULL
        CHECK (declared_body_bytes BETWEEN 0 AND 4294967295),
    truncated INTEGER NOT NULL CHECK (truncated BETWEEN 0 AND 255)) STRICT;

CREATE TABLE console_incident_heads (
    incident_id INTEGER PRIMARY KEY REFERENCES security_incidents (id) ON DELETE CASCADE,
    request_head BLOB NOT NULL CHECK (length(request_head) <= 2048),
    response_head BLOB NOT NULL CHECK (length(response_head) <= 1024),
    request_truncated INTEGER NOT NULL CHECK (request_truncated IN (0, 1)),
    response_truncated INTEGER NOT NULL CHECK (response_truncated IN (0, 1)),
    response_state TEXT NOT NULL
        CHECK (response_state IN ('captured', 'local', 'unobserved', 'unavailable')),
    CHECK (response_state = 'captured'
        OR (length(response_head) = 0 AND response_truncated = 0))) STRICT;

CREATE TABLE console_incident_country (
    incident_id INTEGER PRIMARY KEY REFERENCES security_incidents (id) ON DELETE CASCADE,
    country TEXT CHECK (country GLOB '[A-Z][A-Z]'),
    generation BLOB NOT NULL CHECK (length(generation) = 32)) STRICT;
CREATE INDEX console_incident_country_code ON console_incident_country (country, incident_id);
";
