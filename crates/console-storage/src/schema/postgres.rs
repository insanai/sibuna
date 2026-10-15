//! Version 1 of the console schema on PostgreSQL. It differs from the SQLite text only as
//! the dialect table of SID 0013 states: `BIGINT` integers, identity keys, `BOOLEAN` flags,
//! `BYTEA` with `octet_length`, `JSONB` documents, the `"C"` collation for byte-ordered text
//! keys, regular expressions for country codes, and no table options.

/// The PostgreSQL script of version 1.
pub(super) const V1: &str = r#"
CREATE INDEX console_policies_order ON policies (priority, name, id);
CREATE INDEX console_incidents_category
    ON security_incidents (violation_category, recorded_at, id);
CREATE INDEX console_incidents_campaign ON security_incidents (campaign_id, recorded_at, id);
CREATE INDEX console_incidents_client ON security_incidents (client_ip, recorded_at, id);

CREATE TABLE console_users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT COLLATE "C" NOT NULL UNIQUE CHECK (octet_length(username) BETWEEN 1 AND 64),
    password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 255),
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    must_change BOOLEAN NOT NULL DEFAULT FALSE,
    password_expires_at BIGINT CHECK (password_expires_at >= 0),
    last_login_at BIGINT CHECK (last_login_at >= 0),
    modified_by BIGINT REFERENCES console_users (id),
    modified_at BIGINT NOT NULL CHECK (modified_at >= 0));

CREATE TABLE console_sessions (
    digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(digest) = 32),
    user_id BIGINT NOT NULL REFERENCES console_users (id),
    user_revision BIGINT NOT NULL CHECK (user_revision >= 1),
    kind TEXT NOT NULL CHECK (kind IN ('browser', 'kiosk')),
    csrf_digest BYTEA NOT NULL CHECK (octet_length(csrf_digest) = 32),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    expires_at BIGINT NOT NULL,
    idle_expires_at BIGINT NOT NULL,
    client_ip TEXT CHECK (length(client_ip) BETWEEN 1 AND 48),
    user_agent_digest BYTEA CHECK (octet_length(user_agent_digest) = 32),
    CHECK (expires_at > created_at AND expires_at - created_at <= 43200),
    CHECK (idle_expires_at > created_at AND idle_expires_at <= expires_at));
CREATE INDEX console_sessions_user ON console_sessions (user_id);
CREATE INDEX console_sessions_deadline ON console_sessions (idle_expires_at);

CREATE TABLE console_totp (
    user_id BIGINT PRIMARY KEY REFERENCES console_users (id),
    envelope BYTEA NOT NULL CHECK (octet_length(envelope) = 60),
    key_id BYTEA NOT NULL CHECK (octet_length(key_id) = 32),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enroll_by BIGINT NOT NULL CHECK (enroll_by >= 0),
    last_step BIGINT CHECK (last_step >= 0),
    recovery_digests BYTEA CHECK (octet_length(recovery_digests) = 320),
    recovery_used BIGINT NOT NULL DEFAULT 0 CHECK (recovery_used BETWEEN 0 AND 1023),
    modified_at BIGINT NOT NULL CHECK (modified_at >= 0),
    CHECK (NOT enabled OR recovery_digests IS NOT NULL));

CREATE TABLE console_kiosk_grants (
    digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(digest) = 32),
    user_id BIGINT NOT NULL REFERENCES console_users (id),
    user_revision BIGINT NOT NULL CHECK (user_revision >= 1),
    label TEXT NOT NULL DEFAULT '' CHECK (octet_length(label) <= 64),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    use_by BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    CHECK (use_by = created_at + 600 AND expires_at = created_at + 43200),
    CHECK (consumed_at IS NULL OR consumed_at BETWEEN created_at AND use_by));
CREATE INDEX console_kiosk_outstanding ON console_kiosk_grants (use_by)
    WHERE consumed_at IS NULL;

CREATE TABLE console_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    digest BYTEA NOT NULL UNIQUE CHECK (octet_length(digest) = 32),
    label TEXT NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 64),
    role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    scopes BIGINT NOT NULL CHECK (scopes BETWEEN 1 AND 255),
    created_by BIGINT NOT NULL REFERENCES console_users (id),
    creator_revision BIGINT NOT NULL CHECK (creator_revision >= 1),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    expires_at BIGINT CHECK (expires_at > created_at),
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    modified_by BIGINT NOT NULL REFERENCES console_users (id),
    modified_at BIGINT NOT NULL CHECK (modified_at >= 0));
CREATE INDEX console_tokens_creator ON console_tokens (created_by, id);

CREATE TABLE console_audit (
    id BIGINT PRIMARY KEY CHECK (id >= 1),
    recorded_at BIGINT NOT NULL CHECK (recorded_at >= 0),
    actor BIGINT CHECK (actor >= 1),
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
    subject BIGINT CHECK (subject >= 0),
    target TEXT CHECK (octet_length(target) BETWEEN 1 AND 128),
    client_ip TEXT CHECK (length(client_ip) BETWEEN 1 AND 48),
    before_summary JSONB CHECK (jsonb_typeof(before_summary) = 'object'
        AND octet_length(CAST(before_summary AS TEXT)) <= 2048),
    after_summary JSONB CHECK (jsonb_typeof(after_summary) = 'object'
        AND octet_length(CAST(after_summary AS TEXT)) <= 2048));
CREATE INDEX console_audit_time ON console_audit (recorded_at, id);
CREATE INDEX console_audit_action ON console_audit (action, id);
CREATE INDEX console_audit_actor ON console_audit (actor, id);

CREATE TABLE console_audit_cursor (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    last_id BIGINT NOT NULL CHECK (last_id BETWEEN 0 AND 9223372036854775807));
INSERT INTO console_audit_cursor (id, last_id) VALUES (1, 0);

CREATE TABLE console_settings (
    key TEXT NOT NULL PRIMARY KEY CHECK (key IN ('notify.spike_factor', 'notify.spike_minimum',
        'retention.minutes', 'retention.rankings', 'retention.incidents', 'retention.audit')),
    value BIGINT NOT NULL CHECK (value >= 1 AND value <= CASE key
        WHEN 'notify.spike_factor' THEN 1000000 WHEN 'notify.spike_minimum' THEN 1000000
        WHEN 'retention.minutes' THEN 90 WHEN 'retention.rankings' THEN 7
        WHEN 'retention.incidents' THEN 30 WHEN 'retention.audit' THEN 365 END),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    updated_by BIGINT NOT NULL REFERENCES console_users (id));

CREATE TABLE console_job_leases (
    job TEXT NOT NULL PRIMARY KEY CHECK (job IN ('retention', 'notifier')),
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    fence BIGINT NOT NULL CHECK (fence >= 1),
    expires_at BIGINT NOT NULL CHECK (expires_at >= 0));

CREATE TABLE console_policy_history (
    policy_id TEXT COLLATE "C" NOT NULL CHECK (octet_length(policy_id) BETWEEN 1 AND 128),
    revision BIGINT NOT NULL CHECK (revision >= 0),
    kind TEXT NOT NULL CHECK (kind IN ('baseline', 'edit')),
    actor BIGINT REFERENCES console_users (id),
    recorded_at BIGINT NOT NULL CHECK (recorded_at >= 0),
    document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'
        AND octet_length(CAST(document AS TEXT)) <= 4096),
    PRIMARY KEY (policy_id, revision),
    CHECK ((kind = 'baseline') = (actor IS NULL)));
CREATE INDEX console_policy_history_time ON console_policy_history (recorded_at);

CREATE TABLE console_inspection_history (
    revision BIGINT PRIMARY KEY CHECK (revision >= 1),
    actor BIGINT NOT NULL REFERENCES console_users (id),
    recorded_at BIGINT NOT NULL CHECK (recorded_at >= 0),
    path_traversal TEXT NOT NULL CHECK (path_traversal IN ('disabled', 'audit', 'enforce')),
    sqli TEXT NOT NULL CHECK (sqli IN ('disabled', 'audit', 'enforce')),
    xss TEXT NOT NULL CHECK (xss IN ('disabled', 'audit', 'enforce')),
    rce TEXT NOT NULL CHECK (rce IN ('disabled', 'audit', 'enforce')),
    previous_path_traversal TEXT NOT NULL
        CHECK (previous_path_traversal IN ('disabled', 'audit', 'enforce')),
    previous_sqli TEXT NOT NULL CHECK (previous_sqli IN ('disabled', 'audit', 'enforce')),
    previous_xss TEXT NOT NULL CHECK (previous_xss IN ('disabled', 'audit', 'enforce')),
    previous_rce TEXT NOT NULL CHECK (previous_rce IN ('disabled', 'audit', 'enforce')));

CREATE TABLE console_reputation_sources (
    ip_or_cidr TEXT NOT NULL PRIMARY KEY
        REFERENCES ip_reputation (ip_or_cidr) ON DELETE CASCADE,
    country TEXT CHECK (country ~ '^[A-Z]{2}$'),
    geo_generation BYTEA CHECK (octet_length(geo_generation) = 32),
    note TEXT NOT NULL DEFAULT '' CHECK (octet_length(note) <= 128),
    CHECK ((country IS NULL) = (geo_generation IS NULL)),
    CHECK (country IS NULL OR note = ''));
CREATE INDEX console_reputation_country ON console_reputation_sources (country, ip_or_cidr)
    WHERE country IS NOT NULL;

CREATE TABLE console_country_chunks (
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    ordinal BIGINT NOT NULL CHECK (ordinal BETWEEN 0 AND 1023),
    prefix TEXT COLLATE "C" NOT NULL CHECK (length(prefix) BETWEEN 1 AND 48),
    recorded_at BIGINT NOT NULL CHECK (recorded_at >= 0),
    PRIMARY KEY (digest, ordinal),
    UNIQUE (digest, prefix));

CREATE TABLE console_pages (
    kind TEXT NOT NULL PRIMARY KEY
        CHECK (kind IN ('challenge', 'denied', 'rate_limited', 'banned', 'overloaded')),
    html TEXT NOT NULL CHECK (octet_length(html) <= 16384),
    sha256 BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    updated_by BIGINT NOT NULL REFERENCES console_users (id));

CREATE TABLE console_notifications (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('webhook', 'syslog')),
    transport TEXT NOT NULL CHECK (transport IN ('udp', 'tcp')),
    label TEXT NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 64),
    target TEXT NOT NULL CHECK (octet_length(target) BETWEEN 1 AND 256),
    target_host TEXT NOT NULL CHECK (octet_length(target_host) <= 128),
    secret_envelope BYTEA CHECK (octet_length(secret_envelope) BETWEEN 1 AND 128),
    events BIGINT NOT NULL CHECK (events BETWEEN 1 AND 15),
    cooldown_seconds BIGINT NOT NULL CHECK (cooldown_seconds BETWEEN 0 AND 86400),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_by BIGINT NOT NULL REFERENCES console_users (id),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    modified_by BIGINT NOT NULL REFERENCES console_users (id),
    modified_at BIGINT NOT NULL CHECK (modified_at >= 0),
    last_attempt_at BIGINT CHECK (last_attempt_at >= 0),
    last_outcome TEXT CHECK (last_outcome IN ('delivered', 'failed')),
    last_detail TEXT CHECK (octet_length(last_detail) <= 96));

CREATE TABLE console_notification_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    event TEXT NOT NULL
        CHECK (event IN ('denial_spike', 'ban', 'node_unhealthy', 'leader_change')),
    raised_at BIGINT NOT NULL CHECK (raised_at >= 0),
    detail TEXT NOT NULL CHECK (octet_length(detail) <= 128),
    completed_at BIGINT CHECK (completed_at >= raised_at),
    UNIQUE (node, boot, sequence));
CREATE INDEX console_notification_completed
    ON console_notification_events (completed_at, id) WHERE completed_at IS NOT NULL;
CREATE INDEX console_notification_pending
    ON console_notification_events (id) WHERE completed_at IS NULL;

CREATE TABLE console_notification_deliveries (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id BIGINT NOT NULL
        REFERENCES console_notification_events (id) ON DELETE CASCADE,
    destination_id BIGINT REFERENCES console_notifications (id) ON DELETE SET NULL,
    destination_revision BIGINT NOT NULL CHECK (destination_revision >= 1),
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sending', 'delivered', 'failed', 'skipped')),
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    next_attempt_at BIGINT NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
    claim_fence BIGINT CHECK (claim_fence >= 1),
    claim_expires_at BIGINT,
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    detail TEXT NOT NULL DEFAULT '' CHECK (octet_length(detail) <= 96),
    UNIQUE (event_id, destination_id),
    CHECK (state <> 'sending' OR (claim_fence IS NOT NULL AND claim_expires_at IS NOT NULL)),
    CHECK (destination_id IS NOT NULL OR state IN ('delivered', 'failed', 'skipped')));
CREATE INDEX console_delivery_due
    ON console_notification_deliveries (state, next_attempt_at, id);
CREATE INDEX console_delivery_destination
    ON console_notification_deliveries (destination_id, destination_revision, state);

CREATE TABLE console_nodes (
    node BIGINT PRIMARY KEY CHECK (node BETWEEN 1 AND 8388607),
    address TEXT NOT NULL CHECK (octet_length(address) BETWEEN 1 AND 64),
    console_url TEXT NOT NULL DEFAULT '' CHECK (octet_length(console_url) <= 128),
    version TEXT NOT NULL CHECK (octet_length(version) BETWEEN 1 AND 32),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    first_seen BIGINT NOT NULL CHECK (first_seen >= 0),
    last_seen BIGINT NOT NULL,
    applied_revision BIGINT NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    control_revision BIGINT NOT NULL DEFAULT 0 CHECK (control_revision >= 0),
    draining BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (last_seen >= first_seen));

CREATE TABLE console_commands (
    id BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(id) = 16),
    node BIGINT NOT NULL REFERENCES console_nodes (node),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    kind TEXT NOT NULL CHECK (kind IN ('drain', 'resume', 'clear_local_bans')),
    actor BIGINT NOT NULL REFERENCES console_users (id),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('operator', 'admin')),
    expected_revision BIGINT NOT NULL CHECK (expected_revision >= 0),
    state TEXT NOT NULL DEFAULT 'intent' CHECK (state IN ('intent', 'applied', 'rejected')),
    requested_at BIGINT NOT NULL CHECK (requested_at >= 0),
    completed_at BIGINT,
    applied_revision BIGINT CHECK (applied_revision >= 0),
    cleared_entries BIGINT CHECK (cleared_entries >= 0),
    CHECK ((state = 'intent') = (completed_at IS NULL)),
    CHECK (completed_at IS NULL OR completed_at >= requested_at),
    CHECK (cleared_entries IS NULL OR kind = 'clear_local_bans'));
CREATE INDEX console_commands_node ON console_commands (node, requested_at, id);

CREATE TABLE console_geo_generations (
    digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(digest) = 32),
    provider TEXT NOT NULL CHECK (provider IN ('dbip', 'user-country')),
    source_version TEXT NOT NULL CHECK (length(source_version) BETWEEN 1 AND 10),
    source_digests BYTEA CHECK (octet_length(source_digests) IN (32, 64)),
    ranges BIGINT NOT NULL CHECK (ranges BETWEEN 1 AND 1048576),
    actor BIGINT NOT NULL REFERENCES console_users (id),
    created_at BIGINT NOT NULL CHECK (created_at >= 0));

CREATE TABLE console_geo_chunks (
    digest BYTEA NOT NULL REFERENCES console_geo_generations (digest) ON DELETE CASCADE,
    ordinal BIGINT NOT NULL CHECK (ordinal BETWEEN 0 AND 10485),
    ranges BYTEA NOT NULL
        CHECK (octet_length(ranges) BETWEEN 34 AND 3400 AND octet_length(ranges) % 34 = 0),
    PRIMARY KEY (digest, ordinal));

CREATE TABLE console_geo_active (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    revision BIGINT NOT NULL CHECK (revision >= 0),
    digest BYTEA REFERENCES console_geo_generations (digest),
    loaded_at BIGINT CHECK (loaded_at >= 0),
    actor BIGINT REFERENCES console_users (id),
    CHECK ((digest IS NULL) = (loaded_at IS NULL)),
    CHECK ((digest IS NULL) = (actor IS NULL)),
    CHECK ((digest IS NULL) = (revision = 0)));
INSERT INTO console_geo_active (id, revision) VALUES (1, 0);

CREATE TABLE console_minutes (
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 1 AND 4294967295),
    minute BIGINT NOT NULL CHECK (minute >= 0),
    start_ms BIGINT NOT NULL CHECK (start_ms >= 0),
    end_ms BIGINT NOT NULL,
    sealed BOOLEAN NOT NULL,
    payload BYTEA NOT NULL CHECK (octet_length(payload) = 176
        AND substring(payload FROM 1 FOR 4) = '\x53424d32'::bytea),
    PRIMARY KEY (node, boot, epoch, minute),
    CHECK (end_ms > start_ms));
CREATE INDEX console_minutes_time ON console_minutes (minute, node, boot, epoch);
CREATE INDEX console_minutes_node_time ON console_minutes (node, minute, boot, epoch);

CREATE TABLE console_challenge_minutes (
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    epoch BIGINT NOT NULL CHECK (epoch BETWEEN 1 AND 4294967295),
    minute BIGINT NOT NULL CHECK (minute >= 0),
    start_ms BIGINT NOT NULL CHECK (start_ms >= 0),
    end_ms BIGINT NOT NULL,
    sealed BOOLEAN NOT NULL,
    payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 128 AND 896
        AND (octet_length(payload) - 128) % 96 = 0
        AND substring(payload FROM 1 FOR 4) = '\x53424331'::bytea),
    PRIMARY KEY (node, boot, epoch, minute),
    CHECK (end_ms > start_ms));
CREATE INDEX console_challenge_minutes_time
    ON console_challenge_minutes (minute, node, boot, epoch);
CREATE INDEX console_challenge_minutes_node_time
    ON console_challenge_minutes (node, minute, boot, epoch);

CREATE TABLE console_challenge_records (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    second BIGINT NOT NULL CHECK (second >= 0),
    ip TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 48),
    outcome TEXT NOT NULL CHECK (outcome IN ('issued', 'accepted', 'rejected')),
    cause BIGINT CHECK (cause BETWEEN 0 AND 12),
    algorithm TEXT NOT NULL CHECK (algorithm IN ('hashcash', 'posw')),
    parameter BIGINT NOT NULL CHECK (parameter BETWEEN 0 AND 255),
    openings BIGINT NOT NULL CHECK (openings BETWEEN 0 AND 255),
    duration_ms BIGINT CHECK (duration_ms BETWEEN 0 AND 4294967295),
    CHECK ((outcome = 'rejected') = (cause IS NOT NULL)));
CREATE INDEX console_challenge_records_time ON console_challenge_records (second, id);
CREATE INDEX console_challenge_records_cause
    ON console_challenge_records (cause, second, id);
CREATE INDEX console_challenge_records_ip ON console_challenge_records (ip, second, id);

CREATE TABLE console_challenge_difficulty (
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    second BIGINT NOT NULL CHECK (second >= 0),
    previous_bits BIGINT NOT NULL CHECK (previous_bits BETWEEN 0 AND 255),
    bits BIGINT NOT NULL CHECK (bits BETWEEN 0 AND 255),
    rate_256 BIGINT NOT NULL CHECK (rate_256 >= 0),
    PRIMARY KEY (node, boot, second));
CREATE INDEX console_challenge_difficulty_time
    ON console_challenge_difficulty (second, node, boot);

CREATE TABLE console_rank_usage (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    charged_bytes BIGINT NOT NULL CHECK (charged_bytes BETWEEN 0 AND 536870912));
INSERT INTO console_rank_usage (id, charged_bytes) VALUES (1, 0);

CREATE TABLE console_rank_archives (
    digest BYTEA NOT NULL PRIMARY KEY CHECK (octet_length(digest) = 32),
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    minute BIGINT NOT NULL CHECK (minute >= 0),
    bytes BYTEA NOT NULL CHECK (octet_length(bytes) BETWEEN 92 AND 48536),
    charge BIGINT NOT NULL
        CHECK (charge = (octet_length(bytes) + 2047) / 2048 * 8192 + 1024),
    stored_at BIGINT NOT NULL CHECK (stored_at >= 0),
    UNIQUE (node, boot, minute));
CREATE INDEX console_rank_minute ON console_rank_archives (minute, digest);
CREATE INDEX console_rank_node ON console_rank_archives (node, minute, digest);

CREATE TABLE console_rule_hits (
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    rule_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(rule_key) BETWEEN 1 AND 160),
    generation BIGINT NOT NULL CHECK (generation >= 0),
    revision BIGINT NOT NULL CHECK (revision >= 0),
    name TEXT NOT NULL CHECK (octet_length(name) <= 128),
    minute BIGINT NOT NULL CHECK (minute >= 0),
    utc_start BIGINT NOT NULL CHECK (utc_start >= 0),
    utc_end BIGINT NOT NULL,
    start_ms BIGINT NOT NULL CHECK (start_ms >= 0),
    end_ms BIGINT NOT NULL,
    observed_ms BIGINT NOT NULL CHECK (observed_ms >= 0),
    observations BIGINT NOT NULL CHECK (observations >= 0),
    complete BOOLEAN NOT NULL,
    gap BOOLEAN NOT NULL,
    unconfirmed BIGINT NOT NULL CHECK (unconfirmed >= 0),
    hits BIGINT CHECK (hits >= 0),
    PRIMARY KEY (node, boot, sequence, rule_key),
    CHECK (utc_end >= utc_start AND end_ms >= start_ms));
CREATE INDEX console_rule_hits_history
    ON console_rule_hits (rule_key, node, minute, boot, sequence);
CREATE INDEX console_rule_hits_revision
    ON console_rule_hits (rule_key, node, revision, minute, boot, sequence);
CREATE INDEX console_rule_hits_retention ON console_rule_hits (minute);

CREATE TABLE console_rule_hit_rollups (
    grain BIGINT NOT NULL CHECK (grain IN (60, 1440)),
    node BIGINT NOT NULL CHECK (node BETWEEN 1 AND 8388607),
    boot BYTEA NOT NULL CHECK (octet_length(boot) = 16),
    generation BIGINT NOT NULL CHECK (generation >= 0),
    rule_key TEXT COLLATE "C" NOT NULL CHECK (octet_length(rule_key) BETWEEN 1 AND 160),
    bucket BIGINT NOT NULL CHECK (bucket >= 0 AND bucket % grain = 0),
    revision BIGINT NOT NULL CHECK (revision >= 0),
    name TEXT NOT NULL CHECK (octet_length(name) <= 128),
    hits BIGINT CHECK (hits >= 0),
    observed_ms BIGINT NOT NULL CHECK (observed_ms >= 0),
    intervals BIGINT NOT NULL CHECK (intervals >= 1),
    complete BIGINT NOT NULL CHECK (complete >= 0),
    gaps BIGINT NOT NULL CHECK (gaps >= 0),
    unconfirmed BIGINT NOT NULL CHECK (unconfirmed >= 0),
    through_minute BIGINT NOT NULL
        CHECK (through_minute >= bucket AND through_minute < bucket + grain),
    PRIMARY KEY (grain, node, boot, generation, rule_key, bucket));
CREATE INDEX console_rule_rollup_history
    ON console_rule_hit_rollups (rule_key, node, grain, bucket, boot, generation);
CREATE INDEX console_rule_rollup_retention ON console_rule_hit_rollups (bucket, grain);

CREATE TABLE console_incident_evidence (
    incident_id BIGINT PRIMARY KEY REFERENCES security_incidents (id) ON DELETE CASCADE,
    selected_status BIGINT NOT NULL CHECK (selected_status BETWEEN 100 AND 599),
    query_bytes BIGINT NOT NULL CHECK (query_bytes BETWEEN 0 AND 4294967295),
    body_bytes BIGINT NOT NULL CHECK (body_bytes BETWEEN 0 AND 4294967295),
    declared_body_bytes BIGINT NOT NULL
        CHECK (declared_body_bytes BETWEEN 0 AND 4294967295),
    truncated BIGINT NOT NULL CHECK (truncated BETWEEN 0 AND 255));

CREATE TABLE console_incident_heads (
    incident_id BIGINT PRIMARY KEY REFERENCES security_incidents (id) ON DELETE CASCADE,
    request_head BYTEA NOT NULL CHECK (octet_length(request_head) <= 2048),
    response_head BYTEA NOT NULL CHECK (octet_length(response_head) <= 1024),
    request_truncated BOOLEAN NOT NULL,
    response_truncated BOOLEAN NOT NULL,
    response_state TEXT NOT NULL
        CHECK (response_state IN ('captured', 'local', 'unobserved', 'unavailable')),
    CHECK (response_state = 'captured'
        OR (octet_length(response_head) = 0 AND NOT response_truncated)));

CREATE TABLE console_incident_country (
    incident_id BIGINT PRIMARY KEY REFERENCES security_incidents (id) ON DELETE CASCADE,
    country TEXT CHECK (country ~ '^[A-Z]{2}$'),
    generation BYTEA NOT NULL CHECK (octet_length(generation) = 32));
CREATE INDEX console_incident_country_code ON console_incident_country (country, incident_id);
"#;
