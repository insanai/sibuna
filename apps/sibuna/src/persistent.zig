//! Zaxonlite Persistent Layer (SID 0005)
//!
//! Durable, optionally replicated state behind the in-memory hot path:
//! dynamic policies, IP reputation, and incident forensics with full-text
//! and vector search. SQL and maintenance run on a storage thread. Workers hand
//! incidents to a lock-free ring and pin an immutable `EngineSlot`; this
//! module's single storage thread drains the ring into batched SQL
//! transactions, polls the policy tables for changes, rebuilds the inactive
//! engine slot, and publishes it with read-copy-update semantics.
//!
//! Single-node mode embeds a Zaxonlite `Node` (journal, payload store,
//! SQLite image in one data directory). Cluster mode uses the `Embedded`
//! facade so the same SQL replicates across voters by Multi-Paxos.

const std = @import("std");
const Io = std.Io;
const build_options = @import("build_options");
const zx = @import("zaxonlite");
const core = @import("core");
const policy = @import("policy");
const store = @import("store");
const server = @import("server.zig");

pub const schema = [_][]const u8{
    @import("policy_inspection.zig").table_sql,
    "CREATE TABLE IF NOT EXISTS sibuna_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS policies (" ++
        "id TEXT PRIMARY KEY, name TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 100, " ++
        "path_pattern TEXT, ua_pattern TEXT, action TEXT NOT NULL, difficulty INTEGER, " ++
        "algorithm TEXT, header_matchers TEXT, cidr_matchers TEXT, " ++
        "weight INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, " ++
        "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,limit_config TEXT)",
    "CREATE TABLE IF NOT EXISTS ip_reputation (" ++
        "ip_or_cidr TEXT PRIMARY KEY, reputation_score INTEGER NOT NULL, banned_until INTEGER, " ++
        "trigger_rule TEXT, hits INTEGER NOT NULL DEFAULT 1, last_seen INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS security_incidents (" ++
        "id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL, client_ip TEXT NOT NULL, " ++
        "user_agent TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, " ++
        "violation_category TEXT NOT NULL, offending_payload TEXT NOT NULL, " ++
        "campaign_id INTEGER, recorded_at INTEGER NOT NULL)",
    "CREATE VIRTUAL TABLE IF NOT EXISTS incidents_fts USING fts5(" ++
        "path, offending_payload, content='security_incidents', content_rowid='id')",
    "CREATE VIRTUAL TABLE IF NOT EXISTS incidents_vec USING vec0(" ++
        "item_id INTEGER PRIMARY KEY, embedding float[64] distance_metric=cosine, " ++
        "embedding_coarse bit[64])",
};

/// Cosine distance below which an incident joins the nearest campaign.
pub const campaign_distance: f32 = 0.35;
pub const incident_batch = 32;

pub const IncidentRecord = struct {
    ip: [48]u8 = undefined,
    ip_len: u8 = 0,
    ua: [200]u8 = undefined,
    ua_len: u8 = 0,
    method: [8]u8 = undefined,
    method_len: u8 = 0,
    path: [512]u8 = undefined,
    path_len: u16 = 0,
    category: [32]u8 = undefined,
    category_len: u8 = 0,
    payload: [512]u8 = undefined,
    payload_len: u16 = 0,
    now: u64 = 0,
    evidence: if (build_options.console) core.IncidentEvidence else void =
        if (build_options.console) .{} else {},

    fn copy(dst: []u8, src: []const u8) usize {
        const n = @min(dst.len, src.len);
        @memcpy(dst[0..n], src[0..n]);
        return n;
    }

    fn from(incident: server.Incident) IncidentRecord {
        var r = IncidentRecord{ .now = incident.now };
        r.ip_len = @intCast(copy(&r.ip, incident.client_ip));
        r.ua_len = @intCast(copy(&r.ua, incident.user_agent));
        r.method_len = @intCast(copy(&r.method, incident.method));
        r.path_len = @intCast(copy(&r.path, incident.path));
        r.category_len = @intCast(copy(&r.category, incident.category));
        r.payload_len = @intCast(copy(&r.payload, incident.payload));
        if (build_options.console) {
            r.evidence = incident.evidence;
            const lengths = [_]bool{
                incident.client_ip.len > r.ip.len,
                incident.user_agent.len > r.ua.len,
                incident.method.len > r.method.len,
                incident.path.len > r.path.len,
                incident.category.len > r.category.len,
                incident.payload.len > r.payload.len,
                r.evidence.body_bytes < r.evidence.declared_body_bytes,
            };
            for (lengths, 0..) |truncated, bit| {
                if (truncated) r.evidence.truncated |= @as(u16, 1) << @intCast(bit);
            }
        }
        return r;
    }
};

pub const IncidentQueue = store.BoundedQueue(IncidentRecord, 512);

const Db = @import("database.zig").Db;
const console = if (build_options.console) @import("console") else struct {};

pub const Persistent = struct {
    console_mailbox: if (build_options.console) console.Mailbox else void =
        if (build_options.console) .{} else {},
    console_initialized: bool = false,
    gpa: std.mem.Allocator,
    io: Io,
    cfg: core.Config,
    state: *server.AppState,
    policy_text: ?[]const u8,
    db: Db,
    queue: IncidentQueue,
    pending: [incident_batch]IncidentRecord = undefined,
    pending_len: usize = 0,
    pending_sql: ?[]u8 = null,
    /// Two engine buffers: one live, one being rebuilt. `owned_slot` is the
    /// one this layer allocated; the other belongs to the caller.
    spare: *server.EngineSlot,
    owned_slot: *server.EngineSlot,
    arenas: [2]std.heap.ArenaAllocator,
    version: u64 = 0,
    reputation_expires: u64 = std.math.maxInt(u64),
    next_incident: u64 = 1,
    node_id: u32 = 1,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn start(
        gpa: std.mem.Allocator,
        io: Io,
        cfg: core.Config,
        state: *server.AppState,
        policy_text: ?[]const u8,
    ) !*Persistent {
        const self = try open(gpa, io, cfg, state, policy_text);
        errdefer self.stop();
        self.thread = try std.Thread.spawn(.{}, worker, .{self});
        return self;
    }

    /// Opens the store and performs the initial load without starting the
    /// background thread; tests drive `tick` directly.
    pub fn open(
        gpa: std.mem.Allocator,
        io: Io,
        cfg: core.Config,
        state: *server.AppState,
        policy_text: ?[]const u8,
    ) !*Persistent {
        // Incident IDs occupy SQLite's positive signed 64-bit domain.
        if (cfg.cluster_node >= 0x80_0000) return error.IncidentNodeIdTooLarge;
        const self = try gpa.create(Persistent);
        errdefer gpa.destroy(self);
        const spare = try gpa.create(server.EngineSlot);
        errdefer gpa.destroy(spare);
        const spare_engine = try gpa.create(policy.Engine);
        errdefer gpa.destroy(spare_engine);
        spare.* = .{ .engine = spare_engine };
        self.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .state = state,
            .policy_text = policy_text,
            .db = undefined,
            .queue = IncidentQueue.init(),
            .spare = spare,
            .owned_slot = spare,
            .arenas = .{ std.heap.ArenaAllocator.init(gpa), std.heap.ArenaAllocator.init(gpa) },
            .node_id = if (cfg.cluster_node == 0) 1 else cfg.cluster_node,
        };
        self.db = try openDb(self);
        errdefer self.db.close();
        errdefer {
            self.arenas[0].deinit();
            self.arenas[1].deinit();
        }
        try self.initializeStore();
        state.hooks = .{ .context = self, .record_incident = recordIncidentHook };
        return self;
    }

    pub fn stop(self: *Persistent) void {
        if (build_options.console) self.console_mailbox.stop(self.io);
        self.stopping.store(true, .release);
        if (self.thread) |t| t.join();
        self.state.hooks = .{};
        // Producers have stopped. Flush every bounded batch, then account
        // records whose commit could not be confirmed before shutdown.
        while (true) {
            self.drain() catch |err| {
                std.log.err("storage shutdown could not confirm pending incidents: {t}", .{err});
                break;
            };
            self.fillPending();
            if (self.pending_len == 0) break;
        }
        if (self.pending_sql) |sql| self.gpa.free(sql);
        self.db.close();
        // Make sure the caller's slot is live again before the owned one
        // is freed, so no worker can still be pinned on freed memory.
        if (self.state.slot.load(.acquire) == self.owned_slot) {
            _ = self.state.publishEngine(self.spare);
        }
        self.arenas[0].deinit();
        self.arenas[1].deinit();
        self.gpa.destroy(self.owned_slot.engine);
        self.gpa.destroy(self.owned_slot);
        self.gpa.destroy(self);
    }

    fn openDb(self: *Persistent) !Db {
        const dir = self.cfg.data_dir orelse return error.NoDataDir;
        if (self.cfg.cluster_node == 0) {
            return .{ .node = try zx.Node.open(self.gpa, self.io, .{ .directory = dir }) };
        }
        if (!build_options.cluster) return error.ClusterSupportNotBuilt;
        return .{ .embedded = try openCluster(self, dir) };
    }

    fn openCluster(self: *Persistent, dir: []const u8) !*zx.Embedded {
        if (!build_options.cluster) return error.ClusterSupportNotBuilt;
        var members: [core.max_cluster_peers + 1]zx.EmbeddedMember = undefined;
        var count: usize = 0;
        members[count] = .{
            .id = self.cfg.cluster_node,
            .address = self.cfg.cluster_listen orelse return error.ClusterListenRequired,
        };
        count += 1;
        for (self.cfg.cluster_peers[0..self.cfg.cluster_peer_count]) |spec| {
            members[count] = try parsePeer(spec);
            count += 1;
        }
        var secret_buf: [256]u8 = undefined;
        const secret = if (self.cfg.cluster_secret_file) |path|
            try readSecretFile(self.io, path, &secret_buf)
        else
            null;
        const tls: ?zx.TlsConfig = if (self.cfg.cluster_tls_cert) |cert| .{
            .cert_path = cert,
            .key_path = self.cfg.cluster_tls_key orelse return error.ClusterTlsKeyRequired,
            .ca_path = self.cfg.cluster_tls_ca orelse return error.ClusterTlsCaRequired,
        } else null;
        return zx.Embedded.open(self.gpa, self.io, .{
            .directory = dir,
            .node_id = self.cfg.cluster_node,
            .members = members[0..count],
            .cluster_id = "sibuna",
            .auth_secret = secret,
            .tls = tls,
            // Without certificates the only permitted transport is the
            // loopback development PSK, mirroring `zaxon --dev-psk`.
            .allow_psk_only_loopback = tls == null,
        });
    }

    /// `id@host:port[/role]`, role defaulting to data-voter.
    fn parsePeer(spec: []const u8) !zx.EmbeddedMember {
        const at = std.mem.indexOfScalar(u8, spec, '@') orelse return error.InvalidPeerSpec;
        const id = try std.fmt.parseInt(u32, spec[0..at], 10);
        var rest = spec[at + 1 ..];
        var role: zx.Role = .data_voter;
        if (std.mem.lastIndexOfScalar(u8, rest, '/')) |slash| {
            role = try zx.Role.parse(rest[slash + 1 ..]);
            rest = rest[0..slash];
        }
        return .{ .id = id, .address = rest, .role = role };
    }

    fn readSecretFile(io: Io, path: []const u8, buf: []u8) ![]const u8 {
        const file = try Io.Dir.openFile(.cwd(), io, path, .{});
        defer file.close(io);
        var rbuf: [512]u8 = undefined;
        var reader = file.reader(io, &rbuf);
        const content = try reader.interface.peekGreedy(1);
        const trimmed = std.mem.trimEnd(u8, content, "\r\n");
        if (trimmed.len > buf.len) return error.SecretTooLong;
        @memcpy(buf[0..trimmed.len], trimmed);
        return buf[0..trimmed.len];
    }

    fn initializeStore(self: *Persistent) !void {
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            self.initializeAttempt() catch |err| {
                // A listening cluster member may not yet have a stable leader.
                // Only idempotent startup work is retried, never incident writes.
                if (self.cfg.cluster_node == 0 or attempt >= 29) return err;
                std.debug.print("storage: startup retry {d}: {t}\n", .{ attempt + 1, err });
                try Io.sleep(self.io, Io.Duration.fromMilliseconds(100), .awake);
                continue;
            };
            return;
        }
    }

    fn initializeAttempt(self: *Persistent) !void {
        try self.migrate();
        try self.loadIncidentCounter();
        const stamp = try self.policyVersion();
        try self.rebuild();
        self.version = stamp;
    }

    fn migrate(self: *Persistent) !void {
        // One transaction exposes a complete schema and avoids one
        // consensus round trip per DDL statement on every starting node.
        var sql = Io.Writer.Allocating.init(self.gpa);
        defer sql.deinit();
        const w = &sql.writer;
        for (schema) |statement| try w.print("{s};", .{statement});
        try w.writeAll(
            "INSERT OR IGNORE INTO sibuna_meta(key,value) VALUES ('policy_version','0');",
        );
        // Triggers also cover direct SQL writes and updates within one second.
        inline for (.{ "policies", "ip_reputation", "policy_inspection" }) |table| {
            inline for (.{ "INSERT", "UPDATE", "DELETE" }) |event| {
                try w.writeAll("CREATE TRIGGER IF NOT EXISTS version_" ++
                    table ++ "_" ++ event ++ " AFTER " ++ event ++ " ON " ++ table ++
                    " BEGIN UPDATE sibuna_meta SET value = CAST(value AS INTEGER) + 1 " ++
                    "WHERE key = 'policy_version'; END;");
            }
        }
        try self.db.exec(self.gpa, sql.written());
        try @import("policy_limits.zig").migrate(self);
    }

    /// The receipt survives retention. Deriving identity only from remaining rows could
    /// reuse IDs and make the replay guard silently suppress future committed batches.
    fn loadIncidentCounter(self: *Persistent) !void {
        const sql = try std.fmt.allocPrint(
            self.gpa,
            "SELECT COALESCE(MAX(id),0),COALESCE((SELECT value FROM sibuna_meta " ++
                "WHERE key='incident_cursor_{d}'),'1') " ++
                "FROM security_incidents WHERE id >> 40 = {d}",
            .{ self.node_id, self.node_id },
        );
        defer self.gpa.free(sql);
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        if (result.rows.len != 1) return error.InvalidIncidentCursor;
        const row = result.rows[0];
        const max = try std.fmt.parseInt(
            u64,
            row[0] orelse return error.InvalidIncidentCursor,
            10,
        );
        const receipt = try std.fmt.parseInt(
            u64,
            row[1] orelse return error.InvalidIncidentCursor,
            10,
        );
        if (receipt == 0 or receipt > 0x100_0000_0000) return error.InvalidIncidentCursor;
        self.next_incident = @max((max & 0xff_ffff_ffff) + 1, receipt);
    }

    fn worker(self: *Persistent) void {
        const interval: u64 = @max(50, self.cfg.storage_poll_ms);
        var next_tick: i96 = 0;
        while (!self.stopping.load(.acquire)) {
            const now = Io.Clock.awake.now(self.io).nanoseconds;
            if (now >= next_tick) {
                self.tick() catch |err| {
                    std.debug.print("storage: tick failed: {t}\n", .{err});
                };
                next_tick = now + @as(i96, interval) * std.time.ns_per_ms;
            } else if (build_options.console) @import("console_store.zig").tick(self);
            const remaining = @max(0, next_tick - Io.Clock.awake.now(self.io).nanoseconds);
            const wait_ms: u64 = @intCast(@divTrunc(remaining, std.time.ns_per_ms));
            if (build_options.console) {
                self.console_mailbox.wait(self.io, wait_ms) catch return;
            } else {
                Io.sleep(self.io, .fromMilliseconds(@intCast(wait_ms)), .awake) catch return;
            }
        }
    }

    /// One maintenance round: persist queued incidents, then reload the
    /// policy tables if anything changed.
    pub fn tick(self: *Persistent) !void {
        if (build_options.console) @import("console_store.zig").tick(self);
        // A stalled incident commit must not starve policy/reputation reads.
        self.drain() catch |err| {
            _ = self.state.metrics.incident_write_failures.fetchAdd(1, .monotonic);
            std.log.warn("storage retains pending batch after: {t}", .{err});
        };
        const stamp = try self.policyVersion();
        const now = self.nowSeconds();
        if (stamp != self.version or now >= self.reputation_expires) {
            try self.rebuild();
            // A failed rebuild must be retried; never acknowledge it early.
            self.version = stamp;
        }
    }

    fn fillPending(self: *Persistent) void {
        if (self.pending_len != 0) return;
        while (self.pending_len < incident_batch) {
            self.pending[self.pending_len] = self.queue.pop() orelse break;
            self.pending_len += 1;
        }
    }

    fn drain(self: *Persistent) !void {
        self.fillPending();
        if (self.pending_len == 0) return;
        if (self.pending_sql == null) {
            var sql = Io.Writer.Allocating.init(self.gpa);
            defer sql.deinit();
            const w = &sql.writer;
            if (self.next_incident + self.pending_len > 0x100_0000_0000)
                return error.IncidentIdExhausted;
            for (self.pending[0..self.pending_len], 0..) |*rec, index| {
                try self.appendIncident(w, rec, self.next_incident + index);
            }
            // One receipt per issuer, in the same transaction as all indexes
            // and reputation changes. An ambiguous reply can replay this exact
            // SQL safely, even if the first attempt committed on another leader.
            try w.print(
                "INSERT INTO sibuna_meta(key,value) VALUES ('incident_cursor_{d}','{d}') " ++
                    "ON CONFLICT(key) DO UPDATE SET value=MAX(CAST(value AS INTEGER)," ++
                    "CAST(excluded.value AS INTEGER));",
                .{ self.node_id, self.next_incident + self.pending_len },
            );
            self.pending_sql = try self.gpa.dupe(u8, sql.written());
        }
        try self.db.exec(self.gpa, self.pending_sql.?);
        _ = self.state.metrics.incidents_persisted.fetchAdd(self.pending_len, .monotonic);
        _ = self.state.metrics.incident_batches.fetchAdd(1, .monotonic);
        self.next_incident += self.pending_len;
        self.pending_len = 0;
        self.gpa.free(self.pending_sql.?);
        self.pending_sql = null;
    }

    fn receiptGuard(self: *Persistent, w: *Io.Writer) !void {
        try w.print(" WHERE COALESCE((SELECT CAST(value AS INTEGER) FROM sibuna_meta " ++
            "WHERE key='incident_cursor_{d}'),0)<{d}", .{
            self.node_id,
            self.next_incident + self.pending_len,
        });
    }

    fn recordIncidentHook(ctx: ?*anyopaque, incident: server.Incident) void {
        const self: *Persistent = @ptrCast(@alignCast(ctx orelse return));
        if (!self.queue.push(IncidentRecord.from(incident))) {
            _ = self.state.metrics.incidents_dropped.fetchAdd(1, .monotonic);
        }
    }

    fn appendIncident(
        self: *Persistent,
        w: *Io.Writer,
        rec: *const IncidentRecord,
        sequence: u64,
    ) !void {
        const payload = rec.payload[0..rec.payload_len];
        const vector = policy.embedding.embed(payload);
        const bytes = policy.embedding.toBytes(&vector);
        var hex_buf: [bytes.len * 2]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{&bytes}) catch unreachable;
        const id = (@as(u64, self.node_id) << 40) | sequence;
        try w.print(
            "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
                "violation_category,offending_payload,campaign_id,recorded_at) SELECT {d},{d},",
            .{ id, self.node_id },
        );
        try quote(w, rec.ip[0..rec.ip_len]);
        try w.writeAll(",");
        try quote(w, rec.ua[0..rec.ua_len]);
        try w.writeAll(",");
        try quote(w, rec.method[0..rec.method_len]);
        try w.writeAll(",");
        try quote(w, rec.path[0..rec.path_len]);
        try w.writeAll(",");
        try quote(w, rec.category[0..rec.category_len]);
        try w.writeAll(",");
        try quote(w, payload);
        try w.print(",COALESCE((SELECT CASE WHEN v.distance <= {d} THEN s.campaign_id " ++
            "ELSE NULL END FROM incidents_vec v JOIN security_incidents s ON s.id=v.item_id " ++
            "WHERE v.embedding MATCH X'{s}' AND k=1),{d}),{d}", .{
            campaign_distance,
            hex,
            id,
            rec.now,
        });
        try self.receiptGuard(w);
        try w.writeAll("; ");
        try w.print("INSERT INTO incidents_fts(rowid,path,offending_payload) SELECT {d},", .{id});
        try quote(w, rec.path[0..rec.path_len]);
        try w.writeAll(",");
        try quote(w, payload);
        try self.receiptGuard(w);
        try w.print("; INSERT INTO incidents_vec(item_id,embedding,embedding_coarse) " ++
            "SELECT {d},X'{s}',vec_quantize_binary(X'{s}')", .{ id, hex, hex });
        try self.receiptGuard(w);
        if (std.mem.eql(u8, rec.category[0..rec.category_len], "honeypot")) {
            try w.writeAll("; ");
            try w.writeAll("INSERT INTO ip_reputation(ip_or_cidr,reputation_score,banned_until," ++
                "trigger_rule,hits,last_seen) SELECT ");
            try quote(w, rec.ip[0..rec.ip_len]);
            try w.print(
                ",-100,{d},'honeypot',1,{d}",
                .{ rec.now +| self.cfg.ban_seconds, rec.now },
            );
            try self.receiptGuard(w);
            try w.writeAll(" ON CONFLICT(ip_or_cidr) DO UPDATE SET hits=hits+1," ++
                "reputation_score=-100," ++
                "banned_until=MAX(COALESCE(banned_until,0),excluded.banned_until)," ++
                "trigger_rule='honeypot',last_seen=MAX(last_seen,excluded.last_seen)");
        }
        try w.writeAll("; ");
        if (build_options.console) if (rec.evidence.version != 0) {
            try @import("console_evidence.zig").append(w, id, rec.evidence);
            try self.receiptGuard(w);
            try w.writeAll("; ");
        };
    }

    fn reputationUpsert(
        w: *Io.Writer,
        ip: []const u8,
        score: i32,
        until: u64,
        trigger: []const u8,
        now: u64,
    ) !void {
        try w.writeAll("INSERT INTO ip_reputation(ip_or_cidr,reputation_score,banned_until," ++
            "trigger_rule,hits,last_seen) VALUES (");
        try quote(w, ip);
        try w.print(",{d},{d},", .{ score, until });
        try quote(w, trigger);
        try w.print(",1,{d}) ON CONFLICT(ip_or_cidr) DO UPDATE SET hits = hits + 1, " ++
            "last_seen = excluded.last_seen, banned_until = excluded.banned_until, " ++
            "reputation_score = MIN(reputation_score, excluded.reputation_score)", .{now});
    }

    /// Bans `ip` cluster-wide (visible to every node on its next rebuild).
    pub fn banAddress(
        self: *Persistent,
        ip: []const u8,
        until: u64,
        trigger: []const u8,
        now: u64,
    ) !void {
        var sql = Io.Writer.Allocating.init(self.gpa);
        defer sql.deinit();
        try reputationUpsert(&sql.writer, ip, -100, until, trigger, now);
        try self.db.exec(self.gpa, sql.written());
    }

    fn nowSeconds(self: *const Persistent) u64 {
        return @intCast(@max(
            0,
            @divTrunc(Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_s),
        ));
    }

    fn policyVersion(self: *Persistent) !u64 {
        var result = try self.db.query(
            self.gpa,
            "SELECT value FROM sibuna_meta WHERE key = 'policy_version'",
        );
        defer result.deinit();
        if (result.rows.len != 1) return error.MissingPolicyVersion;
        return std.fmt.parseInt(u64, result.rows[0][0] orelse
            return error.MissingPolicyVersion, 10);
    }

    /// Rebuilds the spare engine from file policy, database policies, and
    /// reputation, then publishes it. The previously live slot becomes the
    /// spare once its readers have drained.
    pub fn rebuild(self: *Persistent) !void {
        const which: usize = if (self.spare == self.owned_slot) 1 else 0;
        _ = self.arenas[which].reset(.retain_capacity);
        const arena = self.arenas[which].allocator();
        const engine = self.spare.engine;
        engine.initInPlace(self.cfg.default_difficulty);
        engine.waf_enabled = self.cfg.waf;
        if (self.policy_text) |text| try engine.loadFromJsonInto(arena, text);
        try @import("policy_inspection.zig").apply(self, engine);
        try self.loadDbPolicies(engine, arena);
        try self.loadReputation(engine);
        self.spare = self.state.publishEngine(self.spare);
    }

    fn loadDbPolicies(self: *Persistent, engine: *policy.Engine, arena: std.mem.Allocator) !void {
        const sql = "SELECT name, path_pattern, ua_pattern, action, difficulty, algorithm, " ++
            "header_matchers,cidr_matchers,weight,id,limit_config " ++
            "FROM policies WHERE enabled = 1 " ++
            "ORDER BY priority, name, id";
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        // Dynamic rules precede file/default rules so generic admission
        // rules cannot hide an operator's live denial.
        const fallback_count = engine.rule_count;
        engine.rule_count = 0;
        for (result.rows) |row| {
            const name = row[0] orelse continue;
            const action = policy.Action.parse(row[3] orelse continue) orelse continue;
            var r = policy.PolicyRule{ .name = try arena.dupe(u8, name), .action = action };
            r.limit_identity = policy.rule_limits.managedIdentity(row[9].?);
            if (row[10]) |text| r.limits = try @import("policy_limits.zig").parse(arena, text);
            if (row[1]) |p| r.path_pattern = try arena.dupe(u8, p);
            if (row[2]) |u| r.ua_pattern = try arena.dupe(u8, u);
            if (row[4]) |d| r.difficulty = std.fmt.parseInt(u32, d, 10) catch null;
            if (row[5]) |a| r.algorithm = try arena.dupe(u8, a);
            if (row[8]) |wt| r.weight = std.fmt.parseInt(i32, wt, 10) catch 0;
            if (row[6]) |h| try parseHeaderMatchers(arena, h, &r);
            if (row[7]) |c| parseCidrMatchers(c, &r);
            if (engine.rule_count + fallback_count >= policy.engine.MAX_RULES)
                return error.TooManyRules;
            const index = engine.rule_count;
            std.mem.copyBackwards(
                policy.PolicyRule,
                engine.rules[index + 1 .. index + 1 + fallback_count],
                engine.rules[index .. index + fallback_count],
            );
            try engine.addRule(r);
        }
        engine.rule_count += fallback_count;
    }

    fn parseHeaderMatchers(
        arena: std.mem.Allocator,
        text: []const u8,
        r: *policy.PolicyRule,
    ) !void {
        var parsed = std.json.parseFromSlice(std.json.Value, arena, text, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;
        var it = parsed.value.object.iterator();
        while (it.next()) |entry| {
            if (r.header_count >= policy.rule.MAX_RULE_HEADERS) break;
            if (entry.value_ptr.* != .string) continue;
            r.headers[r.header_count] = .{
                .name = try arena.dupe(u8, entry.key_ptr.*),
                .pattern = try arena.dupe(u8, entry.value_ptr.*.string),
            };
            r.header_count += 1;
        }
    }

    fn parseCidrMatchers(text: []const u8, r: *policy.PolicyRule) void {
        var it = std.mem.tokenizeAny(u8, text, "[]\", ");
        while (it.next()) |cidr| {
            if (r.cidr_count >= policy.rule.MAX_RULE_CIDRS) break;
            if (policy.rule.CidrMatcher.parse(cidr)) |m| {
                r.cidrs[r.cidr_count] = m;
                r.cidr_count += 1;
            }
        }
    }

    fn loadReputation(self: *Persistent, engine: *policy.Engine) !void {
        const now: u64 = @intCast(
            @max(0, @divTrunc(Io.Clock.real.now(self.io).nanoseconds, std.time.ns_per_s)),
        );
        const sql = try std.fmt.allocPrint(
            self.gpa,
            "SELECT ip_or_cidr, reputation_score, banned_until FROM ip_reputation " ++
                "WHERE (banned_until IS NULL OR banned_until > {d}) " ++
                "AND (reputation_score <= -50 OR reputation_score >= 50)",
            .{now},
        );
        defer self.gpa.free(sql);
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        self.reputation_expires = std.math.maxInt(u64);
        for (result.rows) |row| {
            if (row[2]) |expiry| {
                self.reputation_expires = @min(
                    self.reputation_expires,
                    try std.fmt.parseInt(u64, expiry, 10),
                );
            }
            const cidr = row[0] orelse continue;
            const score = std.fmt.parseInt(i32, row[1] orelse continue, 10) catch continue;
            try engine.ip_trie.insertCidr(cidr, if (score < 0) .deny else .allow);
        }
    }

    /// Full-text forensic search over recorded incidents.
    pub fn searchIncidents(
        self: *Persistent,
        gpa: std.mem.Allocator,
        match: []const u8,
        limit: u32,
    ) !zx.QueryResult {
        var sql = Io.Writer.Allocating.init(gpa);
        defer sql.deinit();
        try sql.writer.writeAll("SELECT s.id, s.client_ip, s.violation_category, s.path, " ++
            "s.campaign_id FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid " ++
            "WHERE incidents_fts MATCH ");
        try quote(&sql.writer, match);
        try sql.writer.print(" ORDER BY rank LIMIT {d}", .{limit});
        return self.db.query(gpa, sql.written());
    }
};

/// SQL string literal with embedded quotes doubled.
fn quote(w: *Io.Writer, text: []const u8) !void {
    try w.writeByte('\'');
    for (text) |c| {
        if (c == '\'') try w.writeByte('\'');
        if (c == 0) continue;
        try w.writeByte(c);
    }
    try w.writeByte('\'');
}

test "sql quoting doubles single quotes and drops nul" {
    var buf: [64]u8 = undefined;
    var w = Io.Writer.fixed(&buf);
    try quote(&w, "it's\x00 a 'test'");
    try std.testing.expectEqualStrings("'it''s a ''test'''", w.buffered());
}

test "peer spec parsing" {
    const a = try Persistent.parsePeer("2@10.0.0.2:9901");
    try std.testing.expectEqual(@as(u32, 2), a.id);
    try std.testing.expectEqualStrings("10.0.0.2:9901", a.address);
    try std.testing.expectEqual(zx.Role.data_voter, a.role);
    const b = try Persistent.parsePeer("7@[::1]:9903/witness");
    try std.testing.expectEqual(zx.Role.witness, b.role);
    try std.testing.expectEqualStrings("[::1]:9903", b.address);
    try std.testing.expectError(error.InvalidPeerSpec, Persistent.parsePeer("nope"));
}

const TestFixture = struct {
    engine: policy.Engine = undefined,
    slot: server.EngineSlot = undefined,
    state: server.AppState = undefined,
};

test "incident identity survives removal of all rows and rejects exhausted or corrupt receipts" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var path: [128]u8 = undefined;
    const fx = try t.allocator.create(TestFixture);
    defer t.allocator.destroy(fx);
    var cfg = core.Config.default();
    cfg.data_dir = try std.fmt.bufPrint(&path, ".zig-cache/tmp/{s}/cursor", .{tmp.sub_path});
    fx.engine.initInPlace(cfg.default_difficulty);
    fx.slot = .{ .engine = &fx.engine };
    fx.state.init(cfg, &fx.slot, &@as([32]u8, @splat(1)));
    const event: server.Incident = .{
        .client_ip = "198.51.100.99",
        .user_agent = "test",
        .method = "GET",
        .path = "/trap",
        .category = "honeypot",
        .payload = "repeat",
        .now = 100,
    };
    {
        const owner = try Persistent.open(t.allocator, t.io, cfg, &fx.state, null);
        defer owner.stop();
        Persistent.recordIncidentHook(owner, event);
        try owner.tick();
        try t.expectEqual(@as(u64, 2), owner.next_incident);
        // Simulate retention's removal without changing the durable receipt.
        const remove = "INSERT INTO incidents_fts(incidents_fts,rowid,path," ++
            "offending_payload) SELECT 'delete',id,path,offending_payload " ++
            "FROM security_incidents;" ++
            "DELETE FROM incidents_vec; DELETE FROM security_incidents;";
        try owner.db.exec(t.allocator, remove);
    }
    // Reset the caller-owned engine pointer before reopening the store.
    fx.slot = .{ .engine = &fx.engine };
    fx.state.init(cfg, &fx.slot, &@as([32]u8, @splat(1)));
    const owner = try Persistent.open(t.allocator, t.io, cfg, &fx.state, null);
    defer owner.stop();
    try t.expectEqual(@as(u64, 2), owner.next_incident);
    Persistent.recordIncidentHook(owner, event);
    try owner.tick();
    var rows = try owner.db.query(t.allocator, "SELECT COUNT(*),MIN(id & 1099511627775) " ++
        "FROM security_incidents");
    defer rows.deinit();
    try t.expectEqualStrings("1", rows.rows[0][0].?);
    try t.expectEqualStrings("2", rows.rows[0][1].?);
    try owner.db.exec(t.allocator, "DELETE FROM sibuna_meta WHERE key='incident_cursor_1'");
    try owner.loadIncidentCounter();
    try t.expectEqual(@as(u64, 3), owner.next_incident);
    try owner.db.exec(t.allocator, "INSERT INTO sibuna_meta VALUES " ++
        "('incident_cursor_1','1099511627776')");
    try owner.loadIncidentCounter();
    Persistent.recordIncidentHook(owner, event);
    try t.expectError(error.IncidentIdExhausted, owner.drain());
    // The exhausted fixture cannot flush; the production shutdown reports this failure.
    owner.pending_len = 0;
    try owner.db.exec(t.allocator, "UPDATE sibuna_meta SET value='0' " ++
        "WHERE key='incident_cursor_1'");
    try t.expectError(error.InvalidIncidentCursor, owner.loadIncidentCounter());
}

test "persistent store: policy reload, reputation, forensics, campaigns" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [128]u8 = undefined;
    const data_dir = try std.fmt.bufPrint(
        &path_buf,
        ".zig-cache/tmp/{s}/sibuna-data",
        .{tmp.sub_path},
    );

    const fx = try gpa.create(TestFixture);
    defer gpa.destroy(fx);
    var cfg = core.Config.default();
    cfg.data_dir = data_dir;
    cfg.default_difficulty = 12;
    fx.engine.initInPlace(cfg.default_difficulty);
    fx.slot = .{ .engine = &fx.engine };
    const seed = [_]u8{1} ** 32;
    fx.state.init(cfg, &fx.slot, &seed);

    const p = try Persistent.open(
        gpa,
        io,
        cfg,
        &fx.state,
        "{\"rules\":[{\"name\":\"file-rule\",\"path\":\"/from-file\",\"action\":\"ALLOW\"}]}",
    );
    defer p.stop();

    // File policy survives the rebuild; nothing else is loaded yet.
    const live = fx.state.acquireEngine();
    try std.testing.expectEqual(
        policy.Action.allow,
        live.engine.evaluate("/from-file", "9.9.9.9", "curl").action,
    );
    try std.testing.expectEqual(
        policy.Action.challenge,
        live.engine.evaluate("/secret", "9.9.9.9", "curl").action,
    );
    server.AppState.releaseEngine(live);

    // A dynamic policy and a reputation ban appear after one tick.
    try p.db.exec(gpa, "INSERT INTO policies(id,name,priority,path_pattern,action,difficulty," ++
        "algorithm,header_matchers,cidr_matchers,weight,enabled,created_at,updated_at) " ++
        "VALUES ('p1','protect-secret',10,'/secret/*','CHALLENGE',20,'posw'," ++
        "'{\"X-Api\":\"v2\"}','[\"10.0.0.0/8\"]',0,1,100,100)");
    try p.banAddress("198.51.100.7", 4102444800, "test", 100);
    try p.tick();
    const fresh = fx.state.acquireEngine();
    try std.testing.expect(fresh != live);
    const hdrs = [_]policy.Header{.{ .name = "X-Api", .value = "v2" }};
    const d = fresh.engine.evaluateWithHeaders("/secret/x", "10.1.2.3", "curl", &hdrs);
    try std.testing.expectEqual(policy.Action.challenge, d.action);
    try std.testing.expectEqualStrings("protect-secret", d.rule_name);
    try std.testing.expectEqual(@as(u32, 20), d.difficulty);
    try std.testing.expectEqualStrings("posw", d.algorithm.?);
    try std.testing.expectEqual(
        policy.Action.deny,
        fresh.engine.evaluate("/", "198.51.100.7", "Mozilla").action,
    );
    // Release before the next rebuild: a publisher waits for readers to drain.
    server.AppState.releaseEngine(fresh);

    // Repeated updates with identical timestamps must reload, and each
    // slot must retain its own arena while the other slot is rebuilt.
    for (0..4) |i| {
        const action = if (i % 2 == 0) "DENY" else "ALLOW";
        const sql = try std.fmt.allocPrint(
            gpa,
            "UPDATE policies SET action='{s}' WHERE id='p1'",
            .{action},
        );
        defer gpa.free(sql);
        try p.db.exec(gpa, sql);
        try p.tick();
        const current = fx.state.acquireEngine();
        defer server.AppState.releaseEngine(current);
        const verdict = current.engine.evaluateWithHeaders(
            "/secret/x",
            "10.1.2.3",
            "Mozilla",
            &hdrs,
        );
        try std.testing.expectEqual(policy.Action.parse(action).?, verdict.action);
        try std.testing.expectEqualStrings("protect-secret", verdict.rule_name);
        try std.testing.expectEqual(
            policy.Action.allow,
            current.engine.evaluate("/from-file", "9.9.9.9", "curl").action,
        );
    }

    // Incidents flow through the ring into FTS and vector tables.
    const hook = fx.state.hooks.record_incident.?;
    const ctx = fx.state.hooks.context;
    hook(ctx, .{
        .client_ip = "203.0.113.5",
        .user_agent = "sqlmap",
        .method = "GET",
        .path = "/login",
        .category = "waf:sqli",
        .payload = "id=1' UNION SELECT username,password FROM users--",
        .now = 200,
    });
    hook(ctx, .{
        .client_ip = "203.0.113.6",
        .user_agent = "sqlmap",
        .method = "GET",
        .path = "/account",
        .category = "waf:sqli",
        .payload = "id=77' union select name,pass from users--",
        .now = 201,
    });
    hook(ctx, .{
        .client_ip = "203.0.113.7",
        .user_agent = "Scrapy",
        .method = "GET",
        .path = "/__sibuna/honeypot",
        .category = "honeypot",
        .payload = "",
        .now = 202,
    });
    try p.tick();
    var found = try p.searchIncidents(gpa, "users", 10);
    defer found.deinit();
    try std.testing.expectEqual(@as(usize, 2), found.rows.len);
    try std.testing.expectEqualStrings(found.rows[0][4].?, found.rows[1][4].?);
    var all = try p.db.query(
        gpa,
        "SELECT COUNT(*), COUNT(DISTINCT campaign_id) FROM security_incidents",
    );
    defer all.deinit();
    try std.testing.expectEqualStrings("3", all.rows[0][0].?);
    try std.testing.expectEqualStrings("2", all.rows[0][1].?);
    var rep = try p.db.query(
        gpa,
        "SELECT reputation_score, trigger_rule FROM ip_reputation " ++
            "WHERE ip_or_cidr = '203.0.113.7'",
    );
    defer rep.deinit();
    try std.testing.expectEqualStrings("-100", rep.rows[0][0].?);
    try std.testing.expectEqualStrings("honeypot", rep.rows[0][1].?);

    // Hold a full batch across a real SQL failure. Policy reads still run.
    try p.db.exec(gpa, "CREATE TRIGGER fail_incident BEFORE INSERT ON security_incidents " ++
        "BEGIN SELECT RAISE(ABORT,'injected test failure'); END;");
    const event: server.Incident = .{
        .client_ip = "198.51.100.99",
        .user_agent = "test",
        .method = "GET",
        .path = "/trap",
        .category = "honeypot",
        .payload = "repeat",
        .now = 203,
    };
    for (0..40) |_| hook(ctx, event);
    try p.tick();
    try std.testing.expectEqual(@as(usize, 32), p.pending_len);
    try std.testing.expect(p.pending_sql != null);
    const fail_cnt = fx.state.metrics.incident_write_failures.load(.monotonic);
    try std.testing.expectEqual(@as(u64, 1), fail_cnt);
    try p.db.exec(gpa, "DROP TRIGGER fail_incident");
    // Commit successfully but pretend the client lost its acknowledgement.
    try p.db.exec(gpa, p.pending_sql.?);
    try p.tick();
    try p.tick();
    var replayed = try p.db.query(gpa, "SELECT " ++
        "(SELECT COUNT(*) FROM security_incidents)," ++
        "(SELECT COUNT(*) FROM incidents_vec)," ++
        "(SELECT COUNT(*) FROM incidents_fts WHERE incidents_fts MATCH 'repeat')," ++
        "(SELECT hits FROM ip_reputation WHERE ip_or_cidr='198.51.100.99')");
    defer replayed.deinit();
    inline for (.{ "43", "43", "40", "40" }, 0..) |expected, i|
        try std.testing.expectEqualStrings(expected, replayed.rows[0][i].?);
    const p_cnt = fx.state.metrics.incidents_persisted.load(.monotonic);
    try std.testing.expectEqual(@as(u64, 43), p_cnt);
    try std.testing.expectEqual(@as(u64, 3), fx.state.metrics.incident_batches.load(.monotonic));
    for (0..513) |_| hook(ctx, event);
    try std.testing.expectEqual(@as(u64, 1), fx.state.metrics.incidents_dropped.load(.monotonic));
    for (0..16) |_| try p.tick();
    const p_cnt2 = fx.state.metrics.incidents_persisted.load(.monotonic);
    try std.testing.expectEqual(@as(u64, 555), p_cnt2);
}

test {
    if (build_options.console) {
        _ = @import("console_store_test.zig");
        _ = @import("console_rankings_test.zig");
        _ = @import("console_minutes_test.zig");
        _ = @import("console_inspection_test.zig");
        _ = @import("console_limits_test.zig");
        _ = @import("console_start.zig");
    }
}
