//! Zaxonlite Persistent Layer (SID 0005)
//!
//! Durable, optionally replicated state behind the in-memory hot path:
//! dynamic policies, IP reputation, and incident forensics with full-text
//! and vector search. Nothing here runs on a request thread. Workers hand
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
    "CREATE TABLE IF NOT EXISTS sibuna_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS policies (" ++
        "id TEXT PRIMARY KEY, name TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 100, " ++
        "path_pattern TEXT, ua_pattern TEXT, action TEXT NOT NULL, difficulty INTEGER, " ++
        "algorithm TEXT, header_matchers TEXT, cidr_matchers TEXT, " ++
        "weight INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, " ++
        "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
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
        return r;
    }
};

pub const IncidentQueue = store.BoundedQueue(IncidentRecord, 512);

const Db = union(enum) {
    node: *zx.Node,
    embedded: if (build_options.cluster) *zx.Embedded else void,

    fn exec(self: Db, gpa: std.mem.Allocator, sql: []const u8) !void {
        switch (self) {
            .node => |n| {
                const z = try gpa.dupeZ(u8, sql);
                defer gpa.free(z);
                _ = try n.exec(z);
            },
            .embedded => |e| {
                if (!build_options.cluster) unreachable;
                _ = try e.exec(sql);
            },
        }
    }

    fn query(self: Db, gpa: std.mem.Allocator, sql: []const u8) !zx.QueryResult {
        return switch (self) {
            .node => |n| n.query(gpa, sql),
            .embedded => |e| if (build_options.cluster) e.query(gpa, sql) else unreachable,
        };
    }

    fn close(self: Db) void {
        switch (self) {
            .node => |n| n.close(),
            .embedded => |e| if (build_options.cluster) e.close(),
        }
    }
};

pub const Persistent = struct {
    gpa: std.mem.Allocator,
    io: Io,
    cfg: core.Config,
    state: *server.AppState,
    policy_text: ?[]const u8,
    db: Db,
    queue: IncidentQueue,
    /// Two engine buffers: one live, one being rebuilt. `owned_slot` is the
    /// one this layer allocated; the other belongs to the caller.
    spare: *server.EngineSlot,
    owned_slot: *server.EngineSlot,
    arenas: [2]std.heap.ArenaAllocator,
    version: u64 = 0,
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
        try self.migrate();
        try self.loadIncidentCounter();
        try self.rebuild();
        state.hooks = .{ .context = self, .record_incident = recordIncidentHook };
        return self;
    }

    pub fn stop(self: *Persistent) void {
        self.stopping.store(true, .release);
        if (self.thread) |t| t.join();
        self.state.hooks = .{};
        self.drain() catch {};
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

    fn migrate(self: *Persistent) !void {
        for (schema) |statement| try self.db.exec(self.gpa, statement);
    }

    /// Incident ids are `node_id << 40 | sequence`, unique across a
    /// cluster with no coordination.
    fn loadIncidentCounter(self: *Persistent) !void {
        const sql = try std.fmt.allocPrint(
            self.gpa,
            "SELECT COALESCE(MAX(id), 0) FROM security_incidents WHERE id >> 40 = {d}",
            .{self.node_id},
        );
        defer self.gpa.free(sql);
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        const cell = if (result.rows.len > 0) result.rows[0][0] else null;
        const max = if (cell) |text| std.fmt.parseInt(u64, text, 10) catch 0 else 0;
        self.next_incident = (max & 0xff_ffff_ffff) + 1;
    }

    fn worker(self: *Persistent) void {
        while (!self.stopping.load(.acquire)) {
            self.tick() catch |err| {
                std.debug.print("storage: tick failed: {t}\n", .{err});
            };
            const pause = Io.Duration.fromMilliseconds(
                @intCast(@max(50, self.cfg.storage_poll_ms)),
            );
            Io.sleep(self.io, pause, .awake) catch return;
        }
    }

    /// One maintenance round: persist queued incidents, then reload the
    /// policy tables if anything changed.
    pub fn tick(self: *Persistent) !void {
        try self.drain();
        if (try self.policiesChanged()) try self.rebuild();
    }

    fn drain(self: *Persistent) !void {
        var handled: usize = 0;
        while (handled < incident_batch * 4) : (handled += 1) {
            const rec = self.queue.pop() orelse return;
            try self.insertIncident(&rec);
        }
    }

    fn recordIncidentHook(ctx: ?*anyopaque, incident: server.Incident) void {
        const self: *Persistent = @ptrCast(@alignCast(ctx orelse return));
        _ = self.queue.push(IncidentRecord.from(incident));
    }

    fn nearestCampaign(self: *Persistent, embedding_hex: []const u8) !?u64 {
        const sql = try std.fmt.allocPrint(
            self.gpa,
            "SELECT s.campaign_id, v.distance FROM incidents_vec v " ++
                "JOIN security_incidents s ON s.id = v.item_id " ++
                "WHERE v.embedding MATCH X'{s}' AND k = 1",
            .{embedding_hex},
        );
        defer self.gpa.free(sql);
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        if (result.rows.len == 0) return null;
        const campaign = result.rows[0][0] orelse return null;
        const distance = std.fmt.parseFloat(f32, result.rows[0][1] orelse "1") catch 1.0;
        if (distance > campaign_distance) return null;
        return std.fmt.parseInt(u64, campaign, 10) catch null;
    }

    fn insertIncident(self: *Persistent, rec: *const IncidentRecord) !void {
        const payload = rec.payload[0..rec.payload_len];
        const vector = policy.embedding.embed(payload);
        const bytes = policy.embedding.toBytes(&vector);
        var hex_buf: [bytes.len * 2]u8 = undefined;
        const hex = std.fmt.bufPrint(&hex_buf, "{x}", .{&bytes}) catch unreachable;
        const id = (@as(u64, self.node_id) << 40) | self.next_incident;
        const campaign = (try self.nearestCampaign(hex)) orelse id;

        var sql = Io.Writer.Allocating.init(self.gpa);
        defer sql.deinit();
        const w = &sql.writer;
        try w.print(
            "INSERT INTO security_incidents(id,node_id,client_ip,user_agent,method,path," ++
                "violation_category,offending_payload,campaign_id,recorded_at) VALUES ({d},{d},",
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
        try w.print(",{d},{d}); ", .{ campaign, rec.now });
        try w.print("INSERT INTO incidents_fts(rowid,path,offending_payload) VALUES ({d},", .{id});
        try quote(w, rec.path[0..rec.path_len]);
        try w.writeAll(",");
        try quote(w, payload);
        try w.print("); INSERT INTO incidents_vec(item_id,embedding,embedding_coarse) " ++
            "VALUES ({d},X'{s}',vec_quantize_binary(X'{s}'))", .{ id, hex, hex });
        if (std.mem.eql(u8, rec.category[0..rec.category_len], "honeypot")) {
            try w.writeAll("; ");
            try reputationUpsert(
                w,
                rec.ip[0..rec.ip_len],
                -100,
                rec.now + self.cfg.ban_seconds,
                "honeypot",
                rec.now,
            );
        }
        try self.db.exec(self.gpa, sql.written());
        self.next_incident += 1;
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

    /// Change stamp over both dynamic tables; any insert, update, or delete
    /// moves it.
    fn policiesChanged(self: *Persistent) !bool {
        const sql = "SELECT (SELECT COALESCE(MAX(updated_at),0) FROM policies) + " ++
            "(SELECT COUNT(*) FROM policies) * 7 + " ++
            "(SELECT COALESCE(MAX(last_seen),0) FROM ip_reputation) * 3 + " ++
            "(SELECT COUNT(*) FROM ip_reputation) * 11";
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        if (result.rows.len == 0) return false;
        const text = result.rows[0][0] orelse return false;
        const stamp = std.fmt.parseInt(u64, text, 10) catch return false;
        if (stamp == self.version) return false;
        self.version = stamp;
        return true;
    }

    /// Rebuilds the spare engine from file policy, database policies, and
    /// reputation, then publishes it. The previously live slot becomes the
    /// spare once its readers have drained.
    pub fn rebuild(self: *Persistent) !void {
        const which: usize = if (self.spare == self.state.slot.load(.acquire)) 1 else 0;
        _ = self.arenas[which].reset(.retain_capacity);
        const arena = self.arenas[which].allocator();
        const engine = self.spare.engine;
        engine.initInPlace(self.cfg.default_difficulty);
        engine.waf_enabled = self.cfg.waf;
        if (self.policy_text) |text| engine.loadFromJsonInto(arena, text) catch {};
        try self.loadDbPolicies(engine, arena);
        try self.loadReputation(engine);
        self.spare = self.state.publishEngine(self.spare);
    }

    fn loadDbPolicies(self: *Persistent, engine: *policy.Engine, arena: std.mem.Allocator) !void {
        const sql = "SELECT name, path_pattern, ua_pattern, action, difficulty, algorithm, " ++
            "header_matchers, cidr_matchers, weight FROM policies WHERE enabled = 1 " ++
            "ORDER BY priority, name";
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        for (result.rows) |row| {
            const name = row[0] orelse continue;
            const action = policy.Action.parse(row[3] orelse continue) orelse continue;
            var r = policy.PolicyRule{ .name = try arena.dupe(u8, name), .action = action };
            if (row[1]) |p| r.path_pattern = try arena.dupe(u8, p);
            if (row[2]) |u| r.ua_pattern = try arena.dupe(u8, u);
            if (row[4]) |d| r.difficulty = std.fmt.parseInt(u32, d, 10) catch null;
            if (row[5]) |a| r.algorithm = try arena.dupe(u8, a);
            if (row[8]) |wt| r.weight = std.fmt.parseInt(i32, wt, 10) catch 0;
            if (row[6]) |h| try parseHeaderMatchers(arena, h, &r);
            if (row[7]) |c| parseCidrMatchers(c, &r);
            engine.addRule(r) catch break;
        }
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
            "SELECT ip_or_cidr, reputation_score FROM ip_reputation " ++
                "WHERE (banned_until IS NULL OR banned_until > {d}) " ++
                "AND (reputation_score <= -50 OR reputation_score >= 50)",
            .{now},
        );
        defer self.gpa.free(sql);
        var result = try self.db.query(self.gpa, sql);
        defer result.deinit();
        for (result.rows) |row| {
            const cidr = row[0] orelse continue;
            const score = std.fmt.parseInt(i32, row[1] orelse continue, 10) catch continue;
            engine.ip_trie.insertCidr(cidr, if (score < 0) .deny else .allow) catch continue;
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
}
