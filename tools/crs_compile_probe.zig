//! Compile-only portability probe; this object is not linked into Sibuna.
//! The allocator remains caller-owned across compilation and zero-allocation matching.
const std = @import("std");
const crs = @import("crs");

pub export fn crsCompileProbe(allocator: *const std.mem.Allocator) u8 {
    const activation: crs.config.Activation = .{};
    activation.validate(.request_metadata, .source_only) catch return 7;
    var compiler = crs.compiler.Compiler.init(allocator.*, .{});
    defer compiler.deinit();
    compiler.addSource("probe.conf", "SecRule ARGS \"@rx (x+)\" \"id:1,phase:1\"") catch return 1;
    var plan = compiler.finish() catch return 2;
    defer plan.deinit();
    var program = crs.regex.compile(
        allocator.*,
        plan.conditions[0].expression.?.argument,
        .{},
    ) catch return 3;
    defer program.deinit();
    var workspace = crs.regex.Workspace.init(allocator.*, &program) catch return 4;
    defer workspace.deinit();
    var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
    var pipeline = crs.pipeline.compile(allocator.*, .{
        .inherited = plan.conditions[0].inherited_actions,
        .local = plan.conditions[0].actions,
    }) catch return 10;
    defer pipeline.deinit();
    var transformed: [4]u8 = undefined;
    var alternate: [4]u8 = undefined;
    var iterator: crs.pipeline_replay.Replay = .{};
    iterator.init(&pipeline, .{
        .input = "xx",
        .scratch = .{ &transformed, &alternate },
        .budget = &budget,
    }) catch return 11;
    _ = iterator.next() catch return 11;
    _ = crs.transforms.apply(.lowercase, .{
        .input = "XX",
        .output = &transformed,
        .budget = &budget,
    }) catch return 8;
    var prefixes: [2]usize = undefined;
    const predicate: crs.primitives.Predicate = .{ .kind = .contains, .argument = "x" };
    _ = predicate.evaluate("xx", .{ .prefixes = &prefixes, .budget = &budget }) catch return 9;
    const range = crs.byte_range.compile("32-126") catch return 12;
    _ = range.inspect("xx", &budget) catch return 13;
    var phrase = crs.phrases_source.inlineWords(allocator.*, "x y", .{}) catch return 14;
    defer phrase.deinit();
    _ = phrase.search("xx", &budget) catch return 15;
    var addresses = crs.address_set.compile(allocator.*, "127.0.0.1,::1", .{}) catch return 16;
    defer addresses.deinit();
    _ = addresses.contains("::1", &budget) catch return 17;
    if (!detectorProbe(&budget)) return 18;
    if (!macroProbe(allocator.*, &budget)) return 24;
    if (!operatorProbe(allocator.*, &budget)) return 25;
    if (!selectionProbe(allocator.*, &budget)) return 26;
    if (!transactionProbe(allocator.*, &budget)) return 27;
    if (!conditionProbe(allocator.*, &budget)) return 28;
    if (!controlProbe(allocator.*, &budget)) return 29;
    if (!signatureProbe()) return 30;
    const result = crs.regex.match.search(
        &program,
        "xx",
        &workspace.scratch,
        &budget,
    ) catch return 5;
    return if (result != null) 0 else 6;
}

fn signatureProbe() bool {
    var scratch: crs.release_signature.Scratch = .{};
    const verifier = crs.release_signature.Verifier.init(&scratch) catch return false;
    if (verifier.verify("bad archive", "bad signature", 1791049738, &scratch)) |_| {
        return false;
    } else |err| return err == error.InvalidArmor;
}

/// Runtime parameters prevent optimization from pruning the RSA verifier from
/// compile-only Windows, macOS and Wasm objects after a constant malformed armor.
pub export fn crsSignatureProbe(
    archive: [*]const u8,
    archive_length: usize,
    armored: [*]const u8,
    armored_length: usize,
    now: u64,
) u8 {
    if (archive_length > 8 * 1024 * 1024 or armored_length > 16 * 1024) return 3;
    var scratch: crs.release_signature.Scratch = .{};
    const verifier = crs.release_signature.Verifier.init(&scratch) catch return 2;
    _ = verifier.verify(
        archive[0..archive_length],
        armored[0..armored_length],
        now,
        &scratch,
    ) catch return 1;
    return 0;
}

fn controlProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    var program = crs.controls.compile(allocator, "ruleRemoveTargetById=1;ARGS:q") catch
        return false;
    defer program.deinit();
    var exclusions: [1]crs.controls.Exclusion = undefined;
    var state: crs.controls.State = .{ .exclusions = &exclusions };
    state.apply(&program, budget) catch return false;
    return state.excludes(1, &.{}, .{ .collection = .args, .key = "q" }, budget) catch false;
}

fn detectorProbe(budget: *crs.work.Budget) bool {
    _ = crs.injection_dictionary.lookup("SELECT", budget) catch return false;
    var prefixes: [2]usize = undefined;
    var lexical: crs.sql_tokens.Context = .{
        .input = "SELECT 1",
        .prefixes = &prefixes,
        .budget = budget,
    };
    var token: crs.sql_tokens.Token = .{};
    _ = crs.sql_tokens.next(&lexical, &token) catch return false;
    var fingerprint: crs.sql_folding.Result = .{};
    crs.sql_folding.fingerprint(&lexical, &fingerprint) catch return false;
    _ = crs.sql_detector.detect(&lexical, &fingerprint) catch return false;
    var html = crs.html_tokens.Context.init("<a href='url'>", budget, .data);
    _ = crs.html_tokens.next(&html) catch return false;
    var xss: crs.xss_detector.Context = .{ .input = "<script>", .budget = budget };
    _ = crs.xss_detector.detect(&xss) catch return false;
    return true;
}

fn macroProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    var program = crs.macros.compile(allocator, "%{TX.value}", .{}) catch return false;
    defer program.deinit();
    const view: crs.variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var pieces: [1][]const u8 = undefined;
    var output: [16]u8 = undefined;
    _ = program.expand(.{
        .view = &view,
        .pieces = &pieces,
        .output = &output,
        .budget = budget,
    }) catch return false;
    return true;
}

fn operatorProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    var program = crs.operators.compile(allocator, .{
        .kind = .contains,
        .argument = "x",
    }, .{}) catch return false;
    defer program.deinit();
    const result = program.evaluate(.{ .input = "xx", .budget = budget }) catch return false;
    return result.matched and result.captured("xx", 0) == null;
}

fn selectionProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    const targets = crs.selectors.parse(allocator, "&ARGS", 1) catch return false;
    defer allocator.free(targets);
    var program = crs.selection.compile(allocator, targets, .{}) catch return false;
    defer program.deinit();
    const view: crs.variables.View = .{ .entries = &.{}, .coverage = @splat(.complete) };
    var entries: [1]crs.variables.Entry = undefined;
    var count: [20]u8 = undefined;
    const result = program.select(0, .{
        .view = &view,
        .output = &entries,
        .count = &count,
        .budget = budget,
    }) catch return false;
    return result.counted and std.mem.eql(u8, result.entries[0].value, "0");
}

fn transactionProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    var entries: [2]crs.variables.Entry = undefined;
    var bytes: [64]u8 = undefined;
    var store = crs.transaction_vars.Store.init(&entries, &bytes);
    store.update("score", .add, "5", budget) catch return false;
    const score = (store.get("SCORE", budget) catch return false) orelse return false;
    return std.mem.eql(u8, score, "5") and setVarProbe(allocator, &store, budget);
}

fn setVarProbe(
    allocator: std.mem.Allocator,
    store: *crs.transaction_vars.Store,
    budget: *crs.work.Budget,
) bool {
    var program = crs.set_var.compile(allocator, "tx.score=+1") catch return false;
    defer program.deinit();
    const view: crs.variables.View = .{
        .entries = store.values() catch return false,
        .coverage = @splat(.complete),
    };
    var pieces: [1][]const u8 = undefined;
    var key: [16]u8 = undefined;
    var value: [16]u8 = undefined;
    program.execute(.{
        .store = store,
        .view = &view,
        .pieces = &pieces,
        .key_output = &key,
        .value_output = &value,
        .budget = budget,
    }) catch return false;
    return true;
}

fn conditionProbe(allocator: std.mem.Allocator, budget: *crs.work.Budget) bool {
    var builder = crs.compiler.Compiler.init(allocator, .{});
    defer builder.deinit();
    builder.addSource("probe.conf",
        \\SecRule ARGS "@contains x" "id:1,setvar:tx.score=+1"
    ) catch return false;
    var source = builder.finish() catch return false;
    defer source.deinit();
    var program = crs.rule_program.compile(allocator, &source, &.{}, .{}) catch return false;
    defer program.deinit();
    const input = [_]crs.variables.Entry{.{ .collection = .args, .key = "q", .value = "x" }};
    var stored: [4]crs.variables.Entry = undefined;
    var bytes: [64]u8 = undefined;
    var store = crs.transaction_vars.Store.init(&stored, &bytes);
    var merged: [16]crs.variables.Entry = undefined;
    var matched: [4]crs.variables.Entry = undefined;
    var matched_bytes: [64]u8 = undefined;
    var context = crs.evaluation_context.Context.init(.{
        .entries = &input,
        .coverage = @splat(.complete),
    }, &store, .{
        .view = &merged,
        .matched = &matched,
        .bytes = &matched_bytes,
    }) catch return false;
    var snapshot: [4]crs.variables.Entry = undefined;
    var count: [20]u8 = undefined;
    var first: [4]u8 = undefined;
    var second: [4]u8 = undefined;
    var prefixes: [4]usize = undefined;
    var pieces: [4][]const u8 = undefined;
    var key: [16]u8 = undefined;
    var value: [16]u8 = undefined;
    var argument: [16]u8 = undefined;
    if (!runProgramProbe(&program, .{
        .context = &context,
        .snapshot = &snapshot,
        .count = &count,
        .transforms = .{ &first, &second },
        .prefixes = &prefixes,
        .pieces = &pieces,
        .key_output = &key,
        .value_output = &value,
        .argument_output = &argument,
        .budget = budget,
    })) return false;
    const score = (store.get("score", budget) catch return false) orelse "";
    return std.mem.eql(u8, score, "1");
}

fn runProgramProbe(
    program: *const crs.rule_program.Program,
    frame: crs.condition.Frame,
) bool {
    var exclusions: [2]crs.controls.Exclusion = undefined;
    var events: [1]crs.action_state.Event = undefined;
    var tags: [2][]const u8 = undefined;
    var bytes: [64]u8 = undefined;
    var state = crs.action_state.State.init(&exclusions, &events, &tags, &bytes, true);
    var unwind: [1]usize = undefined;
    var executor = crs.executor.Executor.init(program, frame, &state, &unwind);
    const result = executor.run(.request_body) catch return false;
    return result == .complete and state.event_used == 1;
}

/// Exercise atomic pool ownership and prepared frame pointers on every target.
pub export fn crsPoolProbe(allocator: *const std.mem.Allocator) u8 {
    var compiler = crs.compiler.Compiler.init(allocator.*, .{});
    defer compiler.deinit();
    compiler.addSource("pool.conf", "SecAction \"id:1,setvar:tx.score=1\"") catch return 1;
    var source = compiler.finish() catch return 2;
    defer source.deinit();
    var program = crs.rule_program.compile(allocator.*, &source, &.{}, .{}) catch return 3;
    defer program.deinit();
    var pool: crs.transaction_pool.Pool = undefined;
    pool.init(allocator.*, &program, .{}, 1, 128 * 1024 * 1024) catch return 4;
    defer pool.deinit();
    var lease = pool.lease() catch return 5;
    defer lease.release();
    pool.close();
    var evaluation = lease.slot().begin(.{
        .entries = &.{},
        .coverage = @splat(.complete),
    }, true) catch return 6;
    _ = evaluation.run(.request_body) catch return 7;
    return 0;
}

/// JSON and form acquisition must remain available without a host JSON library.
pub export fn crsAcquisitionProbe(input: [*]const u8, length: usize, structured: bool) u8 {
    if (length > 4096) return 1;
    var entries: [128]crs.variables.Entry = undefined;
    var bytes: [4096]u8 = undefined;
    var value: [1024]u8 = undefined;
    var path: [1024]u8 = undefined;
    var bits: [8]u8 = undefined;
    var frames: [64]crs.json_acquisition.Frame = undefined;
    var builder = crs.acquired_values.Builder.init(&entries, &bytes);
    var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
    if (structured) {
        crs.json_acquisition.parse(input[0..length], &builder, .{
            .value = &value,
            .path = &path,
            .bits = &bits,
            .frames = &frames,
        }, &budget) catch return 2;
    } else {
        crs.form_acquisition.parse(input[0..length], .form, &builder, .{
            .key = &path,
            .value = &value,
        }, &budget) catch return 3;
    }
    return 0;
}

pub export fn crsMultipartProbe(input: [*]const u8, length: usize) u8 {
    if (length > 4096) return 1;
    var entries: [128]crs.variables.Entry = undefined;
    var bytes: [4096]u8 = undefined;
    var name: [512]u8 = undefined;
    var filename: [512]u8 = undefined;
    var extended: [512]u8 = undefined;
    var builder = crs.acquired_values.Builder.init(&entries, &bytes);
    var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
    crs.multipart_acquisition.parse(input[0..length], "B", &builder, .{
        .name = &name,
        .filename = &filename,
        .extended = &extended,
    }, .{}, &budget) catch return 2;
    return 0;
}

pub export fn crsXmlProbe(input: [*]const u8, length: usize) u8 {
    if (length > 4096) return 1;
    var entries: [128]crs.variables.Entry = undefined;
    var bytes: [4096]u8 = undefined;
    var text: [1024]u8 = undefined;
    var value: [1024]u8 = undefined;
    var frames: [64]crs.xml_acquisition.Frame = undefined;
    var attributes: [128]crs.xml_acquisition.Attribute = undefined;
    var bindings: [128]crs.xml_acquisition.Binding = undefined;
    var builder = crs.acquired_values.Builder.init(&entries, &bytes);
    var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
    crs.xml_acquisition.parse(input[0..length], &builder, .{
        .text = &text,
        .value = &value,
        .frames = &frames,
        .attributes = &attributes,
        .bindings = &bindings,
    }, &budget) catch return 2;
    return 0;
}

/// Instantiate the complete metadata/entity path with runtime inputs on every
/// target. An unused import alone would not qualify Zig's lazily compiled code.
pub export fn crsHttpProbe(
    allocator: *const std.mem.Allocator,
    input: [*]const u8,
    length: usize,
    processor: u8,
) u8 {
    if (length > 4096 or processor > 3) return 1;
    var compiler = crs.compiler.Compiler.init(allocator.*, .{});
    defer compiler.deinit();
    compiler.addSource("http.conf", "SecAction \"id:1,phase:2\"") catch return 2;
    var source = compiler.finish() catch return 3;
    defer source.deinit();
    var program = crs.rule_program.compile(allocator.*, &source, &.{}, .{}) catch return 4;
    defer program.deinit();
    var slot: crs.transaction_slot.Slot = undefined;
    slot.init(allocator.*, &program, .{}) catch return 5;
    defer slot.deinit();
    var transaction = crs.http_transaction.Transaction.begin(&slot, .full, true, .{
        .method = "POST",
        .target = "/probe?q=one&q=two",
        .protocol = "HTTP/1.1",
        .line = "POST /probe?q=one&q=two HTTP/1.1",
        .client = "127.0.0.1",
        .id = "probe",
        .headers = &.{},
    }) catch return 6;
    defer slot.finish();
    slot.state.control.processor = @fromBackingInt(@as(u2, @intCast(processor)));
    _ = transaction.requestBody(input[0..length]) catch return 7;
    _ = transaction.responseHeaders(.{ .status = 200, .headers = &.{} }) catch return 8;
    _ = transaction.responseBody(input[0..length]) catch return 9;
    transaction.finish(.inspected) catch return 10;
    return 0;
}

pub export fn crsPackageProbe(
    allocator: *const std.mem.Allocator,
    archive: [*]const u8,
    archive_length: usize,
    signature: [*]const u8,
    signature_length: usize,
    now: u64,
) u8 {
    if (archive_length > 8 * 1024 * 1024 or signature_length > 16 * 1024) return 1;
    const package = crs.release_package.prepare(allocator.*, .{
        .archive = archive[0..archive_length],
        .signature = signature[0..signature_length],
        .version = .{ .major = 4, .minor = 30, .patch = 0 },
        .now = now,
    }) catch return 2;
    defer package.deinit();
    return 0;
}

/// Instantiate generation publication and pinned ownership on every supported target.
pub export fn crsPublicationProbe(
    allocator: *const std.mem.Allocator,
    archive: [*]const u8,
    archive_length: usize,
    signature: [*]const u8,
    signature_length: usize,
    now: u64,
) u8 {
    if (archive_length > 8 * 1024 * 1024 or signature_length > 16 * 1024) return 1;
    const package = crs.release_package.prepare(allocator.*, .{
        .archive = archive[0..archive_length],
        .signature = signature[0..signature_length],
        .version = .{ .major = 4, .minor = 30, .patch = 0 },
        .now = now,
    }) catch return 2;
    const candidate = crs.generation.Generation.create(allocator.*, package, .{
        .revision = 1,
        .activation = .{ .mode = .audit },
        .observation = .request_response,
        .slots = 1,
        .reservation = 128 * 1024 * 1024,
    }) catch {
        package.deinit();
        return 3;
    };
    var publisher: crs.publication.Publisher = .{};
    defer {
        publisher.close() catch unreachable;
        publisher.deinit();
    }
    publisher.publish(candidate) catch {
        candidate.deinit();
        return 4;
    };
    var lease = publisher.lease() catch return 5;
    defer lease.release();
    const metadata = publisher.snapshot() catch return 6;
    publisher.close() catch return 7;
    return if (metadata.revision == lease.generation().options.revision) 0 else 8;
}
