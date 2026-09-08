# HTML snippets

`html.render(writer, @embedFile("snippets/field.html"), values)` writes trusted markup
with runtime values into a caller-owned `std.Io.Writer`. It compiles for native Zig and
Wasm without networking, storage, an allocator, or a runtime template parser.

```html
<label for="{{ id }}">{{ label }}</label>
<input id="{{ id }}" value="{{ value }}">
```

```zig
try html.render(writer, @embedFile("snippets/field.html"), .{
    .id = "username",
    .label = "Username",
    .value = username,
});
```

Values may be text, integers or booleans. Format dates and decimal values explicitly in
Zig. Text always escapes `&`, `<`, `>`, `"` and `'`. There is no raw HTML escape hatch.
Use Zig conditions, bounded loops and consecutive render calls to compose snippets.
The source limit is 32 KiB and the placeholder limit is 128 per snippet; output is
bounded by the supplied writer. Discard incomplete output after `WriteFailed`.

Only developer-authored templates are supported. Place values in text or quoted ordinary
attributes. HTML escaping does not validate URL schemes or make JavaScript/CSS safe:
do not interpolate script/style, tag names, attribute names or unvalidated URLs.
This renderer is not the sandbox for future operator-edited challenge templates.

Missing fields, malformed names, unclosed placeholders and unsupported tags fail the
build with stable HTML001–HTML007 diagnostics and recovery hints. Snippets are embedded
in the binary: editing markup requires a rebuild, while data is supplied each render.
In the console, rendering runs in Zig/Wasm after browser events or telemetry updates.
Native callers can use the same renderer for server-rendered output.

The design draws on `../kynetica/packages/kynetica-zmpl/src/engine.zig`: escaped output,
strict missing-variable handling and explicit ownership. Kynetica's runtime parser,
CMS inheritance, filters, dynamic maps and component resolvers are deliberately not
copied. Sibuna owns fixed first-party snippets, so build-time expansion is smaller
and avoids allocating an AST or scratch arena during repeated live renders.

Console snippets live under `apps/console-ui/src/snippets/`. Tailwind scans that directory,
and the committed asset manifest covers both snippets and this renderer. Run
`zig build console-assets` after changing them, then `zig build fmt test sid`.
