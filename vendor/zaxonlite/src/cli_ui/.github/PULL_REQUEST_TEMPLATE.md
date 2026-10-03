# Summary

<!-- What does this change do, and why? One or two short paragraphs. -->

## Checklist

- [ ] `zig build test` passes without a TTY.
- [ ] The module stays domain-neutral: no imports of zaxonlite, Kynetica,
      or any product code, and no knowledge of SQL execution, prompts,
      dot commands, or authentication.
- [ ] Piped and scripted output stays byte-for-byte stable; interactive
      polish never changes what a script sees.
- [ ] New behavior in the editor, tokenizer, history, or renderers comes
      with a golden-string or key-sequence test.
- [ ] The vaxis pin stays identical to zaxonlite's pin, or the change
      updates both together.
- [ ] Memory and work stay bounded; every error is handled; Zig lines are
      at or below 100 columns (TigerStyle).

## Verification

<!-- Paste the commands you ran and their results. -->
