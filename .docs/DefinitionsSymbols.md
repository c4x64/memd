∂ - Stable; do not alter without sufficient cause.
ƒ - A failure retained for instruction; it shall remain quarantined.
¨ - Unused; eligible for retirement.
´ - External to this repository, including tools used by it.
´ø¬ - End of life.
¬†ß - Long-term support.
µ∂ - Documentation concerning the use of Git.

Place each marker immediately after the repository-relative filename in a
comment at the end of the file. A marker shall not appear without its
associated filename. For example:

```c
/* kmod/memd/core/memd.c[∂] */
```

Active project files bear `[∂]`. Files within `retired/` bear `[´ø¬]`;
retired documentation bears `[µ∂]` as well. This definitions document
and the KCIDB workflow guide bear `[µ∂]`.

Strict JSON does not permit comments without becoming invalid. Its file
annotation is therefore recorded here:

- `build-matrix.json[∂]`

Attribution: c4x64@oproton.me
<!-- .docs/DefinitionsSymbols.md[∂ µ∂] -->
