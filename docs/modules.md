# Kernel modules

A kernel module (`.ko`, or `.ko.xz` / `.ko.gz` as distributions ship them; unpack `.ko.zst` with `zstd -d` first) may have its own `__bug_table`, `__jump_table` and `__ex_table` as relocatable sections. A one-minute example on Debian's arm64 `ext4.ko` is in [USAGE.md](USAGE.md): [Try a real module](USAGE.md#try-a-real-module-one-minute-377-kb-download).

## On the command line

- The command line lays the sections out from 0x10000 in section-header order,
- gives each undefined symbol its own 64 KB slot after them (so `__tracepoint_X + 8` still names that tracepoint and a key inside an imported array, such as `nf_hooks_needed+0x270` in `bridge.ko`, keeps its own name)
- and applies the relocations, so file names, keys and targets come out right.

Addresses printed for a module are those of this layout, not necessarily IDA's.

## In IDA

- IDA relocates a `.ko` itself, and kflow then finds the tables by segment name.
- IDA puts a module's imports in an extern segment, probably as small items one after another (not verified), so a key at "import + offset" may land on another import's address.
- For those keys kflow takes the name from its own decode of the `.ko` (as above) if the file is still at the path IDA loaded it from and both decodes have the same sites at the same offsets in their sections, and the key reference then goes to that import.
- Tested only with fake `ida_*` modules that put the imports 8 bytes apart, on Debian 13's `bridge.ko` (14 such static-key sites using 9 keys, e.g. `tracepoint fdb_delete`); the real item size of IDA's extern segment is not verified.

## What was checked

- Kernel modules: checked on one x86_64 module (`nf_tables.ko`) and four arm64 modules (`fat.ko`, `vfat.ko`, `ext4.ko`, `jbd2.ko`); their counts are in the [What was verified](VERIFICATION.md#what-was-verified) table.
- Relocations of these types are applied to every allocated section (x86_64 `R_X86_64_PC32`/`PLT32`/`PC64`/`64`/`32`/`32S`, arm64 `R_AARCH64_PREL32`/`PREL64`/`ABS64`/`ABS32`).
- The modules above use `R_X86_64_PC32`/`PC64` and `R_AARCH64_PREL32`/`PREL64` in their tables; the absolute types follow the same rule but are untested on real files.
- In IDA, kflow relies on IDA's own relocation of the `.ko` (not tried in IDA).
