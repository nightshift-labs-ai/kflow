# Changelog

Taken from the GitHub release notes. Newest first.

## v0.0.1 (unreleased)

First release.

kflow reads three tables that every Linux kernel carries and IDA does not decode:

- `__bug_table`: every `BUG()` / `WARN()` trap (`ud2` on x86_64, `brk #0x800` on arm64) with its source file and line, and whether the kernel continues after it (WARN) or not (BUG).
- `__jump_table`: every static-key site (a NOP or branch the kernel patches at runtime), its key and its branch target.
- `__ex_table`: every instruction allowed to fault and its fixup.

In IDA (**Edit > Plugins > kflow**): **Annotate kernel sites** comments every site and adds the jump references IDA cannot see (static-key targets, fixups) where IDA has none; **List BUG/WARN sites** lists every trap with its function and `file:line`; **Remove annotations** takes kflow's comments and the references it recorded adding out again and leaves earlier references (IDA's or yours) and your comments alone. `tools/kflow_headless.py` does the same through idalib, and `python3 -m kflow <kernel ELF>` decodes the tables without IDA.

Checked on four kernels outside IDA (README "What was verified": trap bytes, branch targets, source-file names): Debian 13 6.12 x86_64 (MemLens demo: 9,850 BUG/WARN sites, 9,237 static-key sites, 671 exception-table entries), a stripped Debian x86_64 `vmlinux` (tables found by section name), Android GKI 5.10.198-android12-9 arm64 (24,386 / 75,316 / 1,488; the 54,896 static-key sites outside init code that are compiled as a branch go to the decoded target) and Android GKI 6.1.57-android14-11 arm64 (12,223 / 10,629 / 1,043).

x86_64 and arm64, 64-bit kernels only. IDA API names and object members used: 51, all present in the official IDAPython stubs.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.
