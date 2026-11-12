# Changelog

Taken from the GitHub release notes. Newest first.

## Unreleased

- ELF files with extended section numbering (0xff00 or more sections: `e_shnum` 0, `e_shstrndx` `SHN_XINDEX`, symbol section indexes in `.symtab_shndx`) are read; before, kflow saw no sections in them. Synthetic test.
- A kernel module's relocations are applied in place instead of in a second copy of the file (output unchanged on nf_tables.ko, ext4.ko and a Debian 5.10 kernel).
- A raw arm64 kernel `Image` (also gzip-compressed, as Ubuntu's arm64 `vmlinuz`) or an x86 `bzImage` / `vmlinuz` now gets a message naming the tool that turns it into an ELF (vmlinux-to-elf, or extract-vmlinux on x86), not just "is not an ELF file".
- Checked on two more kernels, Ubuntu 24.04's 6.8.0-149-generic for x86_64 and for arm64 (each `vmlinuz` through vmlinux-to-elf): x86_64 11,027 BUG/WARN sites (8,259 WARN), 8,304 static-key sites (8,189 keys named), 632 exception-table entries (the 45 WRMSR and 41 RDMSR entries all sit on `wrmsr`/`rdmsr`); arm64 10,803 BUG/WARN sites (8,085 WARN, all `brk #0x800`), 31,250 static-key sites (31,126 keys named, 22,918 of them tracepoints), 935 exception-table entries. README table rows added.
- README "Try it": the quickest sample is the `vmlinuz` your own Linux machine boots, through vmlinux-to-elf (with the copy step for a root-only `/boot`).

## v0.0.1 (2026-11-12)

First release.

kflow reads three tables that every Linux kernel carries and IDA does not decode:

- `__bug_table`: every `BUG()` / `WARN()` trap (`ud2` on x86_64, `brk #0x800` on arm64; on x86_64 from Linux 6.19 a WARN with a message is a call, and kflow says so) with its source file and line, and whether the kernel continues after it (WARN) or not (BUG).
- `__jump_table`: every static-key site (a NOP or branch the kernel patches at runtime), its key and its branch target.
- `__ex_table`: every instruction allowed to fault and its fixup.

In IDA (**Edit > Plugins > kflow**): **Annotate kernel sites** comments every site and adds the jump references IDA cannot see (static-key targets, fixups) where IDA has none; **List BUG/WARN sites** lists every trap with its function and `file:line`; **Remove annotations** takes out kflow's comments and the references Annotate recorded adding (also after a rebase), and leaves earlier references (IDA's or yours) and your comments alone. `tools/kflow_headless.py` does the same through idalib, and `python3 -m kflow <kernel ELF>` decodes the tables without IDA.

Kernel modules (`.ko`) work too: the command line applies the module's relocations, and in IDA the tables are found by segment name. Static keys are named where possible: tracepoints as `tracepoint <event>`, dynamic-debug keys as `pr_debug file:line "format"` (8,898 of 9,237 keys on the demo kernel). Checked on five kernels and five modules outside IDA (README "What was verified": trap bytes, branch targets, source-file names): Debian 13 6.12 x86_64 (MemLens demo: 9,850 BUG/WARN sites, 9,237 static-key sites, 671 exception-table entries), a stripped Debian x86_64 `vmlinux` (tables found by section name), Android GKI 5.10.198-android12-9 arm64 (24,386 / 75,316 / 1,488; the 54,896 static-key sites outside init code that are compiled as a branch go to the decoded target); Android GKI 6.1.57-android14-11 arm64 (12,223 / 10,629 / 1,043); Debian 11 5.10.223 x86_64 (6,573 / 3,820 / 548; the older exception-table layout whose third field is a handler function: all 548 handlers are the kernel's `ex_handler_*` functions); module: Debian 13 `nf_tables.ko` (141 BUG/WARN sites, every `file:line` matches the v6.12.115 sources; 8 static-key sites with named keys) and Debian 13 arm64 `fat.ko`, `vfat.ko`, `ext4.ko`, `jbd2.ko` (676 BUG/WARN sites, every `file:line` on a BUG/WARN or assertion macro or a fortified copy in the v6.12.94 sources; 178 static-key sites, 174 of them tracepoints; 36 exception-table entries).

x86_64 and arm64, 64-bit kernels only. IDA API use: 64 names and object members checked against the official IDAPython stubs, 0 missing.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.
