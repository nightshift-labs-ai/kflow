# kflow

Linux kernels carry their own maps of code that a disassembler cannot see from the instructions alone:

- **`__bug_table`**: every `BUG()` / `WARN()` trap (`ud2` on x86_64, `brk #0x800` on arm64), with the **source file and line** and a flag that says whether the kernel **continues after the trap** (WARN) or not (BUG).
- **`__jump_table`**: every static-key site (`static_branch_likely/unlikely`, tracepoints): a NOP or branch that the kernel patches at runtime, its **key** and its **branch target**.
- **`__ex_table`**: every instruction that may fault on purpose (user-memory access, MSR reads...) and its **fixup** landing pad.

kflow reads these tables from the database and, in IDA, comments every site and adds the jump references IDA cannot find on its own (a NOP has no branch, a fault has no visible path to its fixup). It also lists every BUG/WARN site with its function and `file:line`.

## Status: read this first

**kflow has not yet been run inside real IDA.** It was built without access to an IDA installation. The table decoders are checked against the instruction bytes of three real kernels (below); the IDA layer is small, uses 50 IDAPython names that all exist in the official stubs (`tests/check_ida_api.py`), and has only been exercised with fake `ida_*` modules. Bug reports are very welcome.

kflow was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install kflow
```

Or copy this folder into your IDA `plugins` directory. The command-line decoder needs only Python 3.8+ and no packages: `python3 -m kflow <kernel ELF>` from this folder.

## Try it

You need a 64-bit kernel ELF that still has the kernel's symbol names, for example:

- a distribution's debug `vmlinux` (Debian/Ubuntu: `/usr/lib/debug/boot/vmlinux-<version>` from the `linux-image-<version>-dbg` / `-dbgsym` package);
- the `kernel.elf` of the [MemLens demo data](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (22 MB zip; a Debian 13 6.12 kernel exported from a memory image, so freed init code reads as other bytes);
- an Android GKI `Image` turned into an ELF with kallsyms names by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf).

A stripped `vmlinux` (from `extract-vmlinux`) still has `__bug_table` and `__ex_table` as sections, and kflow uses them; the static-key table has no section of its own and needs the `__start___jump_table` symbol.

1. Outside IDA, see what is there: `python3 -m kflow kernel.elf` (output below).
2. In IDA, open the kernel and run **Edit > Plugins > kflow: Annotate kernel sites**.
3. **kflow: List BUG/WARN sites** lists every trap with its function and source line; Enter jumps to it.
4. **kflow: Remove annotations** removes kflow's comments and the references it added. IDA's own references (for example at a static-key site that is currently a jump) and your own comments are never touched.

Without the IDA window (idalib, IDA 9.0+): `python3 tools/kflow_headless.py <kernel> [--no-analysis] [--remove]` does steps 2 and 4 and saves the database.

## What you get (real output, not IDA screenshots)

The MemLens demo `kernel.elf` (Debian 13, 6.12.115, x86_64):

```
$ python3 -m kflow kernel.elf
__bug_table (addr,file,line,flags): 9850 sites, 7831 WARN (resume after the trap), 2019 BUG; 9850 with file:line in 1168 source files
  WARN sites that are ud2 here: 7504; sites inside a function symbol: 9329
__jump_table: 9237 static-key sites, 5129 keys named by a symbol, 9006 targets in the same function
__ex_table (insn,fixup,data): 671 faulting instructions with a fixup, 635 fixups in the same function; types UACCESS 410, IMM_REG 87, WRMSR 42, RDMSR 39, FAULT_SGX 23, CLEAR_FS 15

$ python3 -m kflow kernel.elf --list jump --limit 3
0xffffffff8e391de7 -> 0xffffffff8e391dfc  arch_exit_to_user_mode_prepare.isra.0    key randomize_kstack_offset (likely)
0xffffffff8ef08602 -> 0xffffffff8ef08625  __do_fast_syscall_32                     key randomize_kstack_offset (likely)
0xffffffff8ef08705 -> 0xffffffff8ef087f2  do_syscall_64                            key randomize_kstack_offset (likely)

$ python3 -m kflow kernel.elf --list ex --limit 3
0xffffffff8e200029 -> 0xffffffff8e20002b  sev_es_terminate                         WRMSR
0xffffffff8e20057d -> 0xffffffff8e20057f  early_set_pages_state                    WRMSR
0xffffffff8e200583 -> 0xffffffff8e200585  early_set_pages_state                    RDMSR
```

(`--list warn` and `--list bug` print `address  WARN|BUG  function  file:line`; WARN sites whose bytes are no longer `ud2` sit in init code that the running kernel had freed.)

The comments kflow writes in IDA look like this:

```
kflow: WARN at mm/userfaultfd.c:722 (the kernel reports and continues after this trap)
kflow: static key randomize_kstack_offset (static_branch_likely): runtime-patched NOP/branch; branch target 0x...
kflow: may fault -> fixup at 0x... (UACCESS)
```

## What was verified

`tests/test_demo.py <kernel ELF>` checks the decoded tables against the instruction bytes; `tests/test_ida_stub.py <kernel ELF>` runs the IDA layer on fake `ida_*` modules backed by the same file (annotate, then remove, with IDA's own references and a user comment in place); `tests/test_headless_stub.py <kernel ELF>` does the same through the headless runner; `python3 tests/test_core.py` covers the layouts on synthetic tables.

| Kernel | BUG/WARN sites | static-key sites | exception-table sites | byte checks |
|---|---|---|---|---|
| Debian 13 6.12.115 x86_64 (MemLens demo, memory image) | 9,850 (7,831 WARN) | 9,237 | 671 (12-byte entries) | every enabled site (663 `jmp`) lands on the decoded target; the rest are 2/5-byte NOPs |
| Debian `vmlinux` x86_64, stripped (`extract-vmlinux`) | 9,993 (7,615 WARN, all `ud2`) | needs symbols | 630 | tables found by section name |
| Android 13 GKI 5.10 arm64 (vmlinux-to-elf) | 24,386 (17,374 WARN, all `brk #0x800`) | 75,316 | 1,488 (8-byte entries) | all 55,053 enabled sites are `b` to the decoded target; the rest are `nop` |

The entry layout is chosen from the data: for `__bug_table` the layout whose entries name source files, for `__ex_table` the layout that gives the address-sorted list the kernel build produces (arm64 before 5.16 has 8-byte entries).

## Limits

- 64-bit little-endian kernels with relative table entries (x86_64; arm64 with `CONFIG_GENERIC_BUG_RELATIVE_POINTERS`). Not 32-bit kernels.
- Exception-type names are the x86_64 numbers of Linux 6.12; other versions number some types differently, so treat the name as a hint. arm64 types are shown as numbers.
- kflow does not change how IDA treats a WARN `ud2` (IDA may still end the block there); the comment says that execution continues. Not tried in IDA.
- Static-key sites in freed init code (memory images) are decoded but not commented when they are outside code segments.
- Alternatives (`.altinstructions`) are not handled; see [ida-linux-alternatives](https://github.com/opensrcsec/ida-linux-alternatives).

## Credits

Written by an AI agent (Claude, operated by Nightshift Labs). Table layouts from the Linux kernel sources (`include/asm-generic/bug.h`, `include/linux/jump_label.h`, `arch/x86/include/asm/extable_fixup_types.h`). If you list authors elsewhere, please use "Nightshift Labs (AI agent)".

MIT licence.
