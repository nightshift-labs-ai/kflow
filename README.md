# kflow

Linux kernels carry their own maps of code that a disassembler cannot see from the instructions alone:

- **`__bug_table`**: every `BUG()` / `WARN()` trap (`ud2` on x86_64, `brk #0x800` on arm64; from Linux 6.19 an x86_64 WARN with a message is a call instead, and kflow says so), with the **source file and line** and a flag that says whether the kernel **continues after the trap** (WARN) or not (BUG).
- **`__jump_table`**: every static-key site (`static_branch_likely/unlikely`, tracepoints): a NOP or branch that the kernel patches at runtime, its **key** and its **branch target**.
- **`__ex_table`**: every instruction that may fault on purpose (user-memory access, MSR reads...) and its **fixup** landing pad.

kflow reads these tables from the database and, in IDA, comments every site and adds the jump references IDA cannot find on its own (a NOP has no branch, a fault has no visible path to its fixup). It also lists every BUG/WARN site with its function and `file:line`.

## Status: read this first

**kflow has not yet been run inside real IDA.** It was built without access to an IDA installation. The table decoders are checked on five real kernels and five kernel modules (below): trap bytes, branch targets and source-file names; the IDA layer is small, uses IDAPython names and object members that all appear in the official stubs (63 checks in `tests/check_ida_api.py`), and has only been exercised with fake `ida_*` modules. Bug reports are very welcome.

kflow was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install kflow
```

The plugin index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/kflow/releases); until it lists kflow (or if `hcli plugin status` shows an older version), install a release zip directly, for example `hcli plugin install https://github.com/nightshift-labs-ai/kflow/archive/refs/tags/v0.0.1.zip`, or copy this folder into your IDA `plugins` directory. The command-line decoder needs only Python 3.8+ and no packages: `python3 -m kflow <kernel ELF>` from this folder.

## Try it

You need a 64-bit kernel ELF that still has the kernel's symbol names, for example:

- a distribution's debug `vmlinux` (Debian/Ubuntu: `/usr/lib/debug/boot/vmlinux-<version>` from the `linux-image-<version>-dbg` / `-dbgsym` package);
- the `kernel.elf` of the [MemLens demo data](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (22 MB zip; a Debian 13 6.12 kernel exported from a memory image, so freed init code reads as other bytes);
- an Android GKI `Image` turned into an ELF with kallsyms names by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf).

- a kernel module (`.ko`, or `.ko.xz` / `.ko.gz` as distributions ship them; unpack `.ko.zst` with `zstd -d` first): it has its own `__bug_table` and `__jump_table` (and `__ex_table` if its code touches user memory) as relocatable sections. The command line lays the sections out from 0x10000 in file order, puts undefined symbols in 8-byte slots after them and applies the relocations, so file names, keys and targets come out right; IDA relocates a `.ko` itself, and kflow then finds the tables by segment name. Addresses printed for a module are those of this layout, not necessarily IDA's.

A stripped `vmlinux` (from `extract-vmlinux`) still has `__bug_table` and `__ex_table` as sections, and kflow uses them; the static-key table has no section of its own and needs the `__start___jump_table` symbol.

1. Outside IDA, see what is there: `python3 -m kflow kernel.elf` (output below).
2. In IDA, open the kernel and run **Edit > Plugins > kflow: Annotate kernel sites**.
3. **kflow: List BUG/WARN sites** lists every trap with its function and source line; Enter jumps to it.
4. **kflow: Remove annotations** removes kflow's comments and the references it added (Annotate records each one in the database, so Remove works after a rebase too). References that were there before, IDA's own (for example at a static-key site that is currently a jump) or yours, and your own comments are never touched.

Without the IDA window (idalib, IDA 9.0+): `python3 tools/kflow_headless.py <kernel> [--no-analysis] [--remove]` does steps 2 and 4 and saves the database.

## What you get (real output, not IDA screenshots)

The MemLens demo `kernel.elf` (Debian 13, 6.12.115, x86_64):

```
$ python3 -m kflow kernel.elf
__bug_table (addr,file,line,flags): 9850 sites, 7831 WARN (resume after the trap), 2019 BUG; 9850 with file:line in 1168 source files
  WARN sites that are ud2 here: 7504; sites inside a function symbol: 9329
__jump_table: 9237 static-key sites, 8898 keys named (1728 tracepoints, 1941 pr_debug sites, 100 as symbol+offset), 9006 targets in the same function
__ex_table (insn,fixup,data): 671 faulting instructions with a fixup, 635 fixups in the same function; types UACCESS 410, IMM_REG 87, WRMSR 42, RDMSR 39, FAULT_SGX 23, CLEAR_FS 15

$ python3 -m kflow kernel.elf --list jump --limit 3   (summary lines and the '... more' line left out here)
0xffffffff8e391de7 -> 0xffffffff8e391dfc  arch_exit_to_user_mode_prepare.isra.0    key randomize_kstack_offset (likely)
0xffffffff8ef08602 -> 0xffffffff8ef08625  __do_fast_syscall_32                     key randomize_kstack_offset (likely)
0xffffffff8ef08705 -> 0xffffffff8ef087f2  do_syscall_64                            key randomize_kstack_offset (likely)

$ python3 -m kflow kernel.elf --list ex --limit 3   (same)
0xffffffff8e200029 -> 0xffffffff8e20002b  sev_es_terminate                         WRMSR
0xffffffff8e20057d -> 0xffffffff8e20057f  early_set_pages_state                    WRMSR
0xffffffff8e200583 -> 0xffffffff8e200585  early_set_pages_state                    RDMSR
```

(`--list warn` and `--list bug` print `address  WARN|BUG  function  file:line`; WARN sites whose bytes are no longer `ud2` sit in init code that the running kernel had freed.)

The comments kflow writes in IDA, for three of the sites above (text produced by `kflow/idalayer.py` through the fake-IDA test, not an IDA screenshot):

```
0xffffffff8e629bc4 (mfill_atomic_copy):  kflow: WARN at mm/userfaultfd.c:755 (the kernel reports and continues after this trap)
0xffffffff8e391de7 (arch_exit_to_user_mode_prepare.isra.0):  kflow: static key randomize_kstack_offset (static_branch_likely): runtime-patched NOP/branch; branch target 0xFFFFFFFF8E391DFC
0xffffffff8e200029 (sev_es_terminate):  kflow: may fault -> fixup at 0xFFFFFFFF8E20002B (WRMSR)
```

## What was verified

`tests/test_demo.py <kernel ELF>` checks the decoded tables against the instruction bytes; `tests/test_ida_stub.py <kernel ELF>` runs the IDA layer on fake `ida_*` modules backed by the same file (annotate, then remove, with IDA's own references, a reference you added and user comments in place; again after a rebase); `tests/test_headless_stub.py <kernel ELF>` does the same through the headless runner, and `tests/test_entry_stub.py <kernel ELF>` loads the plugin itself and runs its three menu actions; `python3 tests/test_core.py` covers the layouts on synthetic tables and the relocation of a synthetic module.

| Kernel (banner) | BUG/WARN sites | static-key sites | exception-table entries | what the tests check |
|---|---|---|---|---|
| 6.12.115+deb13.1-amd64, x86_64 (MemLens demo, memory image) | 9,850 (7,831 WARN) | 9,237 | 671 (12-byte, type field) | the 663 sites that are a `jmp` now branch to the decoded target; the other sites outside init code are 2/5-byte NOPs (225 sites in freed init memory are skipped); WARN/BUG sites in functions are `ud2`; >=95% of file names are kernel paths |
| 6.12.115+deb13.1-cloud-amd64, x86_64, stripped `vmlinux` | 9,993 (7,615 WARN) | needs symbols | 630 | tables found by section name; file names are kernel paths (the trap-byte check needs function symbols, so the CLI's "7,615 WARN sites are ud2" is not a test) |
| 5.10.198-android12-9, arm64 (vmlinux-to-elf) | 24,386 (17,374 WARN, all `brk #0x800`) | 75,316 | 1,488 (8-byte, no type) | the 54,896 sites outside init code compiled as a `b` branch to the decoded target (most are `static_branch_likely` sites, not keys switched on); the other sites outside init code are `nop`; file pointers here are entry-relative (before Linux 5.19) |
| 5.10.0-32-amd64 (Debian 11, 5.10.223), x86_64 (vmlinux-to-elf) | 6,573 (4,671 WARN) | 3,820 | 548 (12-byte, third field = handler function) | WARN/BUG sites are `ud2`; the 169 `jmp` sites outside init code branch to the decoded target; file pointers are entry-relative; all 548 handlers are the kernel's `ex_handler_*` functions (288 `ex_handler_uaccess`, 114 `ex_handler_default`, ...), and the 49 MSR handlers sit on `rdmsr`/`wrmsr` |
| module `nf_tables.ko` from 6.12.115+deb13.1-cloud-amd64, x86_64 (relocations applied by the command line) | 141 (138 WARN) | 8 | none in this module | WARN/BUG sites are `ud2`; the 2 sites compiled as a `jmp` branch to the decoded target; all 141 `file:line` pairs checked against the v6.12.115 sources: 133 lines hold a `WARN`/`BUG` macro, the other 8 a `memcpy` (fortified copies warn on overflow); keys named, e.g. `nft_trace_enabled` |
| modules `fat.ko`, `vfat.ko` (Debian installer package `fat-modules`), `ext4.ko`, `jbd2.ko` (`ext4-modules`) from 6.12.94+deb13-arm64, arm64 | 25 + 5 + 484 + 162 (250 WARN, all `brk #0x800`) | 0 + 0 + 153 + 25 (all `nop` on disk; every target in the same function as its site; 174 of 178 keys are tracepoints) | 25 + 0 + 11 + 0 (12-byte, all UACCESS_ERR_ZERO) | all 676 `file:line` pairs checked against the v6.12.94 sources: 554 lines hold a `WARN`/`BUG` macro, 116 an assertion macro built on `BUG_ON` (`ASSERT`, `J_ASSERT*`, `assert_spin_locked`), 6 a fortified copy (`memcpy`; these warn on overflow); every fixup lies in the same function as its faulting instruction |
| 6.1.57-android14-11, arm64 (vmlinux-to-elf) | 12,223 (8,792 WARN, all `brk #0x800`) | 10,629 | 1,043 (12-byte: 1,022 UACCESS_ERR_ZERO, 12 LOAD_UNALIGNED_ZEROPAD, 9 KACCESS_ERR_ZERO) | the 1,099 `b` sites outside init code branch to the decoded target; the other sites outside init code are `nop` |

The entry layout is chosen from the data: for `__bug_table` the layout whose entries name source files, for `__ex_table` the layout that gives the address-sorted list the kernel build produces (arm64 before 5.16 has 8-byte entries).

## Limits

- 64-bit little-endian kernels with relative table entries (x86_64; arm64 with `CONFIG_GENERIC_BUG_RELATIVE_POINTERS`). Not 32-bit kernels. Kernels up to 4.19 have an absolute 24-byte static-key table: kflow reports it as not decoded and still decodes the other two tables (checked on synthetic tables only).
- Exception-type names: x86_64 from Linux 6.12, arm64 from Linux 6.1/6.12 (`asm-extable.h`, same numbers in both; Linux 6.0 renumbered them, so on arm64 5.16-5.19 the names are wrong: there 3 is UACCESS_ERR_ZERO and 4 LOAD_UNALIGNED_ZEROPAD). Other versions number some x86_64 types differently, so treat the name as a hint; arm64 kernels before 5.16 have no type field. On x86_64 before 5.16 the third field points to a handler function: kflow detects that layout and names the handler instead (checked on a synthetic table and on Debian 11's 5.10 kernel).
- Not tried on Linux 6.19+ kernels (the WARN-with-message flag is taken from the 6.19 sources). x86_64 6.19+ kernels built without `CONFIG_DEBUG_BUGVERBOSE` (distributions and Android GKI enable it) have entries with a message but no file and line: kflow decodes that layout (synthetic test only) and lists those sites without `file:line`.
- kflow does not change how IDA treats a WARN `ud2` (IDA may still end the block there); the comment says that execution continues. Not tried in IDA.
- Static-key sites in freed init code (memory images) are decoded but not commented when they are outside code segments.
- Kernel modules: checked on one x86_64 module (`nf_tables.ko`) and four arm64 modules (`fat.ko`, `vfat.ko`, `ext4.ko`, `jbd2.ko`). Only the data relocations the tables use are applied (x86_64 `R_X86_64_PC32`/`PLT32`/`PC64`/`64`/`32`/`32S`, arm64 `R_AARCH64_PREL32`/`PREL64`/`ABS64`/`ABS32`); the modules above use `R_X86_64_PC32`/`PC64` and `R_AARCH64_PREL32`/`PREL64` in their tables; the absolute types follow the same rule but are untested on real files. In IDA, kflow relies on IDA's own relocation of the `.ko` (not tried in IDA).
- Alternatives (`.altinstructions`) are not handled; see [ida-linux-alternatives](https://github.com/opensrcsec/ida-linux-alternatives).

## Credits

Written by an AI agent (Claude, operated by Nightshift Labs). Table layouts from the Linux kernel sources (`include/asm-generic/bug.h`, `include/linux/jump_label.h`, `arch/x86/include/asm/extable_fixup_types.h`). If you list authors elsewhere, please use "Nightshift Labs (AI agent)".

MIT licence.
