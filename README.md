# kflow

<img src="assets/logo.png" width="96" align="right" alt="kflow logo">

For kernel reverse engineers (Linux and Android vulnerability research, patch diffing, crash triage): kflow turns the bare traps, NOPs and faulting instructions of a kernel into source lines, static keys and fixups. A `WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0` line pasted from a kernel log leads to the trap it names, and a NOP says which key patches it and where it then jumps.

Before: what the disassembly shows at three addresses of the [MemLens demo kernel](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (`objdump -d`). After: the comment kflow writes at each one (text from kflow's fake-IDA test, not an IDA screenshot):

```
ffffffff8e629bc4  ud2            ; kflow: WARN at mm/userfaultfd.c:755 (the kernel reports and continues after this trap)
ffffffff8e391de7  xchg %ax,%ax   ; kflow: static key randomize_kstack_offset (static_branch_likely): runtime-patched NOP/branch; jumps to 0xFFFFFFFF8E391DFC when the key is off
ffffffff8e200029  wrmsr          ; kflow: may fault -> fixup at 0xFFFFFFFF8E20002B (WRMSR)
```

## Features

**Status:** the table decoders are checked on seven real kernels and five kernel modules; the IDA layer has not yet been run inside real IDA (only with fake `ida_*` modules). [Details](#status-read-this-first)

- [**BUG/WARN comments**](#step-by-step): every BUG/WARN site of the kernel's `__bug_table` gets its source `file:line` (where the kernel recorded one) and whether the kernel continues after the trap (WARN) or not (BUG).
- [**BUG/WARN list**](#step-by-step): **kflow: List BUG/WARN sites** lists every trap with its function and `file:line`; Enter jumps to it.
- [**Go to oops/WARN line**](#step-by-step): **kflow: Go to oops/WARN line** takes pasted log text (a `WARNING:`, `kernel BUG at`, `RIP:` or `pc :` line, a whole oops or syzbot report, `func+0xoff` or `file:line`) and jumps to the trap it names; when only `file:line` is known and several traps share it, it lists just those. `python3 -m kflow <kernel> --oops <log>` does the same outside IDA (the IDA action is tested only with fake `ida_*` modules). Real command-line output on the MemLens demo kernel; the log line is in the kernel's `__warn()` format, written for this site, not taken from a real crash:

  ```
  $ python3 -m kflow kernel.elf --list warn --limit 100000 | grep userfaultfd.c:755     # before: file:line alone
  0xffffffff8e629bc4 WARN  mfill_atomic_copy                        mm/userfaultfd.c:755
  0xffffffff8e62a489 WARN  mfill_atomic_zeropage                    mm/userfaultfd.c:755
  0xffffffff8e62ab60 WARN  mfill_atomic_continue                    mm/userfaultfd.c:755
  0xffffffff8e62b164 WARN  mfill_atomic_poison                      mm/userfaultfd.c:755

  $ echo 'WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0' > warn.txt
  $ python3 -m kflow kernel.elf --oops warn.txt                                           # after: the whole line
  from the log: WARNING at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0
  exact: the WARN site at mfill_atomic_copy+0x674 (0xffffffff8e629bc4)
    0xffffffff8e629bc4 WARN  mfill_atomic_copy                        mm/userfaultfd.c:755
  ```
- [**Static-key comments and key references**](#step-by-step): each static-key site (a NOP or branch the kernel patches at runtime) gets its key, its branch target and when it jumps, and a jump reference to the target where IDA has none (a data reference if the target is inside another function); a data reference from each site to its key makes X on a key list its sites.
- [**Static-key chooser**](#step-by-step): **kflow: List static-key sites** shows every site with its key, `likely`/`unlikely`, `jump` / `no jump` now, the target and the function; the filter finds every site of one key.
- [**Exception-table fixups**](#what-kflow-reads): each instruction that may fault on purpose (user-memory access, MSR reads...) gets its fixup and type (or handler), and a jump reference to the fixup (a data reference if it is inside another function).
- [**Hex-Rays pseudocode comments**](#hex-rays-pseudocode-comments): with the decompiler, a `// kflow: ...` comment at the end of the site's pseudocode line where it has one (display text only, nothing saved; tested only against a fake `ida_hexrays` module).
- [**Kernel modules**](docs/modules.md) (`.ko`, `.ko.xz`, `.ko.gz`): the command line applies the module's relocations; in IDA, a key inside an imported symbol (`nf_hooks_needed+0x270` in `bridge.ko`) is named from kflow's own decode of the `.ko` when the file is still where IDA loaded it from and both decodes line up (IDA's extern-segment layout is not verified; tested only with fake `ida_*` modules).
- [**Clean removal**](#step-by-step): **kflow: Remove annotations** takes out only the comments and references kflow added (also after a rebase); IDA's and yours stay.
- [**WARN fall-through**](docs/warnflow.md) (experimental, off by default, x86_64 only, not yet run in real IDA): **kflow: Let WARN sites fall through (experimental)** adds ordinary flow after exactly the WARN `ud2` traps the kernel's `__bug_table` lists, so that IDA can reach the code after them; **kflow: Remove WARN fall-through** undoes it.
- [**Headless runner**](#headless-idalib): `python3 tools/kflow_headless.py <kernel>` annotates (or with `--remove` removes) and saves the database without the IDA window (idalib, IDA 9.0+); `--json` exports every site with IDA's function names.
- [**Command-line decoder, no IDA needed**](#what-you-get-real-output-not-ida-screenshots): `python3 -m kflow <kernel ELF>` needs only Python 3.8+ and no packages; `--list warn`, `bug`, `jump` or `ex` lists the sites; `--oops <log>` finds the site a kernel log names.
- [**One-command tests**](#what-was-verified): `sh tests/run_all.sh` runs every test in about two seconds on a pinned Debian arm64 `ext4.ko` (sha256 checked) or on your own files.

## Status: read this first

**kflow has not yet been run inside real IDA.** It was built without access to an IDA installation. The table decoders are checked on seven real kernels and five kernel modules (below): trap bytes, branch targets and source-file names; the IDA layer is small, uses IDAPython names and object members that all appear in the official stubs (203 checks in `tests/check_ida_api.py`; the 86 `ida_*` names also exist in the stubs of IDA 9.1, 9.2, 9.3 and 9.4: `tests/check_ida_names.py` on the PyPI `idapro` packages 0.0.5, 0.0.7, 0.0.9 and 0.0.11), and has only been exercised with fake `ida_*` modules. Bug reports are very welcome.

kflow was built by an AI agent (Claude, operated by Nightshift Labs).

## What kflow reads

Linux kernels carry their own maps of code that a disassembler cannot see from the instructions alone:

- **`__bug_table`**: every `BUG()` / `WARN()` trap (`ud2` on x86_64, `brk #0x800` on arm64; from Linux 6.19 an x86_64 WARN with a message is a call instead, and kflow says so), with the **source file and line** and a flag that says whether the kernel **continues after the trap** (WARN) or not (BUG).
- **`__jump_table`**: every static-key site (`static_branch_likely/unlikely`, tracepoints): a NOP or branch that the kernel patches at runtime, its **key** and its **branch target**.
- **`__ex_table`**: every instruction that may fault on purpose (user-memory access, MSR reads...) and its **fixup** landing pad.

kflow reads these tables from the database and, in IDA, comments every site and adds the jump references IDA cannot find on its own (a NOP has no branch, a fault has no visible path to its fixup). It also lists every BUG/WARN site with its function and `file:line`.

## Install

```
hcli plugin install kflow
```

Hex-Rays added kflow to the plugin index on Nov 12 ([plugin-repository#48](https://github.com/HexRaysSA/plugin-repository/pull/48)); it appears after their next index sync, and the index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/kflow/releases). Until `hcli plugin install kflow` works (or if `hcli plugin status` shows an older version):

- install a release zip directly, for example `hcli plugin install https://github.com/nightshift-labs-ai/kflow/archive/refs/tags/v0.0.4.zip`,
- or copy this folder into your IDA `plugins` directory.

The command-line decoder needs only Python 3.8+ and no packages: `python3 -m kflow <kernel ELF>` from this folder.

## Try it

You need a 64-bit kernel ELF that still has the kernel's symbol names, for example:

- a distribution's debug `vmlinux` (Debian/Ubuntu: `/usr/lib/debug/boot/vmlinux-<version>` from the `linux-image-<version>-dbg` / `-dbgsym` package);
- the `kernel.elf` of the [MemLens demo data](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (22 MB zip; a Debian 13 6.12 kernel exported from a memory image, so freed init code reads as other bytes);
- the `vmlinuz` your Linux machine boots, or an Android GKI `Image`, turned into an ELF with kallsyms names by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) (checked on Ubuntu 24.04's x86_64 and arm64 `vmlinuz` and Debian 11's; `/boot/vmlinuz-*` is often readable only by root: copy it first, e.g. `sudo cp /boot/vmlinuz-$(uname -r) . && sudo chown $USER vmlinuz-*`, then `vmlinux-to-elf vmlinuz-<version> kernel.elf`).
- a kernel module (`.ko`, or `.ko.xz` / `.ko.gz` as distributions ship them; unpack `.ko.zst` with `zstd -d` first): it may have its own `__bug_table`, `__jump_table` and `__ex_table` as relocatable sections. The command line applies the relocations; IDA relocates a `.ko` itself. Layout, imported keys and what is verified: [docs/modules.md](docs/modules.md); a one-minute example: [Try a real module](#try-a-real-module-one-minute-377-kb-download).

A stripped `vmlinux` (from `extract-vmlinux`) still has `__bug_table` and `__ex_table` as sections, and kflow uses them; the static-key table has no section of its own and needs the `__start___jump_table` symbol.

### Step by step

1. Outside IDA, see what is there: `python3 -m kflow kernel.elf` (output below).
2. In IDA, open the kernel and run **Edit > Plugins > kflow: Annotate kernel sites** (comments, the missing jump references, and a data reference from each static-key site to its key, so X on a key lists its sites). Run it after IDA's auto-analysis has finished: a static-key target or fixup that lies inside another function (not at its start, not in a tail chunk the site's own function shares, and not the `.cold` part of the site's own function) then gets a data reference instead of a jump reference, so that IDA is not asked to treat that function's code as flow of this one; it is still listed under X. Running Annotate again later changes earlier references to match IDA's current functions. A site that IDA has not made an instruction yet gets its comment but no reference (Annotate says how many such sites there are); run Annotate again once auto-analysis has finished.
3. **kflow: List BUG/WARN sites** lists every trap with its function and source line; Enter jumps to it.
   From a crash log such as `WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0`: run **kflow: Go to oops/WARN line** and paste the line, or the whole report. It takes the function+offset from the `RIP:` / `pc :` line, else from the `WARNING:` or `kernel BUG at` line (of the first report, if you paste several; a KASAN, lockdep or hung-task report has neither, and its call trace counts only if its first entry is itself a BUG/WARN site), and jumps there: the kernel prints the address of the trap itself, so this lands on the trap (the `ud2` / `brk`; for an x86_64 6.19+ WARN with a message, the site is part of a call to `__WARN_trap`, whose `ud1` traps: the `RIP:` line names `__WARN_trap` and kflow takes the `WARNING:` line's function+offset), where kflow's comment confirms the file and line. With only a `file:line` (one line can have several sites: on the demo kernel four functions share `mm/userfaultfd.c:755`) it shows the list with just those sites. If the log contradicts the site at that address (its `WARNING:` / `kernel BUG at` line names another `file:line` or kind, or without such a line it prints another function size: a log from another build, or two reports pasted together), it warns and shows the sites at the log's `file:line` instead of jumping. The match and any notes (no site at that exact address, a module the log names) go to the Output window. Tested only with fake `ida_*` modules.
4. **kflow: List static-key sites** lists every static-key site with its key, `likely`/`unlikely`, whether the bytes there are a jump to the target now (`jump` / `no jump`), the target and the function; the chooser's filter finds every site of one key.
5. **kflow: Remove annotations** removes kflow's comments and the references it added (Annotate records each one in the database, so Remove works after a rebase too). References that were there before, IDA's own (for example at a static-key site that is currently a jump) or yours, and your own comments are never touched.
6. Experimental, off by default, x86_64 only: **kflow: Let WARN sites fall through (experimental)** and **kflow: Remove WARN fall-through**; read [docs/warnflow.md](docs/warnflow.md) before you use them.

### Hex-Rays pseudocode comments

- With the Hex-Rays decompiler, each annotated site whose address has a pseudocode statement also gets a `// kflow: ...` comment at the end of that line (BUG or WARN with `file:line`; static key and when it jumps; fixup and type).
- A static-key site with no statement of its own (usually a NOP) gets it on the line of the next instruction that has one, if that is at most 16 bytes on in the same function with no other kflow site in between.
- Display text only, nothing saved; Annotate and Remove apply to functions decompiled afterwards (press F5 in a pseudocode window that is already open).
- Not yet run in real IDA or the real decompiler; tested only against a fake `ida_hexrays` module.

### Headless (idalib)

Without the IDA window (idalib, IDA 9.0+): `python3 tools/kflow_headless.py <kernel> [--no-analysis] [--remove] [--json sites.json]` does steps 2 and 5 and saves the database. Not yet run with a real idalib (tested on fake `idapro` / `ida_*` modules).

`--json sites.json` also writes every decoded site with IDA's function names, for scripts (for example to match `file:line` across kernel versions when patch diffing). Addresses are hex strings. Three records from the MemLens demo kernel (fake-IDA test output; function names there come from the ELF symbols):

```
{"addr": "0xFFFFFFFF8E629BC4", "kind": "WARN", "function": "mfill_atomic_copy", "file": "mm/userfaultfd.c", "line": 755}
{"addr": "0xFFFFFFFF8E391DE7", "key": "randomize_kstack_offset", "kind": "likely", "now": "no jump", "target": "0xFFFFFFFF8E391DFC", "function": "arch_exit_to_user_mode_prepare.isra.0"}
{"addr": "0xFFFFFFFF8E200029", "fixup": "0xFFFFFFFF8E20002B", "type": "WRMSR", "handler": null, "function": "sev_es_terminate"}
```

The file has the lists `bug`, `jump` and `ex` of such records, plus `input`, `bug_layout` and `missing` (tables not found).

### Try a real module (one minute, 377 KB download)

Debian's installer ships kernel modules in small packages. The arm64 `ext4.ko` has all three tables (any Linux with `curl`, `ar`, `tar` and Python 3.8+; nothing is installed):

```
curl -sO https://deb.debian.org/debian/pool/main/l/linux-signed-arm64/ext4-modules-6.12.94+deb13-arm64-di_6.12.94-1_arm64.udeb
sha256sum ext4-modules-6.12.94+deb13-arm64-di_6.12.94-1_arm64.udeb   # f7957d08ff7b2d63775a2b97897e1934de2066b9d668cad101fa09147d35aaa0
ar x ext4-modules-6.12.94+deb13-arm64-di_6.12.94-1_arm64.udeb && tar -xf data.tar.xz
PYTHONPATH=/path/to/kflow python3 -m kflow lib/modules/6.12.94+deb13-arm64/kernel/fs/ext4/ext4.ko.xz --list jump --limit 3
```

(`/path/to/kflow` = this folder, e.g. the installed plugin under your IDA user directory's `plugins/kflow`). Output:

```
__bug_table (addr,file,line,flags): 484 sites, 195 WARN (resume after the trap), 289 BUG; 484 with file:line in 28 source files
  WARN sites that are brk #0x800 here: 195; sites inside a function symbol: 484
__jump_table: 153 static-key sites, 153 keys named (151 tracepoints, 0 pr_debug sites, 0 as symbol+offset), 153 targets in the same function
__ex_table (insn,fixup,data): 11 faulting instructions with a fixup, 11 fixups in the same function; types UACCESS_ERR_ZERO 11
found by section name (no __start_/__stop_ symbols): bug, jump, ex
0x49e34 -> 0x49f14  ext4_read_block_bitmap_nowait            key tracepoint ext4_read_block_bitmap_load
0x4cb28 -> 0x4cb68  __ext4_journal_start_sb                  key tracepoint ext4_journal_start_inode
0x4cc0c -> 0x4cc14  __ext4_journal_start_sb                  key tracepoint ext4_journal_start_sb
... 150 more (--limit)
```

In IDA, open the same `ext4.ko` (unpacked: `xz -dk ...ext4.ko.xz`) and run **kflow: Annotate kernel sites**.

## What you get (real output, not IDA screenshots)

The MemLens demo `kernel.elf` (Debian 13, 6.12.115, x86_64):

```
$ python3 -m kflow kernel.elf
__bug_table (addr,file,line,flags): 9850 sites, 7831 WARN (resume after the trap), 2019 BUG; 9850 with file:line in 1168 source files
  WARN sites that are ud2 here: 7504; sites inside a function symbol: 9329
__jump_table: 9237 static-key sites, 9237 keys named (1728 tracepoints, 1941 pr_debug sites, 439 as symbol+offset), 9006 targets in the same function
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
0xffffffff8e391de7 (arch_exit_to_user_mode_prepare.isra.0):  kflow: static key randomize_kstack_offset (static_branch_likely): runtime-patched NOP/branch; jumps to 0xFFFFFFFF8E391DFC when the key is off
0xffffffff8e200029 (sev_es_terminate):  kflow: may fault -> fixup at 0xFFFFFFFF8E20002B (WRMSR)
```

## What was verified

`sh tests/run_all.sh` runs every test below in about two seconds on Debian's arm64 `ext4.ko` (it downloads the 377 KB package from the module example above and checks its sha256), or on your own files: `sh tests/run_all.sh vmlinux mod.ko`; `IDA_STUBS=<folder with ida_*.pyi>` adds the IDA API name check.

- `tests/test_demo.py <kernel ELF>` checks the decoded tables against the instruction bytes;
- `tests/test_ida_stub.py <kernel ELF>` runs the IDA layer on fake `ida_*` modules backed by the same file (annotate, then remove, with IDA's own references, a reference you added and user comments in place; again after a rebase);
- `tests/test_headless_stub.py <kernel ELF>` does the same through the headless runner;
- `tests/test_entry_stub.py <kernel ELF>` loads the plugin itself and runs its annotation, list, Go to oops/WARN line and remove actions;
- `tests/test_oops.py [<kernel ELF>]` reads log samples built from the kernel's own printk formats (x86 and arm64 reports, a syzbot report, Linux 4.9 forms, `dmesg` / journal prefixes, call traces with `?` entries and `[module]`); with a kernel ELF, a `RIP:` / `pc :` line made for every BUG/WARN site inside a function finds that site, and `--oops` is run;
- `tests/test_warnflow_stub.py <kernel ELF>` runs the two experimental WARN fall-through actions on fake `ida_*` modules that model IDA's reanalysis and processor hooks, and function tails with a simplified model (see the test's docstring);
- `python3 tests/test_core.py` covers the layouts on synthetic tables and the relocation of a synthetic module.

| Kernel (banner) | BUG/WARN sites | static-key sites | exception-table entries | what the tests check |
|---|---|---|---|---|
| 6.12.115+deb13.1-amd64, x86_64 (MemLens demo, memory image) | 9,850 (7,831 WARN) | 9,237 | 671 (12-byte, type field) | the 663 sites that are a `jmp` now branch to the decoded target; the other sites outside init code are 2/5-byte NOPs (225 sites in freed init memory are skipped); WARN/BUG sites in functions are `ud2`; >=95% of file names are kernel paths |
| 6.12.115+deb13.1-cloud-amd64, x86_64, stripped `vmlinux` | 9,993 (7,615 WARN) | needs symbols | 630 | tables found by section name; file names are kernel paths (the trap-byte check needs function symbols, so the CLI's "7,615 WARN sites are ud2" is not a test) |
| 5.10.198-android12-9, arm64 (vmlinux-to-elf) | 24,386 (17,374 WARN, all `brk #0x800`) | 75,316 | 1,488 (8-byte, no type) | the 54,896 sites outside init code compiled as a `b` branch to the decoded target (most are `static_branch_likely` sites, not keys switched on); the other sites outside init code are `nop`; file pointers here are entry-relative (before Linux 5.19) |
| 5.10.0-32-amd64 (Debian 11, 5.10.223), x86_64 (vmlinux-to-elf) | 6,573 (4,671 WARN) | 3,820 | 548 (12-byte, third field = handler function) | WARN/BUG sites are `ud2`; the 169 `jmp` sites outside init code branch to the decoded target; file pointers are entry-relative; all 548 handlers are the kernel's `ex_handler_*` functions (288 `ex_handler_uaccess`, 114 `ex_handler_default`, ...), and the 49 MSR handlers sit on `rdmsr`/`wrmsr` |
| module `nf_tables.ko` from 6.12.115+deb13.1-cloud-amd64, x86_64 (relocations applied by the command line) | 141 (138 WARN) | 8 | none in this module | WARN/BUG sites are `ud2`; the 2 sites compiled as a `jmp` branch to the decoded target; all 141 `file:line` pairs checked against the v6.12.115 sources: 133 lines hold a `WARN`/`BUG` macro, the other 8 a `memcpy` (fortified copies warn on overflow); keys named, e.g. `nft_trace_enabled` |
| modules `fat.ko`, `vfat.ko` (Debian installer package `fat-modules`), `ext4.ko`, `jbd2.ko` (`ext4-modules`) from 6.12.94+deb13-arm64, arm64 | 25 + 5 + 484 + 162 (250 WARN, all `brk #0x800`) | 0 + 0 + 153 + 25 (all `nop` on disk; every target in the same function as its site; 174 of 178 keys are tracepoints) | 25 + 0 + 11 + 0 (12-byte, all UACCESS_ERR_ZERO) | all 676 `file:line` pairs checked against the v6.12.94 sources: 554 lines hold a `WARN`/`BUG` macro, 116 an assertion macro built on `BUG_ON` (`ASSERT`, `J_ASSERT*`, `assert_spin_locked`), 6 a fortified copy (`memcpy`; these warn on overflow); every fixup lies in the same function as its faulting instruction |
| 6.1.57-android14-11, arm64 (vmlinux-to-elf) | 12,223 (8,792 WARN, all `brk #0x800`) | 10,629 | 1,043 (12-byte: 1,022 UACCESS_ERR_ZERO, 12 LOAD_UNALIGNED_ZEROPAD, 9 KACCESS_ERR_ZERO) | the 1,099 `b` sites outside init code branch to the decoded target; the other sites outside init code are `nop` |
| 6.8.0-149-generic (Ubuntu 24.04, 6.8.12), x86_64 (`vmlinuz` from the `linux-image-unsigned` package, vmlinux-to-elf) | 11,027 (8,259 WARN) | 8,304 | 632 (12-byte, type field) | WARN/BUG sites in functions are `ud2`; the 243 `jmp` sites outside init code branch to the decoded target; the other sites outside init code are NOPs; >=95% of file names are kernel paths; the 45 WRMSR and 41 RDMSR entries all sit on `wrmsr`/`rdmsr` |
| 6.8.0-149-generic (Ubuntu 24.04, 6.8.12), arm64 (`vmlinuz` from the `linux-image` package, vmlinux-to-elf) | 10,803 (8,085 WARN, all `brk #0x800`) | 31,250 | 935 (12-byte: 917 UACCESS_ERR_ZERO, 9 KACCESS_ERR_ZERO, 9 LOAD_UNALIGNED_ZEROPAD) | the 192 `b` sites outside init code branch to the decoded target; the other sites outside init code are `nop`; >=95% of file names are kernel paths |

The entry layout is chosen from the data: for `__bug_table` the layout whose entries name source files, for `__ex_table` the layout that gives the address-sorted list the kernel build produces (arm64 before 5.16 has 8-byte entries).

## Limits

One line per limit; the full text is in [docs/limits.md](docs/limits.md).

- 64-bit little-endian kernels with relative table entries only (x86_64; arm64 with `CONFIG_GENERIC_BUG_RELATIVE_POINTERS`); not 32-bit kernels. Up to 4.19 the static-key table is not decoded. [More](docs/limits.md#supported-kernels)
- Exception-type names come from x86_64 Linux 6.12 and arm64 Linux 6.1/6.12; on other versions treat them as a hint (on arm64 5.16-5.19 they are wrong). [More](docs/limits.md#exception-type-names)
- Linux 6.19+: checked only on a stripped Ubuntu mainline 7.0.0 x86_64 `vmlinux`. [More](docs/limits.md#linux-619-and-later)
- WARN fall-through (experimental, off by default, x86_64 only): not yet run in real IDA, tested only on fake `ida_*` modules; the part most likely to need a fix. [More](docs/warnflow.md)
- Sites in freed init code (memory images) are decoded but not commented when they are outside code segments (MemLens demo kernel, fake-IDA test: 521 of 9,850 BUG/WARN, 225 of 9,237 static-key and 13 of 671 exception-table sites).
- Kernel modules: checked on one x86_64 and four arm64 modules; absolute relocation types untested on real files; in IDA, kflow relies on IDA's own relocation of the `.ko` (not tried in IDA). [More](docs/modules.md#what-was-checked)
- Go to oops/WARN line: the log must come from the same build as the file you open; from another build the offsets differ, and when the log's own `WARNING:` / `kernel BUG at` line (or, without one, its function size) contradicts the site at that address kflow reports a mismatch and does not jump, but a log with neither can still land on an unrelated site; `foo+0x10` also tries the functions named `foo` plus a Clang LTO suffix (`foo.123`, `foo.llvm.N`, `foo.cfi`: the kernel prints them as `foo`), never GCC's `foo.isra.0` / `foo.part.0`; in IDA only the function IDA shows under the log's name is tried (IDA names one function so; the command line lists all same-named static functions), and a note says so for a static function unless the log's `WARNING:` / `kernel BUG at` line confirms the site; IDA's names for symbols with a dot and for same-named static functions are not verified (not yet run in real IDA). [More](docs/limits.md#go-to-oopswarn-line)
- Alternatives (`.altinstructions`) are not handled; see [ida-linux-alternatives](https://github.com/opensrcsec/ida-linux-alternatives).

## Credits

Written by an AI agent (Claude, operated by Nightshift Labs). Table layouts from the Linux kernel sources (`include/asm-generic/bug.h`, `include/linux/jump_label.h`, `arch/x86/include/asm/extable_fixup_types.h`). If you list authors elsewhere, please use "Nightshift Labs (AI agent)".

Prior art for letting IDA continue after `ud2`: [linux_und.py](https://git.zx2c4.com/ida-plugins/tree/linux_und.py) by Jason A. Donenfeld (2017).

MIT licence.
