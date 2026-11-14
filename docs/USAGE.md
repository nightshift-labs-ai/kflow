# Using kflow

The short version is in the [README](../README.md#try-it) (what you need, install); what each feature does: [FEATURES.md](FEATURES.md).

## Step by step

1. Outside IDA, see what is there: `python3 -m kflow kernel.elf` ([output](OUTPUT.md#what-you-get-real-output-not-ida-screenshots)).
2. In IDA, open the kernel and run **Edit > Plugins > kflow: Annotate kernel sites** (comments, the missing jump references, and a data reference from each static-key site to its key, so X on a key lists its sites). Run it after IDA's auto-analysis has finished: a static-key target or fixup that lies inside another function (not at its start, not in a tail chunk the site's own function shares, and not the `.cold` part of the site's own function) then gets a data reference instead of a jump reference, so that IDA is not asked to treat that function's code as flow of this one; it is still listed under X. Running Annotate again later changes earlier references to match IDA's current functions. A site that IDA has not made an instruction yet gets its comment but no reference (Annotate says how many such sites there are); run Annotate again once auto-analysis has finished. Annotate ends with a window titled **kflow: Annotate finished**: how many static-key NOP sites can jump to code nothing else in the database reaches, one line each for the BUG/WARN sites, static-key sites and exception-table fixups (and how many sites got no reference because IDA has no instruction there yet), the decompile check's result (with the decompiler), a next step (with the decompiler: the function with the most such NOP sites, to press F5 in; and that **Go to oops/WARN line** starts with an example line when it can build one), and buttons to the static-key and BUG/WARN lists; the Output window has the counts.
3. **kflow: List BUG/WARN sites** lists every trap with its function and source line; Enter jumps to it.
   From a crash log such as `WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0`: run **kflow: Go to oops/WARN line** and paste the line, or the whole report. It takes the function+offset from the `RIP:` / `pc :` line, else from the `WARNING:` or `kernel BUG at` line (of the first report with a `WARNING:` / `kernel BUG at` line or a trap `RIP:` / `pc :` line, if you paste several; a KASAN, lockdep or hung-task report has neither: a `RIP:` / `pc :` line after its call trace began (x86 prints an interrupted context's registers there) or in another CPU's NMI backtrace is not its trap, except the trap's own (the x86 executive summary of Linux 4.9 to 4.16, and the `RIP:` right after the `#UD` entry frame `asm_exc_invalid_op`); its call trace counts only if its first reliable entry is itself a BUG/WARN site; syzbot's `WARNING:` and `RIP:` lines repeated for inlined frames count once), and jumps there: the kernel prints the address of the trap itself, so this lands on the trap (the `ud2` / `brk`; for an x86_64 6.19+ WARN with a message, the site is part of a call to `__WARN_trap`, whose `ud1` traps: the `RIP:` line names `__WARN_trap` and kflow takes the `WARNING:` line's function+offset), where kflow's comment confirms the file and line. With only a `file:line` (one line can have several sites: on the demo kernel four functions share `mm/userfaultfd.c:755`) it shows the list with just those sites. If the log contradicts the site at that address (its `WARNING:` / `kernel BUG at` line names another `file:line` or kind, or has no `file:line` and its function+offset names another address than the `RIP:` / `pc :` line, or without a `WARNING:` / `kernel BUG at` line that names the site it prints another function size: a log from another build, or two reports pasted together), it warns and shows the sites at the log's `file:line` (else the site at that address) instead of jumping. The match and any notes (no site at that exact address, a module the log names) go to the Output window. Tested only with fake `ida_*` modules.
4. **kflow: List static-key sites** lists every static-key site with its key, `likely`/`unlikely`, whether the bytes there are a jump to the target now (`jump` / `no jump`), the target, the size of the out-of-line block at the target (`bytes / insns`, the block rule of `tools/reach.py` applied to IDA's instructions and references: from the target up to and including the first instruction that does not go on to the next one, or up to a join; at most 4096 instructions, then `+`; `?` where an instruction cannot be decoded; tested only with fake `ida_*` modules) and the function; the chooser's filter finds every site of one key.
5. **kflow: Remove annotations** removes kflow's comments and the references it added (Annotate records each one in the database, so Remove works after a rebase too). References that were there before, IDA's own (for example at a static-key site that is currently a jump) or yours, and your own comments are never touched.
6. Experimental, off by default, x86_64 only: **kflow: Let WARN sites fall through (experimental)** and **kflow: Remove WARN fall-through**; read [warnflow.md](warnflow.md) before you use them.

## Hex-Rays pseudocode comments

- With the Hex-Rays decompiler, each annotated site whose address has a pseudocode statement also gets a `// kflow: ...` comment at the end of that line (BUG or WARN with `file:line`; static key and when it jumps; fixup and type).
- A static-key site with no statement of its own (usually a NOP) gets it on the line of the next instruction that has one, if that is at most 16 bytes on in the same function with no other kflow site in between.
- A static-key comment adds "nothing else in the database jumps or falls through to 0x..., so this pseudocode probably does not show that code" (at a site that is a jump: "the site is a jump here and nothing else ... to the next instruction 0x... (run when the key is on/off) ...") only when IDA has an instruction on the path the site does not take in the database and no ordinary flow and no jump or call reference leads there other than kflow's own and a NOP site's own (a site that jumps to the very next instruction gets none; that Hex-Rays then hides the code is not checked in real IDA).
- Display text only, nothing saved; Annotate and Remove apply to functions decompiled afterwards (press F5 in a pseudocode window that is already open).
- Decompile check: Annotate (menu and `tools/kflow_headless.py`) picks up to 20 functions with a static-key site that gets a new jump reference (spread evenly over those functions, the same every run; the exception-table references Annotate also adds are not checked), decompiles them before it adds any reference and again afterwards, and adds one line to its summary, for example `decompile check: 20 functions with static-key sites decompile before and after Annotate`. If some stop decompiling, the line names them, each with Hex-Rays' own reason when it gives one, and says that **kflow: Remove annotations** takes kflow's references out. Functions that already failed before Annotate are counted apart. While IDA's auto-analysis is still running the check is skipped and the line says so; after analysis, Remove annotations and Annotate again to run it. It is also skipped, with that advice, when kflow's references from an earlier Annotate are still in the database (Annotate again without Remove). In `tools/kflow_headless.py` these lines, and the pointer to Remove, give its own steps instead of the menu actions (run with `--remove`, then again, without `--no-analysis` when that skipped the analysis). The check decompiles for about 5 s before Annotate and starts no new decompile once about 5 s more have passed after it (a slow function can stretch either part; functions over 16 KB are not picked); before the second part it waits, with no time limit, for IDA to analyse the new references (the wait box says so) and says how many it checked; if it fails itself, Annotate still runs and the line says `decompile check skipped: <reason>`.
- Not yet run in real IDA or the real decompiler; tested only against a fake `ida_hexrays` module.

## Headless (idalib)

Without the IDA window (idalib, IDA 9.1+): `python3 tools/kflow_headless.py <kernel> [--no-analysis] [--remove] [--json sites.json]` does steps 2 and 5 and saves the database. Not yet run with a real idalib (tested on fake `idapro` / `ida_*` modules).

`--json sites.json` also writes every decoded site with IDA's function names, for scripts (for example to match `file:line` across kernel versions when patch diffing). Addresses are hex strings. Without IDA, `python3 -m kflow <kernel> --json sites.json` writes the same records with the ELF's symbol names and file addresses (a module's are kflow's own section layout, [not necessarily IDA's](modules.md)), without the `now` field and with each BUG/WARN record's `flags`: 19,758 records on the MemLens demo kernel. Three records from the MemLens demo kernel (fake-IDA test output; function names there come from the ELF symbols):

```
{"addr": "0xFFFFFFFF8E629BC4", "kind": "WARN", "function": "mfill_atomic_copy", "file": "mm/userfaultfd.c", "line": 755}
{"addr": "0xFFFFFFFF8E391DE7", "key": "randomize_kstack_offset", "kind": "likely", "now": "no jump", "target": "0xFFFFFFFF8E391DFC", "function": "arch_exit_to_user_mode_prepare.isra.0"}
{"addr": "0xFFFFFFFF8E200029", "fixup": "0xFFFFFFFF8E20002B", "type": "WRMSR", "handler": null, "function": "sev_es_terminate"}
```

The file has the lists `bug`, `jump` and `ex` of such records, plus `input`, `bug_layout` (the field order of the kernel's own `__bug_table` entries, not of these records), `missing` (tables not found) and `errors` (tables found but not decoded, whose list is then empty).

## Try a real module (a few minutes, 129 KB download)

Download [`kflow-try-module.zip`](https://github.com/nightshift-labs-ai/kflow/releases/download/try-module/kflow-try-module.zip) (129 KB): Debian 13's x86_64 `dm-mod.ko`, with its sources in `README.txt`. From the kflow folder (the one with README.md):

```
python3 -m kflow dm-mod.ko
python3 -m kflow dm-mod.ko --oops "$(python3 -m kflow dm-mod.ko --oops-example)"
```

The first finds 74 BUG/WARN sites (37 WARN), 22 static-key sites and 2 exception-table fixups; the second builds a `WARNING:` line from the module's own `__bug_table` and maps it back to its site (`exact`, rc 0). Then open `dm-mod.ko` in IDA (a module is analysed in seconds) and run **Edit > Plugins > kflow: Annotate kernel sites**. What you should see (texts from kflow's fake-IDA test on this file; kflow has not yet run in real IDA):

1. The summary window starts with the line **kflow: Annotate finished**, then `22 of 22 static-key NOP sites can jump to code nothing else in this database reaches` (the fake IDA has no other references, so real IDA may show fewer where its own analysis already reaches a target).
2. Its **Static-key sites** button lists the 22 sites. Press F5 in `dm_submit_bio` (4 `zoned_enabled` sites and the `block_split` tracepoint): the sites' `// kflow:` comments name the key and end `so this pseudocode probably does not show that code`.
3. **kflow: Go to oops/WARN line** starts with `WARNING: CPU: 0 PID: 1 at drivers/md/dm-zone.c:35 dm_blk_do_report_zones.isra.0+0x91/0xc0 [dm_mod]`; OK jumps to that `ud2`, commented `WARN at drivers/md/dm-zone.c:35`.

## Or an arm64 module (one minute, 377 KB download)

Debian's installer ships kernel modules in small packages. The arm64 `ext4.ko` has all three tables (any Linux with `curl`, `ar`, `tar` and Python 3.8+; nothing is installed):

```
deb=ext4-modules-6.12.94+deb13-arm64-di_6.12.94-1_arm64.udeb
curl -sO https://deb.debian.org/debian/pool/main/l/linux-signed-arm64/$deb
sha256sum $deb   # f7957d08ff7b2d63775a2b97897e1934de2066b9d668cad101fa09147d35aaa0
ar x $deb && tar -xf data.tar.xz
PYTHONPATH=/path/to/kflow python3 -m kflow \
    lib/modules/6.12.94+deb13-arm64/kernel/fs/ext4/ext4.ko.xz --list jump --limit 3
```

(`/path/to/kflow` = the kflow folder, the one with README.md, e.g. the installed plugin under your IDA user directory's `plugins/kflow`). Output:

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
