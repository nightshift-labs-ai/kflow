# kflow features in full

The one-line list is in the [README](../README.md#features). How to run each action: [USAGE.md](USAGE.md); output: [OUTPUT.md](OUTPUT.md); what was checked: [VERIFICATION.md](VERIFICATION.md); limits: [limits.md](limits.md).

**Status:** the table decoders are checked on seven real kernels and five kernel modules; the IDA layer has not yet been run inside real IDA (only with fake `ida_*` modules). [Details](VERIFICATION.md#status-read-this-first)

## What kflow reads

Linux kernels carry their own maps of code that a disassembler cannot see from the instructions alone:

- **`__bug_table`**: every `BUG()` / `WARN()` trap (`ud2` on x86_64, `brk #0x800` on arm64; from Linux 6.19 an x86_64 WARN with a message is a call instead, and kflow says so), with the **source file and line** and a flag that says whether the kernel **continues after the trap** (WARN) or not (BUG).
- **`__jump_table`**: every static-key site (`static_branch_likely/unlikely`, tracepoints): a NOP or branch that the kernel patches at runtime, its **key** and its **branch target**.
- **`__ex_table`**: every instruction that may fault on purpose (user-memory access, MSR reads...) and its **fixup** landing pad.

kflow reads these tables from the database and, in IDA, comments every site and adds the jump references IDA cannot find on its own (a NOP has no branch, a fault has no visible path to its fixup). It also lists every BUG/WARN site with its function and `file:line`.

## BUG/WARN traps

- [**BUG/WARN comments**](USAGE.md#step-by-step): every BUG/WARN site of the kernel's `__bug_table` gets its source `file:line` (where the kernel recorded one) and whether the kernel continues after the trap (WARN) or not (BUG).
- [**BUG/WARN list**](USAGE.md#step-by-step): **kflow: List BUG/WARN sites** lists every trap with its function and `file:line`; Enter jumps to it.
- [**Go to oops/WARN line**](USAGE.md#step-by-step): **kflow: Go to oops/WARN line** takes pasted log text (a `WARNING:`, `kernel BUG at`, `RIP:` or `pc :` line, a whole oops or syzbot report, `func+0xoff` or `file:line`) and jumps to the trap it names (a `BUG: KASAN:`, lockdep or hung-task report names no BUG/WARN trap, so it gives no match unless its first reliable stack entry is one); when only `file:line` is known and several traps share it, it lists just those. `python3 -m kflow <kernel> --oops <log>` does the same outside IDA (the IDA action is tested only with fake `ida_*` modules). Real command-line output on the MemLens demo kernel; the log line is in the kernel's `__warn()` format, written for this site, not taken from a real crash:

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

## Static keys and exception-table fixups

- [**Static-key comments and key references**](USAGE.md#step-by-step): each static-key site (a NOP or branch the kernel patches at runtime) gets its key, its branch target and when it jumps, and a jump reference to the target where IDA has none (a data reference if the target is inside another function); a data reference from each site to its key makes X on a key list its sites.
- [**Static-key chooser**](USAGE.md#step-by-step): **kflow: List static-key sites** shows every site with its key, `likely`/`unlikely`, `jump` / `no jump` now, the target and the function; the filter finds every site of one key.
- [**Exception-table fixups**](#what-kflow-reads): each instruction that may fault on purpose (user-memory access, MSR reads...) gets its fixup and type (or handler), and a jump reference to the fixup (a data reference if it is inside another function).
- [**What the references add, measured**](../tools/reach_results.md): on the MemLens demo kernel, 96% of the 8,349 static-key NOP sites jump to code that no direct branch targets and no instruction falls into (8,011 out-of-line blocks, 264 KB): kflow's reference is the only one that leads there. The same holds after 90% of the 7,504 WARN traps (1.7 instructions on average up to the next jump or join). Reproduce: `python3 tools/reach.py <kernel>` (x86_64, needs objdump).

## Hex-Rays decompiler

- [**Hex-Rays pseudocode comments**](USAGE.md#hex-rays-pseudocode-comments): with the decompiler, a `// kflow: ...` comment at the end of the site's pseudocode line where it has one (display text only, nothing saved; tested only against a fake `ida_hexrays` module).
- [**Decompile check**](USAGE.md#hex-rays-pseudocode-comments): with the Hex-Rays decompiler, Annotate decompiles up to 20 functions that get a new static-key jump reference before and after it adds anything, and says in one line whether any of them stopped decompiling (and names them). Tested only with fake `ida_*` modules; not yet run in IDA.

## Kernel modules, clean removal, WARN fall-through

- [**Kernel modules**](modules.md) (`.ko`, `.ko.xz`, `.ko.gz`): the command line applies the module's relocations; in IDA, a key inside an imported symbol (`nf_hooks_needed+0x270` in `bridge.ko`) is named from kflow's own decode of the `.ko` when the file is still where IDA loaded it from and both decodes line up (IDA's extern-segment layout is not verified; tested only with fake `ida_*` modules).
- [**Clean removal**](USAGE.md#step-by-step): **kflow: Remove annotations** takes out only the comments and references kflow added (also after a rebase); IDA's and yours stay.
- [**WARN fall-through**](warnflow.md) (experimental, off by default, x86_64 only, not yet run in real IDA): **kflow: Let WARN sites fall through (experimental)** adds ordinary flow after exactly the WARN `ud2` traps the kernel's `__bug_table` lists, so that IDA can reach the code after them; **kflow: Remove WARN fall-through** undoes it.

## Without the IDA window

- [**Headless runner**](USAGE.md#headless-idalib): `python3 tools/kflow_headless.py <kernel>` annotates (or with `--remove` removes) and saves the database without the IDA window (idalib, IDA 9.0+); `--json` exports every site with IDA's function names.
- [**Command-line decoder, no IDA needed**](OUTPUT.md#what-you-get-real-output-not-ida-screenshots): `python3 -m kflow <kernel ELF>` needs only Python 3.8+ and no packages; `--list warn`, `bug`, `jump` or `ex` lists the sites; `--oops <log>` finds the site a kernel log names.
- [**One-command tests**](VERIFICATION.md#what-was-verified): `sh tests/run_all.sh` runs every test in about two seconds on a pinned Debian arm64 `ext4.ko` (sha256 checked) or on your own files.
