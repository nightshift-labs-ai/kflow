# Limits

The full text of the [one-line list](#in-short) below; WARN fall-through and kernel modules have their own pages ([warnflow.md](warnflow.md), [modules.md](modules.md)).

## In short

One line per limit; the full text is in the sections below.

- 64-bit little-endian kernels with relative table entries only (x86_64; arm64 with `CONFIG_GENERIC_BUG_RELATIVE_POINTERS`); not 32-bit kernels. Up to 4.19 the static-key table is not decoded. [More](#supported-kernels)
- Exception-type names come from x86_64 Linux 6.12 and arm64 Linux 6.1/6.12; on other versions treat them as a hint (on arm64 5.16-5.19 they are wrong). [More](#exception-type-names)
- Linux 6.19+: checked only on a stripped Ubuntu mainline 7.0.0 x86_64 `vmlinux`. [More](#linux-619-and-later)
- WARN fall-through (experimental, off by default, x86_64 only): not yet run in real IDA, tested only on fake `ida_*` modules; the part most likely to need a fix. [More](warnflow.md)
- Sites in freed init code (memory images) are decoded but not commented when they are outside code segments (MemLens demo kernel, fake-IDA test: 521 of 9,850 BUG/WARN, 225 of 9,237 static-key and 13 of 671 exception-table sites).
- Kernel modules: checked on one x86_64 and four arm64 modules; absolute relocation types untested on real files; in IDA, kflow relies on IDA's own relocation of the `.ko` (not tried in IDA). [More](modules.md#what-was-checked)
- Go to oops/WARN line: the log must come from the same build as the file you open; from another build the offsets differ, and when the log's own `WARNING:` / `kernel BUG at` line (or, without one, its function size) contradicts the site at that address kflow reports a mismatch and does not jump, but a log with neither can still land on an unrelated site inside that function (an offset past the function's end in this file goes nowhere); `foo+0x10` also tries the functions named `foo` plus a Clang LTO suffix (`foo.123`, `foo.llvm.N`, `foo.cfi`: the kernel prints them as `foo`), never GCC's `foo.isra.0` / `foo.part.0`; in IDA only the function IDA shows under the log's name is tried (IDA names one function so; the command line lists all same-named static functions), and a note says so for a static function unless the log's `WARNING:` / `kernel BUG at` line confirms the site; IDA's names for symbols with a dot and for same-named static functions are not verified (not yet run in real IDA). [More](#go-to-oopswarn-line)
- Alternatives (`.altinstructions`) are not handled; see [ida-linux-alternatives](https://github.com/opensrcsec/ida-linux-alternatives).

## Supported kernels

- 64-bit little-endian kernels with relative table entries (x86_64; arm64 with `CONFIG_GENERIC_BUG_RELATIVE_POINTERS`).
- Not 32-bit kernels.
- Kernels up to 4.19 have an absolute 24-byte static-key table: kflow reports it as not decoded and still decodes the other two tables (checked on synthetic tables only).

## Exception-type names

- Exception-type names: x86_64 from Linux 6.12, arm64 from Linux 6.1/6.12 (`asm-extable.h`, same numbers in both; Linux 6.0 renumbered them, so on arm64 5.16-5.19 the names are wrong: there 3 is UACCESS_ERR_ZERO and 4 LOAD_UNALIGNED_ZEROPAD).
- Other versions number some x86_64 types differently, so treat the name as a hint; arm64 kernels before 5.16 have no type field.
- On x86_64 before 5.16 the third field points to a handler function: kflow detects that layout and names the handler instead (checked on a synthetic table and on Debian 11's 5.10 kernel).

## Linux 6.19 and later

- Linux 6.19+: checked only on a stripped Ubuntu mainline 7.0.0 x86_64 `vmlinux` (`__bug_table` and `__ex_table` by section name): 14,039 BUG/WARN sites with the 16-byte layout; of the 11,443 WARN sites, 9,632 are `ud2` and the other 1,811 are the flagged WARN-with-message calls; 754 exception-table entries.
- x86_64 6.19+ kernels built without `CONFIG_DEBUG_BUGVERBOSE` (distributions and Android GKI enable it) have entries with a message but no file and line: kflow decodes that layout (synthetic test only) and lists those sites without `file:line`.

## Go to oops/WARN line

- The log must come from the same build as the file you open: function+offset is this file's only if the build is the same. From another build kflow notices it when the log's own `WARNING:` / `kernel BUG at` line names another `file:line` or kind than the site at that address, or, without such a line, when the log prints another function size than this file's (the size kallsyms prints, to the next symbol, or the code size): it reports a mismatch and lists the sites at the log's `file:line` (else the site at that address) instead of going there. A log with neither (a bare `RIP:` line without a size) can still land on an unrelated site inside the function it names; an offset past that function's end in this file is reported as such and goes nowhere, also when the next function has a site there (in IDA a function ends at the end of its last chunk before the next name).
- A function+offset this file does not have (another build, or a module the file is not) is never replaced by a jump to the one site at the log's `file:line`; that site is only listed.
- Clang LTO kernels: kallsyms prints `foo.123`, `foo.llvm.N` and `foo.cfi` as `foo`, so `foo+0x10` tries all of them and the plain `foo`; when several have a site at that offset and neither the size nor the `WARNING:` / `kernel BUG at` line decides, they are listed. GCC's `foo.part.N`, `.isra.N`, `.constprop.N` and `.cold` are printed in full and are only found by that full name.
- Same-named static functions: the command line lists them all; in IDA only the function IDA shows under that name is tried (IDA names one function so), and for a static function a note says so unless the log's `WARNING:` / `kernel BUG at` line confirms the site. IDA's names for duplicates and for names with a dot are not verified (not yet run in real IDA).
- A paste with several reports: the first one with a `WARNING:` / `kernel BUG at` line or a trap `RIP:` / `pc :` line is used (x86's executive summary after `end trace`, the trap's `RIP:` again, belongs to the report before it). Reports without one (KASAN, lockdep, hung task) and pasted call traces find a site only if their first reliable entry is one; `?` entries are never used. A `RIP:` / `pc :` line after the report's call trace began (x86 prints an interrupted context's registers where the trace crosses an IRQ or exception entry) or after `NMI backtrace for cpu N` (another CPU's registers) is not counted as one, nor is a call-trace entry that repeats it (arm64 repeats the pc there). The trap's own lines after the trace do count: the executive summary of Linux 4.9 (`RIP  [<%p>] %pS`) and 4.10 to 4.16 (`RIP: %pS RSP: %016lx`), and the `RIP:` right after a reliable `#UD` entry frame (`asm_exc_invalid_op`, before 5.8 `invalid_op`) outside an NMI backtrace, as in panic()'s dump under `panic_on_warn`. Otherwise the rule is by position: a trap `RIP:` line pasted after a call trace (lines out of order) is not used, and a `RIP:` line before the trace that is not a trap (a soft lockup's interrupted code) is still taken as one.
- Linux 6.19+ x86_64 WARN with a message traps in `__WARN_trap`: the `RIP:` line names that, and the `WARNING:` line's function+offset gives the site (checked on hand-made logs only).

## WARN fall-through

Experimental, off by default, x86_64 only, not yet run in real IDA: see [warnflow.md](warnflow.md).

## Freed init code

Sites in freed init code (memory images) are decoded but not commented when they are outside code segments (MemLens demo kernel, fake-IDA test: 521 of 9,850 BUG/WARN, 225 of 9,237 static-key and 13 of 671 exception-table sites).

## Kernel modules

See [modules.md](modules.md#what-was-checked).

## Alternatives

Alternatives (`.altinstructions`) are not handled; see [ida-linux-alternatives](https://github.com/opensrcsec/ida-linux-alternatives).
