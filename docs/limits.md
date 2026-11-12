# Limits

The full text of the README's [Limits](../README.md#limits) section; WARN fall-through and kernel modules have their own pages ([warnflow.md](warnflow.md), [modules.md](modules.md)).

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

- The log must come from the same build as the file you open: function+offset is this file's only if the build is the same. From another build kflow notices it when the log's own `WARNING:` / `kernel BUG at` line names another `file:line` or kind than the site at that address, or, without such a line, when the log prints another function size than this file's (the size kallsyms prints, to the next symbol, or the code size): it reports a mismatch and lists the sites at the log's `file:line` instead of going there. A log with neither (a bare `RIP:` line without a size) can still land on an unrelated site.
- A function+offset this file does not have (another build, or a module the file is not) is never replaced by a jump to the one site at the log's `file:line`; that site is only listed.
- Clang LTO kernels: kallsyms prints `foo.123`, `foo.llvm.N` and `foo.cfi` as `foo`, so `foo+0x10` tries all of them and the plain `foo`; when several have a site at that offset and neither the size nor the `WARNING:` / `kernel BUG at` line decides, they are listed. GCC's `foo.part.N`, `.isra.N`, `.constprop.N` and `.cold` are printed in full and are only found by that full name.
- Same-named static functions: the command line lists them all; in IDA only the function IDA shows under that name is tried (IDA names one function so), and for a static function a note says so unless the log's `WARNING:` / `kernel BUG at` line confirms the site. IDA's names for duplicates and for names with a dot are not verified (not yet run in real IDA).
- A paste with several reports: the first one with a `WARNING:`, `kernel BUG at`, `RIP:` or `pc :` line is used. Reports without one (KASAN, lockdep, hung task) and pasted call traces find a site only if their first reliable entry is one; `?` entries are never used.
- Linux 6.19+ x86_64 WARN with a message traps in `__WARN_trap`: the `RIP:` line names that, and the `WARNING:` line's function+offset gives the site (checked on hand-made logs only).

## WARN fall-through

Experimental, off by default, x86_64 only, not yet run in real IDA: see [warnflow.md](warnflow.md).

## Freed init code

Static-key sites in freed init code (memory images) are decoded but not commented when they are outside code segments.

## Kernel modules

See [modules.md](modules.md#what-was-checked).

## Alternatives

Alternatives (`.altinstructions`) are not handled; see [ida-linux-alternatives](https://github.com/opensrcsec/ida-linux-alternatives).
