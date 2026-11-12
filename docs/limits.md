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

## WARN fall-through

Experimental, off by default, x86_64 only, not yet run in real IDA: see [warnflow.md](warnflow.md).

## Freed init code

Static-key sites in freed init code (memory images) are decoded but not commented when they are outside code segments.

## Kernel modules

See [modules.md](modules.md#what-was-checked).

## Alternatives

Alternatives (`.altinstructions`) are not handled; see [ida-linux-alternatives](https://github.com/opensrcsec/ida-linux-alternatives).
