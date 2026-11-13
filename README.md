# kflow

<img src="assets/logo.png" width="96" align="right" alt="kflow logo">

For kernel reverse engineers (Linux and Android vulnerability research, patch diffing, crash triage): kflow turns the bare traps, NOPs and faulting instructions of a kernel into source lines, static keys and fixups. A `WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0` line pasted from a kernel log leads to the trap it names, and a NOP says which key patches it and where it then jumps.

Before: what the disassembly shows at three addresses of the [MemLens demo kernel](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (`objdump -d`). After: the comment kflow writes at each one (text from kflow's fake-IDA test, not an IDA screenshot):

```
ffffffff8e629bc4  ud2            ; kflow: WARN at mm/userfaultfd.c:755 (the kernel reports and continues after this trap)
ffffffff8e391de7  xchg %ax,%ax   ; kflow: static key randomize_kstack_offset (static_branch_likely): runtime-patched NOP/branch; jumps to 0xFFFFFFFF8E391DFC when the key is off
ffffffff8e200029  wrmsr          ; kflow: may fault -> fixup at 0xFFFFFFFF8E20002B (WRMSR)
```

## Status

**kflow has not yet been run inside real IDA.** It was built without access to an IDA installation. The table decoders are checked on seven real kernels and five kernel modules; the IDA layer has only been exercised with fake `ida_*` modules ([details](docs/VERIFICATION.md#status-read-this-first)). Bug reports are very welcome.

kflow was built by an AI agent (Claude, operated by Nightshift Labs).

## Features

One line per feature; each one in full: [docs/FEATURES.md](docs/FEATURES.md).

- [**BUG/WARN comments**](docs/FEATURES.md#bugwarn-traps): every trap of the kernel's `__bug_table` gets its source `file:line` (where the kernel recorded one) and whether the kernel continues after it (WARN) or not (BUG).
- [**BUG/WARN list**](docs/FEATURES.md#bugwarn-traps): **kflow: List BUG/WARN sites** lists every trap with its function and `file:line`; Enter jumps to it.
- [**Go to oops/WARN line**](docs/FEATURES.md#bugwarn-traps): paste a `WARNING:`, `kernel BUG at`, `RIP:` or `pc :` line, or a whole report, and kflow goes to the trap it names; `python3 -m kflow <kernel> --oops <log>` does the same outside IDA.
- [**Static-key comments and key references**](docs/FEATURES.md#static-keys-and-exception-table-fixups): each runtime-patched NOP or branch gets its key, its branch target and when it jumps, a reference to the target where IDA has none, and a data reference to its key (X on a key lists its sites).
- [**Static-key chooser**](docs/FEATURES.md#static-keys-and-exception-table-fixups): **kflow: List static-key sites** shows every site with its key, `jump` / `no jump` now, the target, the size of the out-of-line block there (`bytes / insns`) and the function; the filter finds every site of one key.
- [**Exception-table fixups**](docs/FEATURES.md#static-keys-and-exception-table-fixups): each instruction that may fault on purpose gets its fixup and type (or handler), and a reference to the fixup.
- [**What the references add, measured**](tools/reach_results.md): on the MemLens demo kernel, 96% of the 8,349 static-key NOP sites jump to code that no direct branch targets and no instruction falls into; the same holds after 90% of the 7,504 WARN traps.
- [**Hex-Rays pseudocode comments**](docs/USAGE.md#hex-rays-pseudocode-comments): a `// kflow: ...` comment at the end of the site's pseudocode line (display text only).
- [**Decompile check**](docs/USAGE.md#hex-rays-pseudocode-comments): with the decompiler, Annotate decompiles up to 20 functions that get a new static-key jump reference, before and after, and names any that stopped decompiling.
- [**Kernel modules**](docs/modules.md) (`.ko`, `.ko.xz`, `.ko.gz`): the command line applies the module's relocations; IDA relocates a `.ko` itself.
- [**Clean removal**](docs/USAGE.md#step-by-step): **kflow: Remove annotations** takes out only the comments and references kflow added (also after a rebase).
- [**WARN fall-through**](docs/warnflow.md) (experimental, off by default, x86_64 only): ordinary flow after exactly the WARN `ud2` traps the kernel's `__bug_table` lists, so that IDA can reach the code after them.
- [**Headless runner**](docs/USAGE.md#headless-idalib): `python3 tools/kflow_headless.py <kernel>` annotates and saves the database without the IDA window (idalib, IDA 9.0+); `--json` exports every site.
- [**Command-line decoder, no IDA needed**](docs/OUTPUT.md): `python3 -m kflow <kernel ELF>` needs only Python 3.8+ and no packages.
- [**One-command tests**](docs/VERIFICATION.md#what-was-verified): `sh tests/run_all.sh` runs every test in about two seconds on a pinned Debian arm64 `ext4.ko` (sha256 checked) or on your own files.

## Install

```
hcli plugin install kflow
```

The plugin index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/kflow/releases). If `hcli plugin status` shows an older version than the newest release:

- install a release zip directly, for example `hcli plugin install https://github.com/nightshift-labs-ai/kflow/archive/refs/tags/v0.0.4.zip`,
- or copy this folder into the `plugins` folder of your IDA user directory: `$IDAUSR/plugins` if `IDAUSR` is set, otherwise `~/.idapro/plugins` (Linux, macOS) or `%APPDATA%\Hex-Rays\IDA Pro\plugins` (Windows).

The command-line decoder needs only Python 3.8+ and no packages: `python3 -m kflow <kernel ELF>` from the plugin's folder (after `hcli plugin install`, for example `cd ~/.idapro/plugins/kflow && python3 -m kflow kernel.elf`).

## Try it

You need a 64-bit kernel ELF that still has the kernel's symbol names, for example:

- a distribution's debug `vmlinux` (Debian/Ubuntu: `/usr/lib/debug/boot/vmlinux-<version>` from the `linux-image-<version>-dbg` / `-dbgsym` package);
- the `kernel.elf` of the [MemLens demo data](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (22 MB zip; a Debian 13 6.12 kernel exported from a memory image, so freed init code reads as other bytes);
- the `vmlinuz` your Linux machine boots, or an Android GKI `Image`, turned into an ELF with kallsyms names by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) (checked on Ubuntu 24.04's x86_64 and arm64 `vmlinuz` and Debian 11's; `/boot/vmlinuz-*` is often readable only by root: copy it first, e.g. `sudo cp /boot/vmlinuz-$(uname -r) . && sudo chown $USER vmlinuz-*`, then `vmlinux-to-elf vmlinuz-<version> kernel.elf`).
- a kernel module (`.ko`, or `.ko.xz` / `.ko.gz` as distributions ship them; unpack `.ko.zst` with `zstd -d` first): it may have its own `__bug_table`, `__jump_table` and `__ex_table` as relocatable sections. The command line applies the relocations; IDA relocates a `.ko` itself. Layout, imported keys and what is verified: [docs/modules.md](docs/modules.md); a one-minute example: [Try a real module](docs/USAGE.md#try-a-real-module-one-minute-377-kb-download).

A stripped `vmlinux` (from `extract-vmlinux`) still has `__bug_table` and `__ex_table` as sections, and kflow uses them; the static-key table has no section of its own and needs the `__start___jump_table` symbol.

### Steps in short

1. Outside IDA, see what is there: `python3 -m kflow kernel.elf` ([output](docs/OUTPUT.md#what-you-get-real-output-not-ida-screenshots)).
2. In IDA, open the kernel and, after IDA's auto-analysis has finished, run **Edit > Plugins > kflow: Annotate kernel sites**.
3. **kflow: List BUG/WARN sites** and **kflow: List static-key sites** list the sites; **kflow: Go to oops/WARN line** takes a log line such as `WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0`, or the whole report.
4. **kflow: Remove annotations** removes kflow's comments and the references it added; IDA's and yours stay.

Every step in full, the Hex-Rays pseudocode comments, the headless runner and a one-minute module example: [docs/USAGE.md](docs/USAGE.md).

## Limits

- 64-bit little-endian kernels with relative table entries only (x86_64; arm64 with `CONFIG_GENERIC_BUG_RELATIVE_POINTERS`); not 32-bit kernels. Up to 4.19 the static-key table is not decoded.
- Exception-type names come from x86_64 Linux 6.12 and arm64 Linux 6.1/6.12; on other versions treat them as a hint (on arm64 5.16-5.19 they are wrong).
- Go to oops/WARN line: the log must come from the same build as the file you open.
- WARN fall-through (experimental): not yet run in real IDA; the part most likely to need a fix.
- Alternatives (`.altinstructions`) are not handled.

Every limit, one line each and then in full: [docs/limits.md](docs/limits.md).

## More documentation

- [docs/FEATURES.md](docs/FEATURES.md): every feature in full, and the three kernel tables kflow reads.
- [docs/USAGE.md](docs/USAGE.md): each action step by step, Hex-Rays pseudocode comments, the headless runner and `--json`, a one-minute kernel-module example.
- [docs/OUTPUT.md](docs/OUTPUT.md): real command-line output on the MemLens demo kernel and the comments kflow writes.
- [docs/VERIFICATION.md](docs/VERIFICATION.md): the tests and the seven kernels and five modules they were run on.
- [docs/limits.md](docs/limits.md): the limits, one line each, then in full.
- [docs/modules.md](docs/modules.md) (kernel modules), [docs/warnflow.md](docs/warnflow.md) (the experimental WARN fall-through), [CHANGELOG.md](CHANGELOG.md).

## Credits

Written by an AI agent (Claude, operated by Nightshift Labs). Table layouts from the Linux kernel sources (`include/asm-generic/bug.h`, `include/linux/jump_label.h`, `arch/x86/include/asm/extable_fixup_types.h`). If you list authors elsewhere, please use "Nightshift Labs (AI agent)".

Prior art for letting IDA continue after `ud2`: [linux_und.py](https://git.zx2c4.com/ida-plugins/tree/linux_und.py) by Jason A. Donenfeld (2017).

MIT licence.
