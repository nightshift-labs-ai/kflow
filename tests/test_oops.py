"""kflow/oops.py: kernel log text -> the BUG/WARN site it names. Pure Python, no IDA.

    python3 tests/test_oops.py                # log samples built from the kernel's printk formats, synthetic sites
    python3 tests/test_oops.py <kernel ELF>   # also: a RIP / pc line made for every BUG/WARN site in a function
                                              # resolves to that site, file:line gives every site at that line, and
                                              # python3 -m kflow <ELF> --oops <log> [--json] prints / writes the match

The samples follow the format strings of kernel/panic.c (__warn, up to 6.18 and from 6.19), lib/bug.c (report_bug),
arch/x86/kernel/dumpstack.c (show_ip, call-trace entries; 4.9 forms), arch/x86/mm/fault.c 4.9 ('IP:'),
arch/arm64/kernel/process.c (__show_regs; 4.9 'PC is at'), arch/arm64/kernel/stacktrace.c, lib/vsprintf.c and
kernel/kallsyms.c (%pS / %pB with ' [module]' and a build id), kernel/printk/printk.c (prefixes), and syzbot's
symbolized reports (file:line after a symbol, '[inline]' frames).
"""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from kflow import oops  # noqa: E402
from kflow.core import BugSite  # noqa: E402

# the four WARN sites at mm/userfaultfd.c:755 on the MemLens demo kernel (python3 -m kflow kernel.elf --list warn),
# with their functions' start and size from its symbol table, plus a few made-up ones
UFFD = [(0xFFFFFFFF8E629BC4, "mfill_atomic_copy", 0xFFFFFFFF8E629550, 0x9D0),
        (0xFFFFFFFF8E62A489, "mfill_atomic_zeropage", 0xFFFFFFFF8E629F30, 0x590),
        (0xFFFFFFFF8E62AB60, "mfill_atomic_continue", 0xFFFFFFFF8E62A4D0, 0x7F0),
        (0xFFFFFFFF8E62B164, "mfill_atomic_poison", 0xFFFFFFFF8E62ACD0, 0x850)]
FUNCS = {name: [(start, size)] for _, name, start, size in UFFD}
SITES = [BugSite(a, "mm/userfaultfd.c", 755, 0x901) for a, _, _, _ in UFFD]
SITES += [BugSite(0xFFFFFFFF8E629BA9, "mm/userfaultfd.c", 861, 0),  # a BUG in mfill_atomic_copy, before the WARN
          BugSite(0xFFFFFFFF81000110, "mm/filemap.c", 1499, 0),  # folio_unlock: a BUG with a unique file:line
          BugSite(0xFFFFFFFF81000210, "lib/dup.c", 10, 1),  # two static functions named dup_fn: sites at +0x10 in both
          BugSite(0xFFFFFFFF81000310, "lib/dup.c", 20, 1),
          BugSite(0xFFFFFFFF81000444, "kernel/cfi.c", 7, 1),  # in lto_fn.cfi (the log prints lto_fn)
          BugSite(0x10A00, "net/netfilter/nf_tables_core.c", 260, 1)]  # a module's site
FUNCS.update({"folio_unlock": [(0xFFFFFFFF810000A0, 0xD0)],
              "dup_fn": [(0xFFFFFFFF81000200, 0x40), (0xFFFFFFFF81000300, 0x60)],
              "lto_fn": [(0xFFFFFFFF81000600, 0x8)],  # the 8-byte CFI jump-table entry has the plain name
              "no_sites_fn": [(0xFFFFFFFF81000800, 0x100)],
              "nft_do_chain": [(0x10600, 0x6D0)]})
SUFFIXED = {"lto_fn": [(0xFFFFFFFF81000400, 0x100)]}  # lto_fn.cfi


def symbols(name, suffixed=False):
    return (SUFFIXED if suffixed else FUNCS).get(name, [])


def find(text, **kw):
    rep = oops.parse(text)
    return rep, oops.resolve(rep, SITES, symbols, **kw)


# ---- samples, each built from the kernel's format strings ----
# __warn() up to 6.18: 'WARNING: CPU: %d PID: %d at %s:%d %pS'; dmesg timestamps '[%5lu.%06lu]'; a full x86 report
X86_WARN = """\
[  152.334198] ------------[ cut here ]------------
[  152.334201] WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0
[  152.334230] Modules linked in: nf_tables(E) libcrc32c
[  152.334260] CPU: 1 UID: 0 PID: 9 Comm: uffd-test Not tainted 6.12.115+deb13-amd64 #1  Debian 6.12.115-1
[  152.334265] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
[  152.334270] RIP: 0010:mfill_atomic_copy+0x674/0x9d0
[  152.334275] Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff 0f 0b <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
[  152.334280] RSP: 0018:ffffc90000d4bd18 EFLAGS: 00010246
[  152.334290] RAX: 0000000000000000 RBX: ffff888103a2c000 RCX: 0000000000000000
[  152.334300] Call Trace:
[  152.334301]  <TASK>
[  152.334305]  ? __warn+0x89/0x130
[  152.334310]  ? mfill_atomic_copy+0x674/0x9d0
[  152.334315]  ? report_bug+0x164/0x190
[  152.334320]  ? handle_bug+0x58/0x90
[  152.334325]  ? exc_invalid_op+0x17/0x70
[  152.334330]  ? asm_exc_invalid_op+0x1a/0x20
[  152.334340]  userfaultfd_ioctl+0x5d1/0x1e70
[  152.334345]  __x64_sys_ioctl+0x94/0xd0
[  152.334350]  do_syscall_64+0x82/0x190
[  152.334355]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
[  152.334360] RIP: 0033:0x7f1c2b0e9c5b
[  152.334365] RSP: 002b:00007ffd4e1d6c18 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
[  152.334370]  </TASK>
[  152.334375] ---[ end trace 0000000000000000 ]---
"""

# __warn() from 6.19: 'WARNING: %s:%d at %pS, CPU#%d: %s/%d' and the no-file variant 'WARNING: at %pS, CPU#%d: %s/%d'
NEW_WARN = "WARNING: mm/userfaultfd.c:755 at mfill_atomic_copy+0x674/0x9d0, CPU#1: uffd-test/9"
NEW_WARN_NO_FILE = "WARNING: at mfill_atomic_copy+0x674/0x9d0, CPU#1: uffd-test/9"
OLD_WARN_NO_FILE = "WARNING: CPU: 1 PID: 9 at mfill_atomic_copy+0x674/0x9d0"

# report_bug(): 'kernel BUG at %s:%u!', then die() -> 'Oops: invalid opcode: %04lx [#%d]...' and show_ip()
X86_BUG = """\
<4>[  222.868961][ T8817] ------------[ cut here ]------------
<2>[  222.868990][ T8817] kernel BUG at mm/filemap.c:1499!
<4>[  222.942000][ T8817] Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN NOPTI
<4>[  222.942106][ T8817] RIP: 0010:folio_unlock+0x70/0xd0
"""
# report_bug() without file:line: 'kernel BUG at %pB [verbose debug info unavailable]' ('Kernel BUG' in 5.10)
BUG_NO_FILE = "kernel BUG at folio_unlock+0x70/0xd0 [verbose debug info unavailable]"
BUG_NO_FILE_510 = "Kernel BUG at folio_unlock+0x70/0xd0 [verbose debug info unavailable]"

# arm64: arch/arm64/kernel/traps.c die('Oops - BUG') -> 'Internal error: %s: %016lx [#%d] SMP', __show_regs() 'pc : %pS'
# and 'lr : %pS' (module code: ' [mod]'), dump_backtrace() 'Call trace:' and ' %pSb' entries with ' (P)' / ' (C)'
ARM64_BUG = """\
<2>[  401.112233][ T4021] kernel BUG at net/netfilter/nf_tables_core.c:260!
<0>[  401.112240][ T4021] Internal error: Oops - BUG: 00000000f2000800 [#1] PREEMPT SMP
<4>[  401.112250][ T4021] Modules linked in: nf_tables nfnetlink
<4>[  401.112260][ T4021] CPU: 3 UID: 0 PID: 4021 Comm: nft Not tainted 6.12.94+deb13-arm64 #1  Debian 6.12.94-1
<4>[  401.112270][ T4021] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
<4>[  401.112290][ T4021] pc : nft_do_chain+0x400/0x6d0 [nf_tables]
<4>[  401.112295][ T4021] lr : nft_do_chain+0x2a0/0x6d0 [nf_tables]
<4>[  401.112300][ T4021] sp : ffff80008a3b3c40
<4>[  401.112310][ T4021] x29: ffff80008a3b3c40 x28: 0000000000000000 x27: ffff0000c1f2a000
<4>[  401.112400][ T4021] Call trace:
<4>[  401.112405][ T4021]  nft_do_chain+0x400/0x6d0 [nf_tables 8f2d0c1e5a6b7c8d9e0f1a2b3c4d5e6f70819283] (P)
<4>[  401.112410][ T4021]  nft_do_chain_ipv4+0x6c/0xb8 [nf_tables 8f2d0c1e5a6b7c8d9e0f1a2b3c4d5e6f70819283]
<4>[  401.112415][ T4021]  nf_hook_slow+0x48/0x100
<4>[  401.112420][ T4021]  ip_local_deliver+0xc4/0x110 (C)
"""

# a syzbot report: the source line after each symbol, inlined frames, a user-mode RIP, interleaved lines of other tasks
SYZBOT = """\
------------[ cut here ]------------
WARNING: CPU: 1 PID: 5850 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:755
Modules linked in:
CPU: 1 UID: 0 PID: 5850 Comm: syz-executor123 Not tainted 6.12.0-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
RIP: 0010:mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:755
Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff e8 40 59 25 00 <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
RSP: 0018:ffffc90003a77a80 EFLAGS: 00010293
RAX: ffffffff81f3a1b4 RBX: 0000000000000000 RCX: ffff888028138000
Call Trace:
 <TASK>
 userfaultfd_copy fs/userfaultfd.c:1700 [inline]
 userfaultfd_ioctl+0x5d1/0x1e70 fs/userfaultfd.c:2026
 vfs_ioctl fs/ioctl.c:51 [inline]
 __do_sys_ioctl fs/ioctl.c:907 [inline]
 __se_sys_ioctl fs/ioctl.c:893 [inline]
 __x64_sys_ioctl+0x19d/0x210 fs/ioctl.c:893
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4d1c2e4ab9
Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 c1 17 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b
RSP: 002b:00007ffd4e1d6c18 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
 </TASK>
"""

# Linux 4.9: show_regs 'RIP: %04lx:[<%016lx>] ' + printk_address ' [<%p>] %pS'; entries ' [<%p>] %s%pB'; the
# executive summary 'RIP  [<%p>] %pS'; arch/x86/mm/fault.c 'IP:' + printk_address; arm64 'PC is at %s'
OLD_X86 = """\
[   12.000001] RIP: 0010:[<ffffffff8e629bc4>]  [<ffffffff8e629bc4>] mfill_atomic_copy+0x674/0x9d0
[   12.000002] Call Trace:
[   12.000003]  [<ffffffff8e2a1234>] ? __warn+0xcb/0xf0
[   12.000004]  [<ffffffff8e62c001>] userfaultfd_ioctl+0x5d1/0x1e70
"""
OLD_SUMMARY = "RIP  [<ffffffff8e629bc4>] mfill_atomic_copy+0x674/0x9d0"
OLD_IP = "IP: [<ffffffff810000a1>] folio_unlock+0x70/0xd0"
OLD_ARM64 = "[   12.000001] PC is at nft_do_chain+0x400/0x6d0 [nf_tables]\n[   12.000002] LR is at nf_hook_slow+0x48/0x100"


class Parse(unittest.TestCase):
    def test_x86_warning_report(self):
        rep = oops.parse(X86_WARN)
        p = rep.primary
        self.assertEqual((p.source, p.function, p.offset, p.size, p.module), ("rip", "mfill_atomic_copy", 0x674, 0x9D0, None))
        self.assertEqual((rep.kind, rep.file, rep.line), ("WARN", "mm/userfaultfd.c", 755))
        self.assertEqual(rep.header.source, "warning")
        self.assertEqual([f.function for f in rep.frames][:3], ["__warn", "mfill_atomic_copy", "report_bug"])
        self.assertEqual([f.reliable for f in rep.frames], [False] * 6 + [True] * 4)  # '? ' = unreliable
        self.assertNotIn("rip", [x.source for x in rep.locations if x.address is not None])  # RIP: 0033 is user mode

    def test_warning_formats(self):
        for text in (NEW_WARN, X86_WARN.splitlines()[1]):
            rep = oops.parse(text)
            self.assertEqual((rep.primary.source, rep.primary.function, rep.primary.offset, rep.file, rep.line),
                             ("warning", "mfill_atomic_copy", 0x674, "mm/userfaultfd.c", 755), text)
        for text in (NEW_WARN_NO_FILE, OLD_WARN_NO_FILE):
            rep = oops.parse(text)
            self.assertEqual((rep.kind, rep.primary.function, rep.primary.size, rep.file), ("WARN", "mfill_atomic_copy", 0x9D0, None))
        # the review's text: the size elided
        rep = oops.parse("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x...")
        self.assertEqual((rep.primary.function, rep.primary.offset, rep.primary.size), ("mfill_atomic_copy", 0x674, None))

    def test_kernel_bug(self):
        rep = oops.parse(X86_BUG)
        self.assertEqual((rep.kind, rep.file, rep.line, rep.primary.source, rep.primary.function), ("BUG", "mm/filemap.c", 1499, "rip", "folio_unlock"))
        for text in (BUG_NO_FILE, BUG_NO_FILE_510):
            rep = oops.parse(text)
            self.assertEqual((rep.kind, rep.primary.source, rep.primary.function, rep.primary.offset), ("BUG", "bug", "folio_unlock", 0x70))
        rep = oops.parse("kernel BUG at mm/filemap.c:1499!")
        self.assertEqual((rep.primary.source, rep.primary.function, rep.file, rep.line), ("bug", None, "mm/filemap.c", 1499))

    def test_arm64_module(self):
        rep = oops.parse(ARM64_BUG)
        p = rep.primary
        self.assertEqual((p.source, p.function, p.offset, p.size, p.module), ("pc", "nft_do_chain", 0x400, 0x6D0, "nf_tables"))
        self.assertEqual((rep.kind, rep.file, rep.line), ("BUG", "net/netfilter/nf_tables_core.c", 260))
        self.assertEqual([x.source for x in rep.locations], ["bug", "pc", "lr", "frame", "frame", "frame", "frame"])
        self.assertEqual([(f.function, f.module) for f in rep.frames],
                         [("nft_do_chain", "nf_tables"), ("nft_do_chain_ipv4", "nf_tables"), ("nf_hook_slow", None),
                          ("ip_local_deliver", None)])  # build ids and ' (P)' / ' (C)' read past

    def test_syzbot(self):
        rep = oops.parse(SYZBOT)
        self.assertEqual((rep.primary.source, rep.primary.function, rep.primary.file, rep.primary.line),
                         ("rip", "mfill_atomic_copy", "mm/userfaultfd.c", 755))
        self.assertEqual((rep.kind, rep.file, rep.line), ("WARN", "mm/userfaultfd.c", 755))
        inline = [f.function for f in rep.frames if f.inline]
        self.assertEqual(inline, ["userfaultfd_copy", "vfs_ioctl", "__do_sys_ioctl", "__se_sys_ioctl", "do_syscall_x64"])
        full = [(f.function, f.offset, f.file, f.line) for f in rep.frames if not f.inline]
        self.assertEqual(full[0], ("userfaultfd_ioctl", 0x5D1, "fs/userfaultfd.c", 2026))
        self.assertEqual(len(full), 4)
        # the same report as /dev/kmsg records, with another task's lines in between: same result
        mixed = "\n".join("4,%d,%d,-,caller=T5850;%s" % (900 + i, 195358969 + i, ln) for i, ln in enumerate(SYZBOT.splitlines()))
        mixed = mixed.replace("Modules linked in:", "Modules linked in:\n6,951,195388344,-,caller=T5935;usb 4-1: Using ep0 maxpacket: 16")
        rep2 = oops.parse(mixed)
        self.assertEqual([(x.source, x.function, x.offset) for x in rep2.locations], [(x.source, x.function, x.offset) for x in rep.locations])

    def test_old_formats(self):
        rep = oops.parse(OLD_X86)
        self.assertEqual((rep.primary.source, rep.primary.function, rep.primary.offset), ("rip", "mfill_atomic_copy", 0x674))
        self.assertEqual([(f.function, f.reliable) for f in rep.frames], [("__warn", False), ("userfaultfd_ioctl", True)])
        self.assertEqual(oops.parse(OLD_SUMMARY).primary.function, "mfill_atomic_copy")
        self.assertEqual((oops.parse(OLD_IP).primary.source, oops.parse(OLD_IP).primary.function), ("rip", "folio_unlock"))
        rep = oops.parse(OLD_ARM64)
        self.assertEqual([(x.source, x.function, x.module) for x in rep.locations],
                         [("pc", "nft_do_chain", "nf_tables"), ("lr", "nf_hook_slow", None)])

    def test_prefixes(self):
        line = "RIP: 0010:mfill_atomic_copy+0x674/0x9d0"
        for prefix in ("", "[  152.334270] ", "<4>[  152.334270][  T123] ", "<4>[    0.000000][    C0] ",
                       "4,1234,152334270,-;", "4,1234,152334270,-,caller=T123;", "Nov 12 10:00:00 buildhost kernel: ",
                       "2026-11-12T10:00:00.123456+00:00 buildhost kernel: ", "[Thu Nov 12 10:00:00 2026] "):
            rep = oops.parse(prefix + line)
            self.assertEqual((rep.primary.source, rep.primary.function), ("rip", "mfill_atomic_copy"), prefix)
        rep = oops.parse("<4>[  152.334305][  T123]  ? __warn+0x89/0x130")  # an entry without 'Call Trace:' above it
        self.assertEqual((rep.primary.source, rep.primary.reliable), ("text", False))

    def test_bare_lines(self):
        for text, want in (("mfill_atomic_copy+0x674", ("mfill_atomic_copy", 0x674, None, None)),
                           ("mfill_atomic_copy+0x674/0x9d0", ("mfill_atomic_copy", 0x674, 0x9D0, None)),
                           ("  mfill_atomic_copy+0x674/0x9d0 [nf_tables]  ", ("mfill_atomic_copy", 0x674, 0x9D0, "nf_tables"))):
            p = oops.parse(text).primary
            self.assertEqual((p.source, p.function, p.offset, p.size, p.module), ("text",) + want, text)
        for text in ("mm/userfaultfd.c:755", "userfaultfd.c:755"):
            rep = oops.parse(text)
            self.assertEqual((rep.primary.function, rep.file, rep.line), (None, text.split(":")[0], 755))
        p = oops.parse("mfill_atomic_copy+0x674/0x...").primary  # the size elided, as in the review's text
        self.assertEqual((p.source, p.function, p.offset, p.size), ("text", "mfill_atomic_copy", 0x674, None))
        # other text after the symbol: not a call-trace entry or a bare location
        self.assertIsNone(oops.parse("mfill_atomic_copy+0x674/0x9d0 is where it stopped").primary)

    def test_nothing(self):
        for text in ("", "hello, world", "WARNING: possible circular locking dependency detected",
                     "WARNING: suspicious RCU usage", "RIP: 0033:0x7f1c2b0e9c5b", "Code: Bad RIP value.",
                     "mfill_atomic_copy", "BUG: unable to handle page fault for address: ffffffffffffffe8"):
            self.assertIsNone(oops.parse(text).primary, text)


class Resolve(unittest.TestCase):
    def test_exact_from_every_sample(self):
        for text in (X86_WARN, NEW_WARN, NEW_WARN_NO_FILE, OLD_WARN_NO_FILE, SYZBOT, OLD_X86, OLD_SUMMARY,
                     "mfill_atomic_copy+0x674", "WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x..."):
            rep, m = find(text)
            self.assertEqual((m.status, m.address, m.site.where()), ("exact", 0xFFFFFFFF8E629BC4, "mm/userfaultfd.c:755"), text)
        rep, m = find(X86_WARN.replace("mfill_atomic_copy", "mfill_atomic_poison").replace("0x674/0x9d0", "0x494/0x850"))
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E62B164))
        lines = oops.describe(rep, m, lambda ea: "mfill_atomic_poison")
        self.assertEqual(lines[:2], ["from the log: WARNING at mm/userfaultfd.c:755; RIP: mfill_atomic_poison+0x494/0x850",
                                     "exact: the WARN site at mfill_atomic_poison+0x494 (0xffffffff8e62b164)"])

    def test_kernel_bug_and_module(self):
        rep, m = find(X86_BUG)  # RIP folio_unlock+0x70 = 0xffffffff81000110, the BUG at mm/filemap.c:1499
        self.assertEqual((m.status, m.address, m.site.where(), m.site.warn), ("exact", 0xFFFFFFFF81000110, "mm/filemap.c:1499", False))
        for text in (BUG_NO_FILE, BUG_NO_FILE_510, OLD_IP):
            self.assertEqual(find(text)[1].address, 0xFFFFFFFF81000110, text)
        rep, m = find(ARM64_BUG, module="nf_tables", is_module=True)
        self.assertEqual((m.status, m.address, m.notes), ("exact", 0x10A00, []))
        rep, m = find(ARM64_BUG)  # looked up in vmlinux: found here (synthetic), but the note says where it lives
        self.assertEqual(m.notes, ["the log puts nft_do_chain in module nf_tables; this file is not that module (vmlinux?): "
                                   "open nf_tables.ko"])
        rep, m = find(X86_BUG, module="ext4", is_module=True)
        self.assertIn("the log puts folio_unlock in the kernel image", m.notes[0])

    def test_near_and_function(self):
        rep, m = find("RIP: 0010:mfill_atomic_copy+0x670/0x9d0")
        self.assertEqual((m.status, m.address, m.site), ("near", 0xFFFFFFFF8E629BC0, None))
        self.assertEqual([s.addr for s in m.candidates], [0xFFFFFFFF8E629BC4, 0xFFFFFFFF8E629BA9])  # nearest first
        self.assertIn("not exact: no BUG/WARN site at mfill_atomic_copy+0x670", oops.describe(rep, m, lambda ea: "")[1])
        # with the WARNING's file:line the site at that line comes first, also when another one is nearer
        rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x658/0x9d0")
        self.assertEqual((m.status, [s.line for s in m.candidates]), ("near", [755, 861]))
        self.assertIn("those at mm/userfaultfd.c:755 first", oops.describe(rep, m, lambda ea: "")[1])
        rep, m = find("RIP: 0010:no_sites_fn+0x20/0x100")
        self.assertEqual((m.status, m.address, m.candidates), ("function", 0xFFFFFFFF81000820, []))
        rep, m = find("RIP: 0010:mfill_atomic_copy+0x670/0x9c0")  # a size that differs from the file's: said so
        self.assertIn("size in the log 0x9c0, here 0x9d0: another build, or another function of that name", m.notes)
        self.assertIsNone(oops.match_record(rep, m, lambda ea: "")["site"])  # near: no site claimed, only candidates

    def test_function_size_from_the_file(self):
        """The function's sites are those inside it as this file has it, whatever size the log prints."""
        copy = [0xFFFFFFFF8E629BC4, 0xFFFFFFFF8E629BA9]  # mfill_atomic_copy's two sites, the one at :755 first
        for size in ("0x100", "0x2000"):  # smaller than the file's 0x9d0 (its sites past it), or larger (the next
            text = "WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x10/" + size  # function's)
            rep, m = find(text)
            self.assertEqual((m.status, m.address, [s.addr for s in m.candidates]), ("near", 0xFFFFFFFF8E629560, copy), text)
            self.assertIn("the 2 sites in mfill_atomic_copy, those at mm/userfaultfd.c:755 first",
                          oops.describe(rep, m, lambda ea: "")[1])
        # an offset past the end of the function here: another build; its sites are listed, nothing to go to
        for off in ("0x9d0", "0xf59"):
            rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+%s/0x1400" % off)
            self.assertEqual((m.status, m.address, m.site, [s.addr for s in m.candidates]), ("near", None, None, copy), off)
            self.assertIn("mfill_atomic_copy+%s is past the end of mfill_atomic_copy here (0x9d0 bytes): a log from "
                          "another build?" % off, m.notes)
            self.assertEqual(oops.describe(rep, m, lambda ea: "")[1],
                             "not exact: mfill_atomic_copy+%s is past the end of mfill_atomic_copy in this file; the 2 "
                             "sites in mfill_atomic_copy, those at mm/userfaultfd.c:755 first, then in address order:" % off)
        rep, m = find("RIP: 0010:mfill_atomic_copy+0x9cf/0x1400")  # the last byte is still inside
        self.assertEqual((m.status, m.address), ("near", 0xFFFFFFFF8E629F1F))
        rep, m = find("RIP: 0010:no_sites_fn+0x100/0x200")  # past the end of a function without sites: nothing
        self.assertEqual((m.status, m.address, m.candidates), ("none", None, []))

    def test_ambiguous_file_line(self):
        for text in ("mm/userfaultfd.c:755", "userfaultfd.c:755", "[  12.3] mm/userfaultfd.c:755"):
            rep, m = find(text)
            self.assertEqual((m.status, m.address, m.label), ("ambiguous", None, text.split("] ")[-1]), text)
            self.assertEqual([s.addr for s in m.candidates], [a for a, _, _, _ in UFFD])
        names = {a: n for a, n, _, _ in UFFD}
        lines = oops.describe(rep, m, lambda ea: names.get(ea, ""))
        self.assertEqual(lines[1], "ambiguous: 4 BUG/WARN sites at mm/userfaultfd.c:755; the function+offset of the RIP: "
                                   "/ pc : / WARNING line picks one:")
        self.assertEqual(lines[2].split(), ["0xffffffff8e629bc4", "WARN", "mfill_atomic_copy", "mm/userfaultfd.c:755"])
        # the function is not in this file: the WARNING line's file:line still gives the candidates
        rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 other_build_fn+0x10/0x20")
        self.assertEqual((m.status, len(m.candidates), m.notes), ("ambiguous", 4, ["no function other_build_fn in this file"]))
        rep, m = find("kernel BUG at mm/filemap.c:1499!")  # one site at that line
        self.assertEqual((m.status, m.address), ("line", 0xFFFFFFFF81000110))

    def test_same_name_suffix_address(self):
        rep, m = find("RIP: 0010:dup_fn+0x10/0x60")  # both dup_fn have a site at +0x10: the log's size picks one
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF81000310))
        rep, m = find("dup_fn+0x10")  # no size, no file:line: both are candidates
        self.assertEqual((m.status, m.label, [s.addr for s in m.candidates]),
                         ("ambiguous", "dup_fn+0x10", [0xFFFFFFFF81000210, 0xFFFFFFFF81000310]))
        rep, m = find("WARNING: CPU: 0 PID: 1 at lib/dup.c:10 dup_fn+0x10")  # the WARNING's file:line picks one
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF81000210))
        rep, m = find("pc : lto_fn+0x44/0x100")  # the plain name is an 8-byte stub; lto_fn.cfi holds the site
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF81000444))
        self.assertIn("matched a function named lto_fn.<suffix>", m.notes[0])
        rep, m = find("pc : lto_fn+0x4/0x8")  # an offset inside the stub: the plain name is used
        self.assertEqual((m.status, m.function_start), ("function", 0xFFFFFFFF81000600))
        rep, m = find("RIP: 0010:0xffffffff8e629bc4")  # no symbol: the address as printed
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E629BC4))
        rep, m = find("RIP: 0010:0xffffffffc0a01234")
        self.assertEqual(m.status, "none")
        self.assertIn("KASLR", m.notes[0])

    def test_no_match(self):
        for text in ("hello", "RIP: 0010:missing_fn+0x10/0x20", "kernel BUG at mm/nowhere.c:1!"):
            rep, m = find(text)
            self.assertEqual((m.status, m.address), ("none", None), text)
            self.assertEqual(oops.describe(rep, m, lambda ea: "")[-2 if m.notes else -1], "no match")
        self.assertEqual(find("hello")[1].notes, ["no WARNING / kernel BUG / RIP / pc line, func+0xoff or file:line in the text"])

    def test_helpers_and_json(self):
        self.assertTrue(all(oops.same_file("mm/userfaultfd.c", b) for b in
                            ("mm/userfaultfd.c", "userfaultfd.c", "./mm/userfaultfd.c", "/build/linux/mm/userfaultfd.c")))
        self.assertFalse(oops.same_file("mm/userfaultfd.c", "fault.c"))
        self.assertEqual([oops.module_name(p) for p in ("/x/nf_tables.ko", "ext4.ko.xz", "snd-hda-intel.ko.zst", "vmlinux")],
                         ["nf_tables", "ext4", "snd_hda_intel", None])
        rep, m = find(SYZBOT)
        rec = json.loads(json.dumps(oops.match_record(rep, m, lambda ea: "mfill_atomic_copy")))
        self.assertEqual((rec["status"], rec["address"], rec["site"]["line"], rec["from"]["offset"], len(rec["frames"])),
                         ("exact", "0xFFFFFFFF8E629BC4", 755, "0x674", 9))


def whole_kernel(path):
    """Every BUG/WARN site inside a function of this file: a RIP (x86_64) or pc (arm64) line built from its function
    and offset resolves to it; and each file:line gives exactly the sites at that line."""
    from kflow.cli import Elf, load
    elf = Elf(path)
    t = load(elf)
    bugs = t.get("bug", [])
    index = oops.SiteIndex(bugs)
    mod = oops.module_name(path)
    tag = " [%s]" % mod if mod and re.fullmatch(r"\w+", mod) else ""  # a renamed copy (deb13-6.12.115-bridge.ko): none
    reg = {"x86_64": "RIP: 0010:", "aarch64": "pc : "}.get(elf.arch, "RIP: 0010:")
    first_at = {}
    for b in bugs:
        first_at.setdefault(b.addr, b)
    done = same_name = 0
    for b in bugs:
        name = elf.func(b.addr)
        if not name or first_at[b.addr] is not b:
            continue
        start, size = next((a, s) for a, s in elf.function_starts(name) if a <= b.addr < a + s)
        rep = oops.parse("%s%s+%#x/%#x%s" % (reg, name, b.addr - start, size, tag))
        m = oops.resolve(rep, index, elf.function_starts, mod, elf.relocatable)
        if m.status == "ambiguous":  # functions of the same name and size, each with a site at this offset
            assert b in m.candidates and m.label == "%s+%#x" % (name, b.addr - start), (hex(b.addr), m)
            same_name += 1
        else:
            assert (m.status, m.address) == ("exact", b.addr), (hex(b.addr), name, m.status, m.notes)
            assert not m.notes or (elf.relocatable and not tag and len(m.notes) == 1
                                   and "in the kernel image (no [module] after it)" in m.notes[0]), m.notes
        done += 1
    per_line = {}
    for b in bugs:
        if b.file:
            per_line.setdefault((b.file, b.line), []).append(b.addr)
    lines = list(per_line.items())[::max(1, len(per_line) // 300)]
    for (f, ln), addrs in lines:
        m = oops.resolve(oops.parse("%s:%d" % (f, ln)), index, elf.function_starts)
        want = sorted(set(addrs))
        assert sorted({s.addr for s in m.candidates}) == want and m.status == ("line" if len(addrs) == 1 else "ambiguous"), (f, ln, m.status)
    cli_check(path, elf, bugs, reg, tag)
    if any(b.addr == 0xFFFFFFFF8E629BC4 for b in bugs):  # the MemLens demo kernel: the review's example
        m = oops.resolve(oops.parse("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x..."),
                         index, elf.function_starts)
        assert (m.status, m.address, m.site.where()) == ("exact", 0xFFFFFFFF8E629BC4, "mm/userfaultfd.c:755"), m
    print("OK oops on %s: %d of %d BUG/WARN sites in functions found from their %sfunc+0xoff/0xsize line (%d of them "
          "among same-named functions: listed as candidates); file:line checked for %d lines; --oops exit status, "
          "output and --json checked"
          % (os.path.basename(path), done, len(bugs), reg, same_name, len(lines)))


def cli_check(path, elf, bugs, reg, tag):
    """python3 -m kflow <file> --oops <log> [--json]: exit status 0 / 1 / 2, the printed match, the JSON record."""
    import contextlib
    import io
    import tempfile
    from kflow import cli
    site = next((b for b in bugs if elf.func(b.addr) and b.file), None)
    with tempfile.TemporaryDirectory() as d:
        log, out = os.path.join(d, "oops.txt"), os.path.join(d, "oops.json")

        def run(text, *more):
            with open(log, "w") as fh:
                fh.write(text)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                code = cli.main([path, "--oops", log] + list(more))
            return code, buf.getvalue()
        if site is not None:
            name = elf.func(site.addr)
            start, size = next((a, n) for a, n in elf.function_starts(name) if a <= site.addr < a + n)
            text = "[  152.334201] WARNING: CPU: 1 PID: 9 at %s:%d %s+%#x/%#x%s\n" % (site.file, site.line, name,
                                                                              site.addr - start, size, tag)
            code, got = run(text, "--json", out)
            rec = json.load(open(out))["oops"]
            if rec["status"] == "exact":
                assert code == 0 and "%#x" % site.addr in got.splitlines()[2] and got.splitlines()[1].startswith("exact:"), got
                assert rec["address"] == "0x%X" % site.addr and rec["site"]["line"] == site.line, rec
            else:  # same-named functions with a site at this offset
                assert code == 0 and rec["status"] == "ambiguous" and "0x%X" % site.addr in [c["addr"] for c in rec["candidates"]]
        code, got = run("hello, world\n")
        assert code == 1 and "no match" in got, got
        code, got = run("%skflow_no_such_function+0x10/0x20\n" % reg)
        assert code == 1 and "note: no function kflow_no_such_function in this file" in got, got
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main([path, "--oops", os.path.join(d, "missing.txt")])
        assert code == 2 and "missing.txt" in err.getvalue(), err.getvalue()


if __name__ == "__main__":
    paths = sys.argv[1:]
    del sys.argv[1:]
    result = unittest.main(exit=False, verbosity=1).result
    if not result.wasSuccessful():
        sys.exit(1)
    for p in paths:
        whole_kernel(p)
