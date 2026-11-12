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
          BugSite(0xFFFFFFFF8E62ACE0, "mm/userfaultfd.c", 900, 1),  # a WARN in mfill_atomic_poison, before :755's
          BugSite(0xFFFFFFFF810012C3, "lib/pad.c", 1, 1),  # right at the end of padded_fn's code: not in it
          BugSite(0xFFFFFFFF81000110, "mm/filemap.c", 1499, 0),  # folio_unlock: a BUG with a unique file:line
          BugSite(0xFFFFFFFF81000210, "lib/dup.c", 10, 1),  # two static functions named dup_fn: sites at +0x10 in both
          BugSite(0xFFFFFFFF81000310, "lib/dup.c", 20, 1),
          BugSite(0xFFFFFFFF81000444, "kernel/cfi.c", 7, 1),  # in lto_fn.cfi (the log prints lto_fn)
          BugSite(0x10A00, "net/netfilter/nf_tables_core.c", 260, 0)]  # a module's BUG (ARM64_BUG: kernel BUG at)
# the six WARN_ONCE sites of refcount_warn_saturate on the MemLens demo kernel (lib/refcount.c, flags 0x909), POW_X86
SITES += [BugSite(a, "lib/refcount.c", ln, 0x909) for a, ln in (
    (0xFFFFFFFF8E8A52B5, 22), (0xFFFFFFFF8E8A52D8, 34), (0xFFFFFFFF8E8A52FB, 19), (0xFFFFFFFF8E8A531E, 28),
    (0xFFFFFFFF8E8A5345, 25), (0xFFFFFFFF8E8A535F, 31))]
FUNCS.update({"folio_unlock": [(0xFFFFFFFF810000A0, 0xD0)],
              "dup_fn": [(0xFFFFFFFF81000200, 0x40), (0xFFFFFFFF81000300, 0x60)],
              "lto_fn": [(0xFFFFFFFF81000600, 0x8)],  # the 8-byte CFI jump-table entry has the plain name
              "no_sites_fn": [(0xFFFFFFFF81000800, 0x100)],
              "nft_do_chain": [(0x10600, 0x6D0)],
              "refcount_warn_saturate": [(0xFFFFFFFF8E8A5260, 0x110)]})
SUFFIXED = {"lto_fn": [oops.Func(0xFFFFFFFF81000400, 0x100, None, "lto_fn.cfi")]}
# Clang LTO (Android GKI 5.10): three static functions the kernel prints as cut_fn: cut_fn, cut_fn.123 (same size) and
# cut_fn.77 (larger), each with a WARN at +0x20; GCC: gcc_fn and gcc_fn.part.0, printed in full by the kernel
FUNCS["cut_fn"] = [oops.Func(0xFFFFFFFF81002000, 0x80, 0x80, "cut_fn")]
SUFFIXED["cut_fn"] = [oops.Func(0xFFFFFFFF81002100, 0x80, 0x80, "cut_fn.123"),
                      oops.Func(0xFFFFFFFF81002200, 0x90, 0x90, "cut_fn.77")]
FUNCS["gcc_fn"] = [oops.Func(0xFFFFFFFF81002400, 0x40, 0x40, "gcc_fn")]
SUFFIXED["gcc_fn"] = FUNCS["gcc_fn.part.0"] = [oops.Func(0xFFFFFFFF81002500, 0x100, 0x100, "gcc_fn.part.0")]
SITES += [BugSite(0xFFFFFFFF81002020, "lib/cut_a.c", 1, 1), BugSite(0xFFFFFFFF81002120, "lib/cut_b.c", 2, 1),
          BugSite(0xFFFFFFFF81002220, "lib/cut_c.c", 3, 1), BugSite(0xFFFFFFFF81002560, "lib/gcc.c", 5, 1)]
# the size the kernel prints is measured to the next symbol: padding after the code counts (st_size 0x9c3, prints 0x9d0)
FUNCS["padded_fn"] = [oops.Func(0xFFFFFFFF81000900, 0x9C3, 0x9D0, "padded_fn")]
# two static functions named pad_dup, code sizes 0x40 and 0x48, both printed as 0x50: the code size still picks
FUNCS["pad_dup"] = [oops.Func(0xFFFFFFFF81001000, 0x40, 0x50, "pad_dup"), oops.Func(0xFFFFFFFF81001100, 0x48, 0x50, "pad_dup")]
# a BUG at a function's first byte (Android GKI 6.1 arm64: switched_to_stop+0x0, after the 8-byte task_tick_stop)
FUNCS["task_tick_stop"] = [oops.Func(0xFFFFFFFF81003000, 0x8, 0x8, "task_tick_stop")]
FUNCS["switched_to_stop"] = [oops.Func(0xFFFFFFFF81003008, 0x8, 0x8, "switched_to_stop")]
SITES += [BugSite(0xFFFFFFFF81003008, "kernel/sched/stop_task.c", 101, 0)]
# the same after padding: pb_prev's code is 0x20 bytes, kallsyms prints 0x30 (to pb_next), and pb_next has a BUG at +0x0
FUNCS["pb_prev"] = [oops.Func(0xFFFFFFFF81003100, 0x20, 0x30, "pb_prev")]
FUNCS["pb_next"] = [oops.Func(0xFFFFFFFF81003130, 0x18, 0x20, "pb_next")]
SITES += [BugSite(0xFFFFFFFF81003130, "kernel/pb.c", 7, 0)]


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
# the rest of that oops (arch/x86/kernel/dumpstack.c, 4.17+): __die_body() show_regs() (registers, call trace) and
# print_modules(), then oops_end(): oops_exit()'s '---[ end trace %016llx ]---', the executive summary
# __show_regs(&exec_summary_regs, ...) ('RIP: %04x:%pS' and the registers again, "in case the oops scrolled away") and
# panic("Fatal exception"). One report (review s163 MINOR 1)
X86_BUG_REST = """\
<4>[  222.942110][ T8817] Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff 0f 0b <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
<4>[  222.942120][ T8817] RSP: 0018:ffffc90000d4bd18 EFLAGS: 00010246
<4>[  222.942130][ T8817] RAX: 0000000000000000 RBX: ffff888103a2c000 RCX: 0000000000000000
<4>[  222.942140][ T8817] Call Trace:
<4>[  222.942141][ T8817]  <TASK>
<4>[  222.942142][ T8817]  ? die+0x36/0x90
<4>[  222.942143][ T8817]  ? do_trap+0xdd/0x100
<4>[  222.942144][ T8817]  ? folio_unlock+0x70/0xd0
<4>[  222.942145][ T8817]  ? exc_invalid_op+0x50/0x70
<4>[  222.942146][ T8817]  ? asm_exc_invalid_op+0x1a/0x20
<4>[  222.942147][ T8817]  filemap_add_folio+0x3c/0xa0
<4>[  222.942148][ T8817]  do_syscall_64+0x82/0x190
<4>[  222.942149][ T8817]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
<4>[  222.942150][ T8817]  </TASK>
<4>[  222.942151][ T8817] Modules linked in: nf_tables libcrc32c
<4>[  222.942160][ T8817] ---[ end trace 0000000000000000 ]---
<4>[  222.942170][ T8817] RIP: 0010:folio_unlock+0x70/0xd0
<4>[  222.942171][ T8817] Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff 0f 0b <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
<4>[  222.942172][ T8817] RSP: 0018:ffffc90000d4bd18 EFLAGS: 00010246
<4>[  222.942173][ T8817] RAX: 0000000000000000 RBX: ffff888103a2c000 RCX: 0000000000000000
<0>[  222.942180][ T8817] Kernel panic - not syncing: Fatal exception
<0>[  222.942190][ T8817] Kernel Offset: disabled
<0>[  222.942200][ T8817] ---[ end Kernel panic - not syncing: Fatal exception ]---
"""
# the same oops as a syzbot report (symbolized, no prefixes) ends with the summary too
SYZBOT_BUG = """\
------------[ cut here ]------------
kernel BUG at mm/filemap.c:1499!
Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN NOPTI
CPU: 1 UID: 0 PID: 5850 Comm: syz-executor123 Not tainted 6.12.0-rc7-syzkaller #0
RIP: 0010:folio_unlock+0x70/0xd0 mm/filemap.c:1499
Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff e8 40 59 25 00 <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
RSP: 0018:ffffc90003a77a80 EFLAGS: 00010293
Call Trace:
 <TASK>
 filemap_add_folio+0x3c/0xa0 mm/filemap.c:960
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f4d1c2e4ab9
RSP: 002b:00007ffd4e1d6c18 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:folio_unlock+0x70/0xd0 mm/filemap.c:1499
Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff e8 40 59 25 00 <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
RSP: 0018:ffffc90003a77a80 EFLAGS: 00010293
"""
# report_bug() without file:line: 'Kernel BUG at %pB [verbose debug info unavailable]' (capital K, v5.10 to v7.0); the
# lower-case form is not printed by the kernel but accepted, as people retype it
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
# syzbot symbolizes a %pS that lies in inlined code by printing its line once per inlined frame, innermost first, as
# 'func file:line [inline]' (no address), then once with the function+offset (review s161 MAJOR 1; as in its 'WARNING
# in hlock_class' reports): the WARNING line and the RIP line both. The WARN at mm/userfaultfd.c:755 is in mfill_atomic(),
# which the MemLens demo kernel inlines into mfill_atomic_copy and three other functions; the caller's line is made up
SYZBOT_INLINE = SYZBOT.replace(
    "WARNING: CPU: 1 PID: 5850 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:755\n",
    "WARNING: CPU: 1 PID: 5850 at mm/userfaultfd.c:755 mfill_atomic mm/userfaultfd.c:755 [inline]\n"
    "WARNING: CPU: 1 PID: 5850 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:887\n").replace(
    "RIP: 0010:mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:755\n",
    "RIP: 0010:mfill_atomic mm/userfaultfd.c:755 [inline]\nRIP: 0010:mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:887\n")
# the same with __warn()'s 6.19 format, the rest of the line after each frame (syzbot keeps what follows the symbol)
SYZBOT_INLINE_619 = SYZBOT_INLINE.replace(
    "WARNING: CPU: 1 PID: 5850 at mm/userfaultfd.c:755 mfill_atomic mm/userfaultfd.c:755 [inline]\n",
    "WARNING: mm/userfaultfd.c:755 at mfill_atomic mm/userfaultfd.c:755 [inline], CPU#1: syz.0.17/5850\n").replace(
    "WARNING: CPU: 1 PID: 5850 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:887\n",
    "WARNING: mm/userfaultfd.c:755 at mfill_atomic_copy+0x674/0x9d0 mm/userfaultfd.c:887, CPU#1: syz.0.17/5850\n")
# review s161's paste on the MemLens demo kernel: the WARN site kernel/sched/sched.h:1686 at update_rq_clock+0x13d
# (0xffffffff8e30df4d; lockdep_assert_rq_held() inlined) and update_rq_clock's size are that kernel's; the caller's line,
# the call trace and the register values are made up
SYZ_SCHED = """\
------------[ cut here ]------------
WARNING: CPU: 0 PID: 5100 at kernel/sched/sched.h:1686 lockdep_assert_rq_held kernel/sched/sched.h:1686 [inline]
WARNING: CPU: 0 PID: 5100 at kernel/sched/sched.h:1686 update_rq_clock+0x13d/0x1a0 kernel/sched/core.c:790
Modules linked in:
CPU: 0 UID: 0 PID: 5100 Comm: syz-executor104 Not tainted 6.12.0-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
RIP: 0010:lockdep_assert_rq_held kernel/sched/sched.h:1686 [inline]
RIP: 0010:update_rq_clock+0x13d/0x1a0 kernel/sched/core.c:790
Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff e8 40 59 25 00 <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
RSP: 0018:ffffc90003a77a80 EFLAGS: 00010293
RAX: ffffffff81f3a1b4 RBX: 0000000000000000 RCX: ffff888028138000
Call Trace:
 <TASK>
 __schedule+0x3f0/0xbe0 kernel/sched/core.c:6600
 schedule+0x27/0xc0 kernel/sched/core.c:6781
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x1b0 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7e
 </TASK>
"""

# registers that are not the report's trap (review s161 MAJOR 2). x86 prints the interrupted context's registers where a
# call trace crosses an IRQ or exception entry (show_regs_if_on_stack / show_iret_regs: 'RIP: %04x:%pS'), so a KASAN
# report raised in an interrupt has the RIP of the code it interrupted after 'Call Trace:'; hung-task and RCU-stall
# reports print other CPUs' registers after 'NMI backtrace for cpu %d' (lib/nmi_backtrace.c; arm64: __show_regs 'pc :').
# Each RIP / pc here lands on a BUG/WARN site of the synthetic table: taken as the trap, it would be an exact match
KASAN_IRQ = """\
[  301.000001] ==================================================================
[  301.000010] BUG: KASAN: slab-use-after-free in folio_unlock+0x10/0xd0
[  301.000020] Read of size 8 at addr ffff888012345678 by task swapper/0/0
[  301.000040] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.12.115+deb13.1-amd64 #1  Debian 6.12.115-2
[  301.000060] Call Trace:
[  301.000070]  <IRQ>
[  301.000080]  dump_stack_lvl+0x5d/0x80
[  301.000090]  print_report+0xcf/0x620
[  301.000100]  kasan_report+0xb5/0xe0
[  301.000110]  folio_unlock+0x10/0xd0
[  301.000120]  __handle_irq_event_percpu+0x4a/0x1a0
[  301.000140]  </IRQ>
[  301.000150]  <TASK>
[  301.000160]  asm_common_interrupt+0x26/0x40
[  301.000170] RIP: 0010:mfill_atomic_copy+0x674/0x9d0
[  301.000180] Code: 4c 01 c7 4c 29 c2 e9 72 ff ff ff 90 90 90 90 90 90 90 90 90 90 90 90 90 <fa> c3 cc cc cc cc 66 66 2e 0f
[  301.000190] RSP: 0018:ffffffff8f803e78 EFLAGS: 00000202
[  301.000200]  ? mfill_atomic_copy+0x670/0x9d0
[  301.000210]  userfaultfd_ioctl+0x5d1/0x1e70
[  301.000230]  </TASK>
[  301.000240] ==================================================================
"""
HUNG_NMI = """\
INFO: task kworker/u8:3:5123 blocked for more than 143 seconds.
      Not tainted 6.12.115+deb13.1-amd64 #1
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:kworker/u8:3    state:D stack:0     pid:5123  tgid:5123  ppid:2      flags:0x00004000
Call Trace:
 <TASK>
 __schedule+0x3f0/0xb40
 schedule+0x27/0xf0
 </TASK>
NMI backtrace for cpu 1
CPU: 1 UID: 0 PID: 29 Comm: khungtaskd Not tainted 6.12.115+deb13.1-amd64 #1  Debian 6.12.115-2
Call Trace:
 <TASK>
 dump_stack_lvl+0x5d/0x80
 nmi_cpu_backtrace+0xd0/0x100
 </TASK>
Sending NMI from CPU 1 to CPUs 0:
NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 4410 Comm: stress Not tainted 6.12.115+deb13.1-amd64 #1  Debian 6.12.115-2
RIP: 0010:mfill_atomic_copy+0x674/0x9d0
Code: 90 90 90
RSP: 0018:ffffb37c4a8bfe08 EFLAGS: 00000246
Call Trace:
 <NMI>
 ? nmi_cpu_backtrace+0x9d/0x100
 </NMI>
 <TASK>
 userfaultfd_ioctl+0x5d1/0x1e70
 </TASK>
"""
# an RCU stall: no call trace before the other CPU's registers, only its 'NMI backtrace for cpu' line; and on arm64 the
# registers alone (a partial paste: arm64 repeats the pc as the first call-trace entry)
RCU_NMI = """\
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
rcu:     0-...!: (1 GPs behind) idle=b9c4/1/0x4000000000000000 softirq=8721/8722 fqs=2531
rcu:     (detected by 1, t=10502 jiffies, g=12345, q=86 ncpus=2)
Sending NMI from CPU 1 to CPUs 0:
NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 4410 Comm: stress Not tainted 6.12.115+deb13.1-amd64 #1  Debian 6.12.115-2
RIP: 0010:mfill_atomic_copy+0x674/0x9d0
Code: 90 90 90
RSP: 0018:ffffb37c4a8bfe08 EFLAGS: 00000246
Call Trace:
 <NMI>
 ? nmi_cpu_backtrace+0x9d/0x100
 </NMI>
 <TASK>
 userfaultfd_ioctl+0x5d1/0x1e70
 </TASK>
"""
RCU_NMI_ARM64 = """\
<3>[  412.110000] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
<6>[  412.110030] Sending NMI from CPU 1 to CPUs 3:
<4>[  412.110040] NMI backtrace for cpu 3
<4>[  412.110050] CPU: 3 UID: 0 PID: 4021 Comm: nft Not tainted 6.12.94+deb13-arm64 #1  Debian 6.12.94-1
<4>[  412.110060] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
<4>[  412.110070] pc : nft_do_chain+0x400/0x6d0 [nf_tables]
<4>[  412.110080] lr : nft_do_chain+0x2a0/0x6d0 [nf_tables]
"""

# panic_on_warn (kernel/panic.c, 6.12): __warn() prints the WARNING report (show_regs: registers, call trace), then
# check_panic_on_warn("kernel") calls panic() before the end marker: 'Kernel panic - not syncing: kernel: panic_on_warn
# set ...', then panic()'s own dump_stack(), which on x86 crosses the exception frame and prints the trap's RIP again.
# One report. Built on the MemLens demo kernel (Debian 6.12.115): the WARN_ONCE site lib/refcount.c:28 at
# refcount_warn_saturate+0xbe, the Code: bytes, every function+offset/size (return addresses from its disassembly: the
# kcmp syscall's call with REFCOUNT_SUB_UAF, __warn.cold / check_panic_on_warn.cold, panic's dump_stack call) and the
# Kernel Offset are that kernel's; register values and the user-mode lines are made up
POW_X86 = """\
[ 4521.903101] ------------[ cut here ]------------
[ 4521.903114] refcount_t: underflow; use-after-free.
[ 4521.903139] WARNING: CPU: 2 PID: 48213 at lib/refcount.c:28 refcount_warn_saturate+0xbe/0x110
[ 4521.903152] Modules linked in: nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 nf_tables libcrc32c nfnetlink binfmt_misc virtio_net net_failover failover virtio_balloon joydev evdev button ext4 crc16 mbcache jbd2 virtio_blk virtio_pci virtio_pci_legacy_dev virtio_pci_modern_dev virtio virtio_ring
[ 4521.903188] CPU: 2 UID: 1000 PID: 48213 Comm: kcmp-test Not tainted 6.12.115+deb13.1-amd64 #1  Debian 6.12.115-2
[ 4521.903195] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
[ 4521.903199] RIP: 0010:refcount_warn_saturate+0xbe/0x110
[ 4521.903207] Code: 01 01 e8 35 dc a1 ff 0f 0b c3 cc cc cc cc 80 3d db 65 78 01 00 75 85 48 c7 c7 68 a6 79 8f c6 05 cb 65 78 01 01 e8 12 dc a1 ff <0f> 0b c3 cc cc cc cc 80 3d b9 65 78 01 00 0f 85 5e ff ff ff 48 c7
[ 4521.903211] RSP: 0018:ffffb37c4a8bfe08 EFLAGS: 00010286
[ 4521.903217] RAX: 0000000000000000 RBX: ffff8f2a43a1c000 RCX: 0000000000000027
[ 4521.903221] RDX: ffff8f2bbbd21788 RSI: 0000000000000001 RDI: ffff8f2bbbd21780
[ 4521.903224] RBP: 0000000000000000 R08: 0000000000000000 R09: ffffb37c4a8bfc90
[ 4521.903228] R10: ffffb37c4a8bfc88 R11: ffffffff902f1d28 R12: ffff8f2a43a1c000
[ 4521.903231] R13: 0000000000000000 R14: 0000000000000000 R15: ffff8f2a4c3b9500
[ 4521.903235] FS:  00007f6e2d4f9740(0000) GS:ffff8f2bbbd00000(0000) knlGS:0000000000000000
[ 4521.903239] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 4521.903242] CR2: 00007f6e2d6c2000 CR3: 0000000112f6a003 CR4: 0000000000770ef0
[ 4521.903248] Call Trace:
[ 4521.903250]  <TASK>
[ 4521.903253]  ? __warn.cold+0x93/0xf6
[ 4521.903260]  ? refcount_warn_saturate+0xbe/0x110
[ 4521.903266]  ? report_bug+0xff/0x140
[ 4521.903272]  ? handle_bug+0x10f/0x170
[ 4521.903277]  ? exc_invalid_op+0x17/0x70
[ 4521.903281]  ? asm_exc_invalid_op+0x1a/0x20
[ 4521.903286]  ? refcount_warn_saturate+0xbe/0x110
[ 4521.903292]  __do_sys_kcmp+0x28d/0x560
[ 4521.903298]  do_syscall_64+0x87/0x1b0
[ 4521.903303]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
[ 4521.903308] RIP: 0033:0x7f6e2d61c88d
[ 4521.903311] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 73 b5 0d 00 f7 d8 64 89 01 48
[ 4521.903316] RSP: 002b:00007ffc8a1e3b58 EFLAGS: 00000246 ORIG_RAX: 0000000000000138
[ 4521.903321] RAX: ffffffffffffffda RBX: 00007ffc8a1e3c88 RCX: 00007f6e2d61c88d
[ 4521.903325] RDX: 0000000000000000 RSI: 000000000000bc55 RDI: 000000000000bc55
[ 4521.903328] RBP: 00007ffc8a1e3b70 R08: 0000000000000000 R09: 00007f6e2d71a680
[ 4521.903332] R10: 0000000000000003 R11: 0000000000000246 R12: 0000000000000000
[ 4521.903335] R13: 00007ffc8a1e3c98 R14: 00007f6e2d75c000 R15: 000055d8c4a0fdd8
[ 4521.903339]  </TASK>
[ 4521.903342] Kernel panic - not syncing: kernel: panic_on_warn set ...
[ 4521.903519] CPU: 2 UID: 1000 PID: 48213 Comm: kcmp-test Not tainted 6.12.115+deb13.1-amd64 #1  Debian 6.12.115-2
[ 4521.903525] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
[ 4521.903528] Call Trace:
[ 4521.903530]  <TASK>
[ 4521.903532]  dump_stack_lvl+0x5d/0x80
[ 4521.903538]  panic+0x118/0x2db
[ 4521.903543]  check_panic_on_warn.cold+0xf/0x1e
[ 4521.903548]  __warn.cold+0x9f/0xf6
[ 4521.903553]  ? refcount_warn_saturate+0xbe/0x110
[ 4521.903557]  report_bug+0xff/0x140
[ 4521.903562]  handle_bug+0x10f/0x170
[ 4521.903566]  exc_invalid_op+0x17/0x70
[ 4521.903570]  asm_exc_invalid_op+0x1a/0x20
[ 4521.903575] RIP: 0010:refcount_warn_saturate+0xbe/0x110
[ 4521.903579] Code: 01 01 e8 35 dc a1 ff 0f 0b c3 cc cc cc cc 80 3d db 65 78 01 00 75 85 48 c7 c7 68 a6 79 8f c6 05 cb 65 78 01 01 e8 12 dc a1 ff <0f> 0b c3 cc cc cc cc 80 3d b9 65 78 01 00 0f 85 5e ff ff ff 48 c7
[ 4521.903583] RSP: 0018:ffffb37c4a8bfe08 EFLAGS: 00010286
[ 4521.903587] RAX: 0000000000000000 RBX: ffff8f2a43a1c000 RCX: 0000000000000027
[ 4521.903590] RDX: ffff8f2bbbd21788 RSI: 0000000000000001 RDI: ffff8f2bbbd21780
[ 4521.903594] RBP: 0000000000000000 R08: 0000000000000000 R09: ffffb37c4a8bfc90
[ 4521.903597] R10: ffffb37c4a8bfc88 R11: ffffffff902f1d28 R12: ffff8f2a43a1c000
[ 4521.903601] R13: 0000000000000000 R14: 0000000000000000 R15: ffff8f2a4c3b9500
[ 4521.903605]  __do_sys_kcmp+0x28d/0x560
[ 4521.903610]  do_syscall_64+0x87/0x1b0
[ 4521.903614]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
[ 4521.903618] RIP: 0033:0x7f6e2d61c88d
[ 4521.903621] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 73 b5 0d 00 f7 d8 64 89 01 48
[ 4521.903625] RSP: 002b:00007ffc8a1e3b58 EFLAGS: 00000246 ORIG_RAX: 0000000000000138
[ 4521.903629] RAX: ffffffffffffffda RBX: 00007ffc8a1e3c88 RCX: 00007f6e2d61c88d
[ 4521.903632] RDX: 0000000000000000 RSI: 000000000000bc55 RDI: 000000000000bc55
[ 4521.903636] RBP: 00007ffc8a1e3b70 R08: 0000000000000000 R09: 00007f6e2d71a680
[ 4521.903639] R10: 0000000000000003 R11: 0000000000000246 R12: 0000000000000000
[ 4521.903643] R13: 00007ffc8a1e3c98 R14: 00007f6e2d75c000 R15: 000055d8c4a0fdd8
[ 4521.903645]  </TASK>
[ 4521.903790] Kernel Offset: 0xd200000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[ 4521.927451] ---[ end Kernel panic - not syncing: kernel: panic_on_warn set ... ]---
"""
# the same on arm64 (6.12 formats; offsets made up): the panic's dump has no pc line, the trap is a call-trace entry
POW_ARM64 = """\
<4>[  88.123450][ T2201] ------------[ cut here ]------------
<4>[  88.123460][ T2201] WARNING: CPU: 5 PID: 2201 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0
<4>[  88.123470][ T2201] Modules linked in:
<4>[  88.123480][ T2201] CPU: 5 UID: 0 PID: 2201 Comm: uffd-test Not tainted 6.12.94+deb13-arm64 #1  Debian 6.12.94-1
<4>[  88.123485][ T2201] Hardware name: linux,dummy-virt (DT)
<4>[  88.123490][ T2201] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
<4>[  88.123500][ T2201] pc : mfill_atomic_copy+0x674/0x9d0
<4>[  88.123505][ T2201] lr : mfill_atomic_copy+0x4b0/0x9d0
<4>[  88.123510][ T2201] sp : ffff80008a3b3c40
<4>[  88.123520][ T2201] Call trace:
<4>[  88.123525][ T2201]  mfill_atomic_copy+0x674/0x9d0
<4>[  88.123530][ T2201]  userfaultfd_ioctl+0x5d1/0x1e70
<4>[  88.123535][ T2201]  __arm64_sys_ioctl+0xb4/0x100
<0>[  88.123540][ T2201] Kernel panic - not syncing: kernel: panic_on_warn set ...
<4>[  88.123550][ T2201] CPU: 5 UID: 0 PID: 2201 Comm: uffd-test Not tainted 6.12.94+deb13-arm64 #1  Debian 6.12.94-1
<4>[  88.123555][ T2201] Hardware name: linux,dummy-virt (DT)
<4>[  88.123560][ T2201] Call trace:
<4>[  88.123565][ T2201]  dump_backtrace+0x9c/0x100
<4>[  88.123566][ T2201]  show_stack+0x20/0x38
<4>[  88.123570][ T2201]  dump_stack_lvl+0x38/0xd0
<4>[  88.123575][ T2201]  dump_stack+0x18/0x28
<4>[  88.123580][ T2201]  panic+0x3ac/0x418
<4>[  88.123585][ T2201]  check_panic_on_warn+0x60/0xa0
<4>[  88.123590][ T2201]  __warn+0xa0/0x1c0
<4>[  88.123595][ T2201]  report_bug+0x118/0x1d8
<4>[  88.123600][ T2201]  bug_handler+0x2c/0x88
<4>[  88.123605][ T2201]  call_el1_break_hook+0x80/0xa0
<4>[  88.123610][ T2201]  brk_handler+0x2c/0xb0
<4>[  88.123615][ T2201]  do_debug_exception+0x70/0x170
<4>[  88.123620][ T2201]  el1_dbg+0x64/0x80
<4>[  88.123625][ T2201]  el1h_64_sync_handler+0x60/0xa8
<4>[  88.123630][ T2201]  el1h_64_sync+0x64/0x68
<4>[  88.123635][ T2201]  mfill_atomic_copy+0x674/0x9d0
<4>[  88.123640][ T2201]  userfaultfd_ioctl+0x5d1/0x1e70
<4>[  88.123645][ T2201]  __arm64_sys_ioctl+0xb4/0x100
<0>[  88.123700][ T2201] SMP: stopping secondary CPUs
<0>[  88.123710][ T2201] Kernel Offset: disabled
<0>[  88.123730][ T2201] Memory Limit: none
<0>[  88.123740][ T2201] ---[ end Kernel panic - not syncing: kernel: panic_on_warn set ... ]---
"""

# Linux 4.10 to 4.16 (arch/x86/kernel/dumpstack.c __die(): show_regs(), then the executive summary 'RIP: %pS RSP:
# %016lx', no CS, after the call trace), as Ubuntu 18.04's 4.15 prints it; the site and sizes are the fixture's
X86_414_BUG = """\
[  222.868961] ------------[ cut here ]------------
[  222.868990] kernel BUG at mm/filemap.c:1499!
[  222.942000] invalid opcode: 0000 [#1] SMP PTI
[  222.942001] Modules linked in: nf_tables libcrc32c
[  222.942010] CPU: 1 PID: 8817 Comm: a.out Not tainted 4.15.0-213-generic #224-Ubuntu
[  222.942030] RIP: 0010:folio_unlock+0x70/0xd0
[  222.942120] RSP: 0018:ffffc90000d4bd18 EFLAGS: 00010246
[  222.942140] Call Trace:
[  222.942147]  filemap_add_folio+0x3c/0xa0
[  222.942148]  do_syscall_64+0x82/0x190
[  222.942149]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
[  222.942150] Code: 48 8b 7c 24 10 e8 c5 f2 ff ff 49 89 c4 e9 1b fc ff ff 0f 0b <0f> 0b 49 c7 c4 f2 ff ff ff e9 0d fc ff ff
[  222.942160] RIP: folio_unlock+0x70/0xd0 RSP: ffffc90000d4bd18
[  222.942170] ---[ end trace 1a2b3c4d5e6f7081 ]---
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
# logs from other builds (review s157): Ubuntu 6.8 x86_64, Android 5.10 arm64
OTHER_BUILD_X86 = """\
[  301.551234] ------------[ cut here ]------------
[  301.551240] WARNING: CPU: 2 PID: 4411 at mm/mmu_notifier.c:848 mmu_notifier_unregister+0xd8/0xf0
[  301.551290] CPU: 2 PID: 4411 Comm: qemu-system-x86 Not tainted 6.8.0-149-generic #159-Ubuntu
[  301.551300] RIP: 0010:mmu_notifier_unregister+0xd8/0xf0
"""
OTHER_BUILD_ARM64 = """\
<4>[  88.123460][ T2201] WARNING: CPU: 5 PID: 2201 at lib/refcount.c:25 prepare_kernel_cred+0x370/0x46c
<4>[  88.123500][ T2201] pc : prepare_kernel_cred+0x370/0x46c
"""
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
                       "2026-11-12T10:00:00.123456+00:00 buildhost kernel: ", "[Thu Nov 12 10:00:00 2026] ",
                       "Nov 12 10:00:00.123456 buildhost kernel: ",  # journalctl -o short-precise
                       "[  152.334270] buildhost kernel: ",  # journalctl -o short-monotonic
                       "kern  :warn  : [  152.334270] ", "kern  :warn  : ",  # dmesg -x
                       "2026-11-12T10:00:00,123456+02:00 ",  # dmesg --time-format iso
                       "[Nov12 10:00] ", "[  +0.000005] ", "[<    0.000005>] ",  # dmesg -H
                       "[  152.334270 <    0.000005>] ",  # dmesg -d
                       "11-12 10:00:00.123     0     0 W         : ", "11-12 10:00:00.123  0  0 I kernel  : "):  # logcat
            rep = oops.parse(prefix + line)
            self.assertEqual((rep.primary.source, rep.primary.function), ("rip", "mfill_atomic_copy"), prefix)
            # call-trace entries and bare lines are read only when the whole prefix is gone
            rep = oops.parse("%sCall Trace:\n%s <TASK>\n%s ? __warn+0x89/0x130\n%s userfaultfd_ioctl+0x5d1/0x1e70\n" % (
                (prefix,) * 4))
            self.assertEqual([(f.function, f.reliable) for f in rep.frames], [("__warn", False), ("userfaultfd_ioctl", True)],
                             prefix)
            rep = oops.parse(prefix + "mfill_atomic_copy+0x674/0x9d0")
            self.assertEqual((rep.primary.source, rep.primary.offset), ("text", 0x674), prefix)
            rep = oops.parse(prefix + "mm/userfaultfd.c:755")
            self.assertEqual((rep.file, rep.line), ("mm/userfaultfd.c", 755), prefix)
        rep = oops.parse("<4>[  152.334305][  T123]  ? __warn+0x89/0x130")  # an entry without 'Call Trace:' above it
        self.assertEqual([(x.source, x.function, x.reliable) for x in rep.locations], [("text", "__warn", False)])
        self.assertIsNone(rep.primary)  # a '? ' entry (unreliable) is never the one to go to

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

    def test_several_reports(self):
        """A paste with several reports: cut at 'cut here' / 'end trace' / the next WARNING or kernel BUG line / the
        first line of another report after a register dump; the first report with a trap line is used, with a note."""
        poison = X86_WARN.replace("mfill_atomic_copy", "mfill_atomic_poison").replace("0x674/0x9d0", "0x494/0x850")
        rep = oops.parse("[ 10.1] RIP: 0010:mfill_atomic_copy+0x674/0x9d0\n[ 10.2] ---[ end trace 0000000000000000 ]---\n"
                         + poison)  # an oops, then a WARNING report (review s157 mixed.txt)
        self.assertEqual((rep.reports, rep.kind, rep.header, rep.primary.function, rep.frames), (2, "oops", None,
                                                                                               "mfill_atomic_copy", []))
        rep, m = find(X86_WARN + poison)  # two WARNING reports: the first one's WARNING and RIP lines
        self.assertEqual((rep.reports, rep.primary.function, rep.header.function, m.status, m.address),
                         (2, "mfill_atomic_copy", "mfill_atomic_copy", "exact", 0xFFFFFFFF8E629BC4))
        self.assertEqual(len(rep.frames), 10)
        self.assertIn("the text holds 2 reports; the first one with a WARNING / kernel BUG / RIP / pc line is used "
                      "(paste one report to look up another)", m.notes)
        rep = oops.parse(NEW_WARN + "\n" + OLD_WARN_NO_FILE.replace("copy+0x674", "poison+0x494"))  # no cut-here line
        self.assertEqual((rep.reports, rep.primary.offset, rep.file), (2, 0x674, "mm/userfaultfd.c"))
        rep = oops.parse("BUG: KASAN: slab-use-after-free in folio_unlock+0x10/0xd0\nCall Trace:\n dump_stack_lvl+0x7d/0xa0\n"
                         + X86_WARN)  # a KASAN report without a trap line, then a WARNING report: the WARNING one
        self.assertEqual((rep.reports, rep.primary.source, rep.primary.function), (2, "rip", "mfill_atomic_copy"))
        for one in (X86_WARN, X86_BUG, ARM64_BUG, SYZBOT):  # 'Oops:' / 'Internal error:' after the BUG line: one report
            self.assertEqual(oops.parse(one).reports, 1, one[:60])
        self.assertEqual(oops.parse(X86_BUG + X86_WARN).primary.function, "folio_unlock")  # BUG, then a WARNING
        self.assertEqual(oops.parse("mfill_atomic_copy+0x674").reports, 0)  # a bare line is no report
        rep = oops.parse("RIP: 0010:folio_unlock+0x70/0xd0\nCall Trace:\n f+0x1/0x2\nBUG: unable to handle page fault for "
                         "address: 0000000000000008\nRIP: 0010:mfill_atomic_copy+0x674/0x9d0")  # no cut / end line
        self.assertEqual((rep.reports, rep.primary.function, [f.function for f in rep.frames]), (2, "folio_unlock", ["f"]))

    def test_panic_on_warn(self):
        """review s159 NIT 2: 'Kernel panic - not syncing: ...' continues the report in progress (panic_on_warn: the
        panic line and panic()'s stack dump, on x86 with the same trap's RIP again, follow the WARNING report): one
        report, no 'the text holds 2 reports' note. A report that ended (oops, then 'Fatal exception') is still one, and
        two different reports are still two."""
        rep, m = find(POW_X86)
        self.assertEqual((rep.reports, rep.kind, rep.file, rep.line, rep.primary.source, rep.primary.function,
                          rep.primary.offset, rep.primary.size),
                         (1, "WARN", "lib/refcount.c", 28, "rip", "refcount_warn_saturate", 0xBE, 0x110))
        self.assertEqual((m.status, m.address, m.site.where()), ("exact", 0xFFFFFFFF8E8A531E, "lib/refcount.c:28"))
        self.assertFalse([n for n in m.notes if "reports" in n], m.notes)
        # panic()'s dump shows the trap's RIP again inside its call trace, right after the #UD entry frame
        # asm_exc_invalid_op: the trap's own registers (review s163 MINOR 2; s161 MAJOR 2 had made it 'regs')
        self.assertEqual([x.source for x in rep.locations if x.source != "frame"], ["warning", "rip", "rip"])
        rep, m = find(POW_ARM64)  # arm64: the panic's dump prints no pc line
        self.assertEqual((rep.reports, rep.primary.source, m.status, m.address), (1, "pc", "exact", 0xFFFFFFFF8E629BC4))
        self.assertFalse([n for n in m.notes if "reports" in n], m.notes)
        fatal = ("<4>[  222.942500][ T8817] ---[ end trace 0000000000000000 ]---\n"
                 "<0>[  222.942510][ T8817] Kernel panic - not syncing: Fatal exception\n"
                 "<0>[  222.943000][ T8817] Kernel Offset: disabled\n"
                 "<0>[  222.943010][ T8817] ---[ end Kernel panic - not syncing: Fatal exception ]---\n")
        for text in (X86_BUG + fatal, X86_BUG + fatal.split("\n", 1)[1]):  # with and without the end-trace line
            rep, m = find(text)
            self.assertEqual((rep.reports, rep.kind, m.status, m.address), (1, "BUG", "exact", 0xFFFFFFFF81000110))
        # a panic with no report before it is one report (its call trace has no trap: nothing to go to)
        rep = oops.parse("Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)\nCall Trace:\n"
                         " <TASK>\n dump_stack_lvl+0x5d/0x80\n panic+0x118/0x2db\n")
        self.assertEqual((rep.reports, [f.function for f in rep.frames]), (1, ["dump_stack_lvl", "panic"]))
        # two different reports are still two: the second one's cut-here / WARNING line starts it (also with neither
        # the end-panic line nor the cut-here line between them)
        for text, first in ((POW_X86 + X86_WARN, "refcount_warn_saturate"), (X86_WARN + POW_X86, "mfill_atomic_copy"),
                            ("\n".join(POW_X86.splitlines()[:-1] + X86_WARN.splitlines()[1:]), "refcount_warn_saturate")):
            rep, m = find(text)
            self.assertEqual((rep.reports, rep.primary.function, m.status), (2, first, "exact"), text[:80])
            self.assertIn("the text holds 2 reports; the first one with a WARNING / kernel BUG / RIP / pc line is used "
                          "(paste one report to look up another)", m.notes)

    def test_executive_summary(self):
        """review s163 MINOR 1: x86 oops_end() prints the trap's RIP and registers again after the end marker (the
        executive summary, 4.17+): the same report, no 'the text holds 2 reports' note. Another RIP after the end
        marker, or another report, still counts."""
        for text in (X86_BUG + X86_BUG_REST, SYZBOT_BUG):
            rep, m = find(text)
            self.assertEqual((rep.reports, rep.kind, m.status, m.address), (1, "BUG", "exact", 0xFFFFFFFF81000110), text)
            self.assertFalse([n for n in m.notes if "reports" in n], m.notes)
        rep, m = find(X86_BUG + X86_BUG_REST + X86_WARN)  # another report after it: two
        self.assertEqual((rep.reports, rep.primary.function, m.status), (2, "folio_unlock", "exact"))
        rep = oops.parse(X86_BUG + X86_BUG_REST.replace("RIP: 0010:folio_unlock", "RIP: 0010:mfill_atomic_copy+0x674/0x9d0 "
                                                                                   "folio_unlock"))  # not the trap's RIP
        self.assertEqual((rep.reports, rep.primary.function), (2, "folio_unlock"))
        # the summary after a WARNING / kernel BUG line without the trap's RIP line (a partial paste): the same address
        rep = oops.parse("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0\nCall Trace:\n"
                         " userfaultfd_ioctl+0x5d1/0x1e70\n---[ end trace 0000000000000000 ]---\n"
                         "RIP: 0010:mfill_atomic_copy+0x674/0x9d0\n")
        self.assertEqual((rep.reports, rep.primary.source, rep.primary.function), (1, "rip", "mfill_atomic_copy"))

    def test_no_trap_line(self):
        """Reports with no WARNING / kernel BUG / RIP / pc line (KASAN, hung task, lockdep) and pasted call traces: the
        first entry is a caller, so only a BUG/WARN site right there counts; a single bare line is still looked up."""
        for text in ("BUG: KASAN: slab-use-after-free in mfill_atomic_copy+0x674/0x9d0\nCall Trace:\n <TASK>\n"
                     " dump_stack_lvl+0x7d/0xa0\n print_report+0xcf/0x620\n mfill_atomic_copy+0x670/0x9d0\n",
                     "INFO: task kworker/0:1:9 blocked for more than 122 seconds.\nCall Trace:\n <TASK>\n"
                     " __schedule+0x2d1/0x1e70\n schedule+0x27/0x80\n",
                     "WARNING: possible circular locking dependency detected\n-> #1 (&mm->mmap_lock){++++}-{3:3}:\n"
                     "       mfill_atomic_copy+0x670/0x9d0\n       __might_fault+0x58/0x80\n",
                     "[  152.334305]  ? __warn+0x89/0x130\n[  152.334310]  ? mfill_atomic_copy+0x674/0x9d0\n"
                     "[  152.334340]  mfill_atomic_copy+0x670/0x9d0\n[  152.334345]  userfaultfd_ioctl+0x5d1/0x1e70\n"):
            rep, m = find(text)
            self.assertEqual((m.status, m.address, m.candidates), ("none", None, []), text)
            self.assertTrue(m.notes[-1].startswith("no BUG/WARN trap in this report (no WARNING / kernel BUG / RIP / pc "
                                                   "line), and no BUG/WARN site at its first "), m.notes)
            self.assertNotIn("__warn", m.notes[-1])  # a '? ' entry is never used
        rep, m = find("Call Trace:\n mfill_atomic_copy+0x674/0x9d0\n userfaultfd_ioctl+0x5d1/0x1e70")  # a site there
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E629BC4))
        rep, m = find("mfill_atomic_copy+0x670")  # one bare line: the function's sites, as asked
        self.assertEqual((m.status, m.address), ("near", 0xFFFFFFFF8E629BC0))

    def test_registers_not_the_trap(self):
        """review s161 MAJOR 2: a RIP: / pc : line after the report's call trace began (x86 prints an interrupted
        context's registers where the trace crosses an IRQ or exception entry) or after 'NMI backtrace for cpu N'
        (another CPU's registers) is not the report's trap: kept as a 'regs' location, never the one to go to."""
        for text in (KASAN_IRQ, HUNG_NMI, RCU_NMI):
            rep, m = find(text)
            self.assertEqual((rep.kind, m.status, m.address, m.candidates), (None, "none", None, []), text[:80])
            self.assertTrue(m.notes[-1].startswith("no BUG/WARN trap in this report (no WARNING / kernel BUG / RIP / pc "
                                                   "line), and no BUG/WARN site at its first call-trace entry "), m.notes)
            self.assertEqual([(x.function, x.offset) for x in rep.locations if x.source == "regs"],
                             [("mfill_atomic_copy", 0x674)])
            self.assertEqual(m.notes[-2], "not a trap line: RIP: 0010:mfill_atomic_copy+0x674/0x9d0 (after the report's "
                                          "call trace began or in an NMI backtrace: the registers of an interrupted "
                                          "context or of another CPU)")
        rep, m = find(RCU_NMI_ARM64)
        self.assertEqual((rep.primary, m.status, [x.source for x in rep.locations]), (None, "none", ["regs", "lr"]))
        self.assertEqual(m.notes, ["no WARNING / kernel BUG / RIP / pc line, func+0xoff or file:line in the text",
                                   "not a trap line: pc : nft_do_chain+0x400/0x6d0 [nf_tables] (after the report's call "
                                   "trace began or in an NMI backtrace: the registers of an interrupted context or of "
                                   "another CPU)"])
        # the whole arm64 NMI backtrace: arm64 repeats that CPU's pc as the first call-trace entry, which is not taken
        # either (review s163 NIT 2)
        rep, m = find(RCU_NMI_ARM64 + "<4>[  412.110090][    C1] Call trace:\n"
                                      "<4>[  412.110100][    C1]  nft_do_chain+0x400/0x6d0 [nf_tables] (P)\n"
                                      "<4>[  412.110110][    C1]  nft_do_chain_ipv4+0x6c/0xb8 [nf_tables]\n")
        self.assertEqual((m.status, m.address, rep.primary.function), ("none", None, "nft_do_chain_ipv4"))
        self.assertTrue(m.notes[-2].startswith("not a trap line: pc : nft_do_chain+0x400/0x6d0 [nf_tables]"), m.notes)
        # the trap's own RIP comes before the call trace: still used when an interrupt frame's RIP (here on another site)
        # follows in the trace; with the trap's RIP line left out, the WARNING line, not the interrupted code
        irq = X86_WARN.replace("[  152.334340]  userfaultfd_ioctl", "[  152.334336]  asm_sysvec_apic_timer_interrupt+0x1a/0x20\n"
                               "[  152.334337] RIP: 0010:folio_unlock+0x70/0xd0\n"
                               "[  152.334338] RSP: 0018:ffffc90000d4be00 EFLAGS: 00000246\n[  152.334340]  userfaultfd_ioctl")
        for text in (irq, irq.replace("[  152.334270] RIP: 0010:mfill_atomic_copy+0x674/0x9d0\n", "")):
            rep, m = find(text)
            self.assertEqual((rep.reports, m.status, m.address), (1, "exact", 0xFFFFFFFF8E629BC4), (text, m.reason))
        # a WARNING report after an NMI backtrace, no cut-here line between them: two reports, the WARNING one's RIP
        poison = X86_WARN.replace("mfill_atomic_copy", "mfill_atomic_poison").replace("0x674/0x9d0", "0x494/0x850")
        rep, m = find(HUNG_NMI + poison.split("\n", 1)[1])
        self.assertEqual((rep.reports, rep.primary.function, m.status, m.address),
                         (2, "mfill_atomic_poison", "exact", 0xFFFFFFFF8E62B164))
        # Linux 4.9's executive summary 'RIP  [<%p>] %pS' follows the call trace and is the trap's RIP
        rep, m = find(OLD_X86.split("\n", 1)[1] + OLD_SUMMARY)
        self.assertEqual((rep.primary.source, m.status, m.address), ("rip", "exact", 0xFFFFFFFF8E629BC4))

    def test_trap_rip_after_the_trace(self):
        """review s163 MINOR 2: RIP lines the kernel prints after the call trace that are the trap's own: Linux
        4.10-4.16's executive summary 'RIP: %pS RSP: %016lx' (no CS), and a RIP right after the #UD entry frame
        (asm_exc_invalid_op: panic()'s dump crossing the BUG/WARN ud2's exception). On a paste of the bottom of a report
        (the top scrolled away) they are the trap. In an NMI backtrace (another CPU), after an unreliable '? ' entry or
        another entry, a RIP after the call trace is still not (review s161 MAJOR 2)."""
        bottom = X86_414_BUG[X86_414_BUG.index("[  222.942140] Call Trace:"):]
        for text in (X86_414_BUG, bottom):
            rep, m = find(text)
            self.assertEqual((rep.reports, m.status, m.address), (1, "exact", 0xFFFFFFFF81000110), text[:60])
            self.assertFalse([x for x in rep.locations if x.source == "regs"], text[:60])
            self.assertFalse([n for n in m.notes if "not a trap line" in n], m.notes)
        pow_bottom = POW_X86[POW_X86.index("[ 4521.903342] Kernel panic"):]  # panic()'s dump only
        rep, m = find(pow_bottom)
        self.assertEqual((rep.reports, rep.primary.source, m.status, m.address), (1, "rip", "exact", 0xFFFFFFFF8E8A531E))
        nmi_ud = ("INFO: task kworker/u8:3:5123 blocked for more than 143 seconds.\nNMI backtrace for cpu 0\n"
                  "CPU: 0 UID: 0 PID: 4410 Comm: stress Not tainted 6.12.115+deb13.1-amd64 #1\n"
                  "RIP: 0010:folio_unlock+0x10/0xd0\nCall Trace:\n <NMI>\n nmi_cpu_backtrace+0x9d/0x100\n </NMI>\n"
                  " <TASK>\n handle_bug+0x10f/0x170\n exc_invalid_op+0x17/0x70\n asm_exc_invalid_op+0x1a/0x20\n"
                  "RIP: 0010:mfill_atomic_copy+0x674/0x9d0\n </TASK>\n")  # another CPU in a WARN: not this report's
        for text in (pow_bottom.replace("]  asm_exc_invalid_op", "]  ? asm_exc_invalid_op"),
                     pow_bottom.replace("asm_exc_invalid_op", "asm_sysvec_apic_timer_interrupt"), nmi_ud,
                     bottom.replace("RIP: folio_unlock+0x70/0xd0 RSP: ffffc90000d4bd18", "RIP: 0010:folio_unlock+0x70/0xd0")):
            rep, m = find(text)
            self.assertEqual((m.status, m.address), ("none", None), text)
            self.assertIn(("folio_unlock", 0x70) if "folio_unlock+0x70" in text else ("mfill_atomic_copy", 0x674) if
                          "mfill" in text else ("refcount_warn_saturate", 0xBE),
                          [(x.function, x.offset) for x in rep.locations if x.source == "regs"], text)

    def test_trap_rule_resets(self):
        """review s163 NIT 1: where 'after the call trace began' ends. A cut-here / end marker, a report's first line
        and a new report start fresh, so the trap RIP after them counts; a register dump that is not a trap ('regs')
        still lets the next report's first line cut."""
        # the bottom of an x86 oops (from 'Call Trace:'): the executive summary after the end marker is the trap
        rep, m = find(X86_BUG_REST)
        self.assertEqual((rep.reports, rep.primary.source, m.status, m.address), (1, "rip", "exact", 0xFFFFFFFF81000110))
        # a hung task's call trace, then an oops (no cut-here): its 'BUG:' line starts it, its RIP is its trap
        hung_then_oops = ("INFO: task kworker/u8:3:5123 blocked for more than 143 seconds.\nCall Trace:\n <TASK>\n"
                          " __schedule+0x3f0/0xb40\n schedule+0x27/0xf0\n </TASK>\n"
                          "BUG: kernel NULL pointer dereference, address: 0000000000000008\n"
                          "Oops: 0000 [#1] PREEMPT SMP NOPTI\nRIP: 0010:folio_unlock+0x10/0xd0\n")
        rep, m = find(hung_then_oops)
        self.assertEqual((rep.primary.source, rep.primary.function, m.status, m.address),
                         ("rip", "folio_unlock", "near", 0xFFFFFFFF810000B0))
        # a KASAN report from an interrupt (its RIP is an interrupted context's), then an oops: two reports, the oops is
        # used with its own call trace only
        rep, m = find(KASAN_IRQ + "BUG: unable to handle page fault for address: 0000000000000008\n"
                                  "Oops: 0000 [#1] PREEMPT SMP NOPTI\nRIP: 0010:folio_unlock+0x70/0xd0\n")
        self.assertEqual((rep.reports, rep.primary.function, rep.frames, m.status, m.address),
                         (2, "folio_unlock", [], "exact", 0xFFFFFFFF81000110))
        # 'Kernel BUG at %pB' for a BUG at a function's first byte after padding: the previous symbol + its printed
        # size (kallsyms measures to the next symbol), not its code size (review s161 MINOR 1, ae14dc0)
        for text in ("Kernel BUG at pb_prev+0x30/0x30 [verbose debug info unavailable]",
                     "Kernel BUG at pb_prev+0x30/0x30 [verbose debug info unavailable]\nRIP: 0010:pb_next+0x0/0x20"):
            rep, m = find(text)
            self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF81003130), text)

    def test_details(self):
        """Parser details the review's mutants found untested (review s157 m7)."""
        self.assertEqual(oops.parse(X86_WARN.splitlines()[5]).kind, "oops")  # a RIP line alone: an oops
        self.assertEqual(oops.parse("RIP: 0010:mfill_atomic_copy+0x674/0x9D0").primary.size, 0x9D0)  # upper-case hex
        self.assertIsNone(oops.parse("RIP: 0010:0x1234").primary)  # not an address: fewer than 8 hex digits
        self.assertIsNone(oops.parse("mm/userfaultfd.c:755 and more").primary)  # file:line must be the whole line
        rep = oops.parse("Call Trace:\n mm/userfaultfd.c:755\n vfs_ioctl fs/ioctl.c:51\n vfs_ioctl fs/ioctl.c:51 [inline]")
        self.assertEqual([(x.function, x.inline) for x in rep.locations], [("vfs_ioctl", True)])  # only '[inline]' frames
        rep = oops.parse("Call Trace:\n entry_SYSCALL_64_after_hwframe+0x77/0x7f arch/x86/entry/entry_64.S:130\n"
                         " rust_fn+0x10/0x20 rust/kernel/lib.rs:12")  # syzbot: assembly and Rust sources
        self.assertEqual([(f.function, f.file, f.line) for f in rep.frames],
                         [("entry_SYSCALL_64_after_hwframe", "arch/x86/entry/entry_64.S", 130),
                          ("rust_fn", "rust/kernel/lib.rs", 12)])
        rep = oops.parse("vfs_ioctl fs/ioctl.c:51 [inline]\nmfill_atomic_copy+0x674/0x9d0")  # an inlined frame: no address
        self.assertEqual(rep.primary.function, "mfill_atomic_copy")
        rep = oops.parse("lr : folio_unlock+0x70/0xd0\npc : mfill_atomic_copy+0x674/0x9d0")  # lr is a caller
        self.assertEqual(rep.primary.function, "mfill_atomic_copy")
        rep, m = find("Call Trace:\n ? mfill_atomic_copy+0x674/0x9d0\n userfaultfd_ioctl+0x5d1/0x1e70")
        self.assertEqual(m.status, "none")  # the site is only on a '? ' (unreliable) entry
        self.assertFalse(oops.same_file("mm/userfaultfd.c", "faultfd.c"))  # a whole path component
        self.assertEqual(oops.parse("WARNING: at the end of the day").primary, None)  # not __warn()'s
        index = oops.SiteIndex([BugSite(0x10, "a.c", 1, 1), BugSite(0x10, "b.c", 2, 1)])
        self.assertEqual(index.by_addr[0x10].file, "a.c")  # as the kernel's find_bug(): the first entry at an address
        # a 6.19+ x86_64 WARN with a message traps in __WARN_trap (RIP), the WARNING line names the site: its
        # function+offset is tried after the RIP's
        rep, m = find("WARNING: mm/userfaultfd.c:755 at mfill_atomic_copy+0x674/0x9d0, CPU#1: t/9\n"
                      "RIP: 0010:__WARN_trap+0x0/0x10")
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E629BC4))
        # the first function found without a site is the one listed (the RIP's), not the WARNING line's
        rep, m = find("WARNING: CPU: 1 PID: 9 at lib/none.c:1 no_sites_fn+0x20/0x100\nRIP: 0010:mfill_atomic_copy+0x670/0x9d0")
        self.assertEqual((m.status, m.address), ("near", 0xFFFFFFFF8E629BC0))
        for off in (0x80, 0x88):  # no size: only cut_fn.77 is that long (cut_fn and cut_fn.123 end at +0x80)
            rep, m = find("pc : cut_fn+%#x" % off)
            self.assertEqual((m.status, m.address, m.function), ("near", 0xFFFFFFFF81002200 + off, "cut_fn.77"))

    def test_old_and_bare_forms(self):
        """2.6 / 3.x __warn() 'WARNING: at %s:%d %pS()' and report_bug()'s 'Kernel BUG at %p' (a bare address)."""
        rep, m = find("WARNING: at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9d0()")
        self.assertEqual((rep.kind, rep.file, rep.line, rep.primary.function, rep.primary.offset, m.status, m.address),
                         ("WARN", "mm/userfaultfd.c", 755, "mfill_atomic_copy", 0x674, "exact", 0xFFFFFFFF8E629BC4))
        rep, m = find("Kernel BUG at ffffffff81000110 [verbose debug info unavailable]")
        self.assertEqual((rep.kind, rep.primary.address, m.status, m.address), ("BUG", 0xFFFFFFFF81000110, "exact",
                                                                                0xFFFFFFFF81000110))

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

    def test_syzbot_inline_lines(self):
        """review s161 MAJOR 1: syzbot's WARNING / RIP lines repeated for each inlined frame ('func file:line [inline]',
        no address) are one report, not two, and the WARNING line with the function+offset is the report's own."""
        for text in (SYZBOT_INLINE, SYZBOT_INLINE_619):
            rep, m = find(text)
            self.assertEqual((rep.reports, rep.kind, rep.file, rep.line, rep.header.function, rep.header.offset,
                              rep.primary.source, rep.primary.function, rep.primary.offset),
                             (1, "WARN", "mm/userfaultfd.c", 755, "mfill_atomic_copy", 0x674, "rip", "mfill_atomic_copy",
                              0x674), text[:200])
            self.assertEqual((m.status, m.address, m.notes), ("exact", 0xFFFFFFFF8E629BC4, []))
            self.assertEqual(oops.describe(rep, m, lambda ea: "")[0], "from the log: WARNING at mm/userfaultfd.c:755; "
                                                                      "RIP: mfill_atomic_copy+0x674/0x9d0")
            # without its RIP lines: the WARNING line with the function+offset
            rep, m = find("\n".join(ln for ln in text.splitlines() if not ln.startswith("RIP: 0010:")))
            self.assertEqual((rep.reports, rep.primary.source, rep.primary.function, m.status, m.address, m.notes),
                             (1, "warning", "mfill_atomic_copy", "exact", 0xFFFFFFFF8E629BC4, []))
        # only the inlined frame's WARNING line: its file:line, as any WARNING line without a function+offset
        rep, m = find(SYZBOT_INLINE.splitlines()[1])
        self.assertEqual((rep.reports, rep.kind, rep.file, rep.line, m.status, len(m.candidates)),
                         (1, "WARN", "mm/userfaultfd.c", 755, "ambiguous", 4))
        # two such reports, with or without the cut-here line between them, are still two (the first one is used)
        poison = SYZBOT_INLINE.replace("mfill_atomic_copy", "mfill_atomic_poison").replace("0x674/0x9d0", "0x494/0x850")
        for text in (SYZBOT_INLINE + poison, SYZBOT_INLINE + poison.split("\n", 1)[1]):
            rep, m = find(text)
            self.assertEqual((rep.reports, rep.primary.function, m.status, m.address),
                             (2, "mfill_atomic_copy", "exact", 0xFFFFFFFF8E629BC4))

    def test_readme_lines(self):
        """Every WARNING line the README gives as an example to paste finds the demo kernel's site (review s157)."""
        with open(os.path.join(HERE, "..", "README.md"), encoding="utf-8") as fh:
            readme = fh.read()
        lines = [t for t in re.findall(r"`(WARNING: [^`]*)`", readme) + re.findall(r"echo '(WARNING: [^']*)'", readme)
                 if "mfill_atomic_copy" in t]
        self.assertGreaterEqual(len(lines), 3)
        for text in lines:
            rep, m = find(text)
            self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E629BC4), text)

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

    def test_printed_size(self):
        """The log's size is compared with the size the kernel prints (to the next symbol), not only the code size."""
        rep, m = find("RIP: 0010:padded_fn+0x10/0x9d0")
        self.assertEqual((m.status, m.address, m.notes), ("function", 0xFFFFFFFF81000910, []))
        rep, m = find("RIP: 0010:padded_fn+0x10/0x9c3")  # the ELF size, as a log built from the symbol table has it
        self.assertEqual(m.notes, [])
        rep, m = find("RIP: 0010:padded_fn+0x10/0x9e0")
        self.assertEqual(m.notes, ["size in the log 0x9e0, here 0x9d0: another build, or another function of that name"])
        rep, m = find("RIP: 0010:pad_dup+0x10/0x48")
        self.assertEqual((m.function_start, m.notes[0]), (0xFFFFFFFF81001100, "2 functions are named pad_dup; the one "
                                                                               "whose size matches the log's is used"))

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
        # review s161 MINOR 2: past the end, on the next function's site (lib/pad.c:1 right after padded_fn's code, the
        # BUG at switched_to_stop+0x0 right after task_tick_stop): not that site, whatever the line, with or without size
        for text in ("RIP: 0010:padded_fn+0x9c3", "RIP: 0010:padded_fn+0x9c3/0x9d0", "padded_fn+0x9c3/0x...",
                     "WARNING: CPU: 1 PID: 9 at padded_fn+0x9c3/0x9d0", "pc : task_tick_stop+0x8/0x8"):
            rep, m = find(text)
            self.assertEqual((m.status, m.address, m.site), ("none", None, None), (text, m.status))
            p = rep.primary
            self.assertEqual(m.notes, ["%s+%#x is past the end of %s here (%#x bytes): a log from another build?" % (
                p.function, p.offset, p.function, FUNCS[p.function][0].size)])

    def test_mismatch(self):
        """A site at the log's address that the log itself contradicts (its WARNING / kernel BUG line names another
        file:line or kind, or it prints another size): not exact, nothing to go to; the sites at the log's file:line."""
        here = [0xFFFFFFFF8E629BC4]
        # another file:line on the WARNING line: no site at it here, so the site at the address is the one listed
        rep, m = find("WARNING: CPU: 2 PID: 4411 at mm/mmu_notifier.c:848 mfill_atomic_copy+0x674/0x9d0")
        why = ("the WARN site at mfill_atomic_copy+0x674 is at mm/userfaultfd.c:755, but the log's WARNING line says "
               "mm/mmu_notifier.c:848")
        self.assertEqual((m.status, m.address, m.site, [s.addr for s in m.candidates], m.reason, m.label),
                         ("mismatch", None, None, here, why, "mfill_atomic_copy+0x674"))
        self.assertEqual(oops.describe(rep, m, lambda ea: "f")[1:3], [
            "mismatch: %s (a log from another build, or two reports in one paste?); not taken as the match" % why,
            "the 1 BUG/WARN site at mfill_atomic_copy+0x674 in this file:"])
        rec = oops.match_record(rep, m, lambda ea: "")
        self.assertEqual((rec["status"], rec["address"], rec["site"], rec["reason"], rec["notes"]),
                         ("mismatch", None, None, why, []))
        # the offset lands on the BUG at :861, the log says :755: the four sites at :755, mfill_atomic_copy's first
        rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x659/0x9d0")
        self.assertEqual((m.status, m.label, [s.addr for s in m.candidates]),
                         ("mismatch", "mm/userfaultfd.c:755", [a for a, _, _, _ in UFFD]))
        # review s159 MINOR 1: a WARNING line without file:line (no CONFIG_DEBUG_BUGVERBOSE) naming another function+offset
        # than the RIP line (a hand-mixed paste): never exact, no jump
        rep, m = find("WARNING: CPU: 1 PID: 9 at do_one_initcall+0x27c/0x310\nRIP: 0010:mfill_atomic_copy+0x674/0x9d0")
        self.assertEqual((m.status, m.address, m.site), ("mismatch", None, None), (m.status, m.reason))
        self.assertIn("is not the log's WARNING line's do_one_initcall+0x27c", m.reason)
        # the reason names the WARNING line's function+offset, so 'from the log' shows it too (review s161 NIT 2)
        self.assertEqual(oops.describe(rep, m, lambda ea: "")[0], "from the log: WARNING do_one_initcall+0x27c/0x310; "
                                                                  "RIP: mfill_atomic_copy+0x674/0x9d0")
        # header and RIP / pc line agree (the normal report of a kernel without CONFIG_DEBUG_BUGVERBOSE): exact (review
        # s161 MINOR 3: the old check used a function without sites, so a rule that always fired passed it)
        for text, want in (("WARNING: CPU: 1 PID: 9 at mfill_atomic_copy+0x674/0x9d0\nRIP: 0010:mfill_atomic_copy+0x674/0x9d0",
                            0xFFFFFFFF8E629BC4),
                           ("WARNING: at mfill_atomic_copy+0x674/0x9d0, CPU#1: t/9\npc : mfill_atomic_copy+0x674/0x9d0",
                            0xFFFFFFFF8E629BC4),
                           ("Kernel BUG at folio_unlock+0x70/0xd0 [verbose debug info unavailable]\n"
                            "RIP: 0010:folio_unlock+0x70/0xd0", 0xFFFFFFFF81000110)):
            rep, m = find(text)
            self.assertEqual((m.status, m.address, m.reason), ("exact", want, None), text)
        # review s161 MINOR 1: without CONFIG_DEBUG_BUGVERBOSE report_bug() prints 'Kernel BUG at %pB'; %pB looks up
        # addr-1 and prints offset+1, so a BUG at a function's first byte is printed as the previous symbol + its size.
        # It names the same address as the pc / RIP line: exact, also alone
        head = "Kernel BUG at task_tick_stop+0x8/0x8 [verbose debug info unavailable]\n"
        for text in (head + "pc : switched_to_stop+0x0/0x8", head + "RIP: 0010:switched_to_stop+0x0/0x8", head):
            rep, m = find(text)
            self.assertEqual((m.status, m.address, m.site and m.site.where()),
                             ("exact", 0xFFFFFFFF81003008, "kernel/sched/stop_task.c:101"), (text, m.reason))
        rep, m = find("Kernel BUG at task_tick_stop+0x4/0x8 [verbose debug info unavailable]\npc : switched_to_stop+0x0/0x8")
        self.assertEqual((m.status, m.address), ("mismatch", None))  # another address than the pc line's
        rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_poison+0x10/0x850")  # on :900
        self.assertEqual((m.status, [s.addr for s in m.candidates]),
                         ("mismatch", [0xFFFFFFFF8E62B164, 0xFFFFFFFF8E629BC4, 0xFFFFFFFF8E62A489, 0xFFFFFFFF8E62AB60]))
        rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_poison+0x494/0x850")
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E62B164))  # the same site: exact
        rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_poison+0x494/0x850\n"
                      "RIP: 0010:mfill_atomic_copy+0x674/0x9d0")  # RIP from another report: other function, same line
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E629BC4))
        self.assertEqual(oops.describe(rep, m, lambda ea: "")[0], "from the log: WARNING at mm/userfaultfd.c:755 "
                                                                  "mfill_atomic_poison+0x494/0x850; RIP: "
                                                                  "mfill_atomic_copy+0x674/0x9d0")
        # the kind: a kernel BUG line, a WARN site at the address (same file:line)
        rep, m = find("kernel BUG at mm/userfaultfd.c:755!\nRIP: 0010:mfill_atomic_copy+0x674/0x9d0")
        self.assertEqual((m.status, m.reason), ("mismatch", "the site at mfill_atomic_copy+0x674 is a WARN, but the log "
                                                            "reports a BUG"))
        rep, m = find("WARNING: CPU: 1 PID: 9 at mfill_atomic_copy+0x659/0x9d0")  # no file:line, a BUG there
        self.assertEqual((m.status, [s.addr for s in m.candidates]), ("mismatch", [0xFFFFFFFF8E629BA9]))
        rep, m = find("kernel BUG at mm/filemap.c:1499!\nRIP: 0010:0xffffffff8e629bc4")  # an address, no symbol
        self.assertEqual((m.status, m.label, [s.addr for s in m.candidates]),
                         ("mismatch", "mm/filemap.c:1499", [0xFFFFFFFF81000110]))
        # the size: without a WARNING / kernel BUG line to confirm the site, another size means another build
        rep, m = find("RIP: 0010:mfill_atomic_copy+0x674/0x9c0")
        self.assertEqual((m.status, m.reason), ("mismatch", "the log prints mfill_atomic_copy's size as 0x9c0, this "
                                                            "file has 0x9d0"))
        rep, m = find("RIP: 0010:padded_fn+0x10/0x9d0")  # the printed size, not the code size 0x9c3: fine
        self.assertEqual(m.status, "function")
        rep, m = find("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x9c0")  # confirmed
        self.assertEqual((m.status, m.address, m.notes), ("exact", 0xFFFFFFFF8E629BC4, [
            "size in the log 0x9c0, here 0x9d0: another build, but the log's WARNING line names this site"]))
        # file:line only, one site of the other kind
        rep, m = find("WARNING: CPU: 0 PID: 1 at mm/filemap.c:1499 other_build_fn+0x10/0x20")
        self.assertEqual((m.status, m.address, m.reason), ("mismatch", None, "the site at mm/filemap.c:1499 is a BUG, "
                                                                             "but the log reports a WARN"))
        self.assertEqual(find("kernel BUG at mm/filemap.c:1499!")[1].status, "line")
        # the function the log names is not in this file (another build, another file): its file:line's one site is
        # listed, not gone to (review s157 m2)
        for text in ("WARNING: CPU: 0 PID: 1 at lib/cut_c.c:3 missing_fn+0x10/0x20",
                     "WARNING: CPU: 0 PID: 1 at lib/cut_c.c:3 no_sites_fn+0x100/0x200",  # past its end here
                     "kernel BUG at mm/filemap.c:1499!\nRIP: 0010:missing_fn+0x10/0x20"):
            rep, m = find(text)
            fn = text.split()[-1].split("+")[0] if "missing" not in text else "missing_fn"
            self.assertEqual((m.status, m.address, m.site, len(m.candidates)), ("mismatch", None, None, 1), text)
            self.assertTrue(m.reason.startswith("the log's %s+0x" % fn) and "is not in this file, so the one site at "
                            in m.reason, m.reason)

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
        self.assertEqual((m.status, m.address, m.function), ("exact", 0xFFFFFFFF81000444, "lto_fn.cfi"))
        self.assertEqual(m.notes, ["lto_fn in the log is lto_fn.cfi in this file (Clang LTO: the kernel prints the name "
                                   "without the suffix)"])
        self.assertEqual(oops.describe(rep, m, lambda ea: "")[1], "exact: the WARN site at lto_fn.cfi+0x44 (0xffffffff81000444)")
        rep, m = find("pc : lto_fn+0x4/0x8")  # an offset inside the stub: the plain name is used
        self.assertEqual((m.status, m.function_start), ("function", 0xFFFFFFFF81000600))
        rep, m = find("RIP: 0010:0xffffffff8e629bc4")  # no symbol: the address as printed
        self.assertEqual((m.status, m.address), ("exact", 0xFFFFFFFF8E629BC4))
        rep, m = find("RIP: 0010:0xffffffffc0a01234")
        self.assertEqual(m.status, "none")
        self.assertIn("KASLR", m.notes[0])

    def test_lto_names(self):
        """Clang LTO: the kernel prints foo.123 as foo, so every function that the log's foo can be is tried (the plain
        one too); GCC's foo.part.0 is printed in full, so foo+off never means it."""
        for full in ("foo.llvm.12345", "foo.123", "foo.1a2f", "foo.cfi", "foo.cfi_jt", "foo.123.cfi_jt"):
            self.assertTrue(oops.lto_suffix(full, "foo"), full)
        for full in ("foo.part.0", "foo.isra.0", "foo.constprop.0", "foo.cold", "foo.part.0.cold", "foo_bar", "foo",
                     "foobar.1", "foo."):
            self.assertFalse(oops.lto_suffix(full, "foo"), full)
        rep, m = find("pc : cut_fn+0x20/0x80")  # cut_fn and cut_fn.123: both 0x80, both a WARN at +0x20
        self.assertEqual((m.status, m.label, [s.addr for s in m.candidates]),
                         ("ambiguous", "cut_fn+0x20", [0xFFFFFFFF81002020, 0xFFFFFFFF81002120]))
        rep, m = find("pc : cut_fn+0x20/0x90")  # the size picks cut_fn.77
        self.assertEqual((m.status, m.address, m.function), ("exact", 0xFFFFFFFF81002220, "cut_fn.77"))
        self.assertEqual(m.notes, ["cut_fn in the log is cut_fn.77 in this file (Clang LTO: the kernel prints the name "
                                   "without the suffix)"])
        rep, m = find("WARNING: CPU: 0 PID: 0 at lib/cut_b.c:2 cut_fn+0x20/0x80")  # the WARNING's file:line picks one
        self.assertEqual((m.status, m.address, m.function), ("exact", 0xFFFFFFFF81002120, "cut_fn.123"))
        rep, m = find("WARNING: CPU: 0 PID: 0 at lib/cut_a.c:1 cut_fn+0x20/0x80")  # ... also the plain-named one
        self.assertEqual((m.status, m.address, m.function, m.notes), ("exact", 0xFFFFFFFF81002020, "cut_fn", []))
        rep, m = find("pc : cut_fn+0x88/0x90")  # past the plain one's end, in cut_fn.77 (no site there)
        self.assertEqual((m.status, m.function_start, m.function), ("near", 0xFFFFFFFF81002200, "cut_fn.77"))
        self.assertIn("in cut_fn.77, nearest first", oops.describe(rep, m, lambda ea: "")[1])
        # GCC: gcc_fn+0x60 is past the end of gcc_fn (0x40): another build; never gcc_fn.part.0's site at +0x60
        rep, m = find("RIP: 0010:gcc_fn+0x60/0x100")
        self.assertEqual((m.status, m.address, m.site), ("none", None, None))
        self.assertIn("gcc_fn+0x60 is past the end of gcc_fn here (0x40 bytes): a log from another build?", m.notes)
        rep, m = find("RIP: 0010:gcc_fn.part.0+0x60/0x100")  # printed in full: found
        self.assertEqual((m.status, m.address, m.notes), ("exact", 0xFFFFFFFF81002560, []))

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
        self.assertEqual([oops.module_name(p) for p in ("/x/nf_tables.ko", "ext4.ko.xz", "snd-hda-intel.ko.zst", "vmlinux",
                                                        "nf_tables.ko.debug")],
                         ["nf_tables", "ext4", "snd_hda_intel", None, "nf_tables"])
        rep, m = find(SYZBOT)
        rec = json.loads(json.dumps(oops.match_record(rep, m, lambda ea: "mfill_atomic_copy")))
        self.assertEqual((rec["status"], rec["address"], rec["site"]["line"], rec["from"]["offset"], len(rec["frames"])),
                         ("exact", "0xFFFFFFFF8E629BC4", 755, "0x674", 9))


def whole_kernel(path):
    """Every BUG/WARN site inside a function of this file: a RIP (x86_64) or pc (arm64) line built from its function
    and offset resolves to it; and each file:line gives exactly the sites at that line."""
    import bisect
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
    # kallsyms' symbols, for %pB below (mapping symbols and .L labels are not among them; see Elf.printed_size)
    ksyms = sorted(a for a, n in elf.by_addr.items() if not n.startswith(("$", ".L")))
    done = same_name = headed = contradicted = unverbose = 0
    for b in bugs:
        name = elf.func(b.addr)
        if not name or first_at[b.addr] is not b:
            continue
        # the size as the kernel prints it (to the next symbol), as a real log from this build has it
        start, size, printed, _ = next(c for c in elf.function_starts(name) if c[0] <= b.addr < c[0] + c[1])
        at = "%s%s+%#x/%#x%s" % (reg, name, b.addr - start, printed or size, tag)
        rep = oops.parse(at)
        m = oops.resolve(rep, index, elf.function_starts, mod, elf.relocatable)
        several = m.status == "ambiguous"
        if several:  # functions of the same name and size, each with a site at this offset
            assert b in m.candidates and m.label == "%s+%#x" % (name, b.addr - start), (hex(b.addr), m)
            same_name += 1
        else:
            assert (m.status, m.address) == ("exact", b.addr), (hex(b.addr), name, m.status, m.notes)
            assert not m.notes or (elf.relocatable and not tag and len(m.notes) == 1
                                   and "in the kernel image (no [module] after it)" in m.notes[0]), m.notes
        done += 1
        # the report of a kernel without CONFIG_DEBUG_BUGVERBOSE (review s161 MINOR 3): __warn()'s 'WARNING: CPU: %d
        # PID: %d at %pS', or report_bug()'s 'Kernel BUG at %pB [verbose debug info unavailable]', where %pB names the
        # kallsyms symbol of addr-1 with offset+1 (for a BUG at a function's first byte: the previous symbol + its size;
        # the kernel prints a Clang LTO name without its suffix). With the RIP / pc line: exact (among same-named
        # functions: listed); the line alone: exact, or listed among same-named functions
        if b.warn:
            head = "WARNING: CPU: 1 PID: 9 at %s+%#x/%#x%s" % (name, b.addr - start, printed or size, tag)
        else:
            k = ksyms[bisect.bisect_right(ksyms, b.addr - 1) - 1]
            sym = elf.by_addr[k]
            sym = sym.split(".")[0] if oops.lto_suffix(sym, sym.split(".")[0]) else sym
            head = "Kernel BUG at %s+%#x/%#x%s [verbose debug info unavailable]" % (
                sym, b.addr - k, (printed or size) if k == start else elf.printed_size(k) or b.addr - k, tag)
        for text in (head + "\n" + at, head):
            m = oops.resolve(oops.parse(text), index, elf.function_starts, mod, elf.relocatable)
            if several or text == head:
                assert (m.status, m.address) == ("exact", b.addr) or (m.status == "ambiguous" and b in m.candidates), (
                    hex(b.addr), text, m.status, m.reason, m.notes)
            else:
                assert (m.status, m.address) == ("exact", b.addr), (hex(b.addr), text, m.status, m.reason, m.notes)
        unverbose += 1
        if not b.file:
            continue
        # the whole report as this build prints it (its WARNING / kernel BUG line names the site's own file:line and
        # kind): still exact; a line or kind the site does not have (another build, another report): never exact
        for line, warn, ok in ((b.line, b.warn, True), (b.line + 100000, b.warn, False), (b.line, not b.warn, False)):
            head = ("WARNING: CPU: 1 PID: 9 at %s:%d %s+%#x/%#x%s" % (b.file, line, name, b.addr - start, printed or size,
                                                                     tag) if warn else "kernel BUG at %s:%d!" % (b.file, line))
            m = oops.resolve(oops.parse(head + "\n" + at), index, elf.function_starts, mod, elf.relocatable)
            if ok:
                assert m.status in ("exact", "ambiguous") and b in m.candidates, (hex(b.addr), head, m.status, m.notes)
                headed += 1
            elif several and m.status == "ambiguous":  # none of them at the log's line: still only candidates
                assert m.address is None and b in m.candidates, (hex(b.addr), head, m)
            else:
                assert m.status == "mismatch" and m.address is None and m.reason and not [
                    n for n in m.notes if "in the kernel image (no [module] after it)" not in n], (hex(b.addr), head, m)
                contradicted += 1
    # Clang LTO: the kernel prints foo.123 / foo.llvm.123 / foo.cfi as foo; a log of this build has the cut name. Each
    # site in such a function is found from the cut name, alone or with its own WARNING / kernel BUG line, or listed
    # among same-named candidates; never another site
    cut = cut_listed = 0
    for b in bugs:
        name = elf.func(b.addr)
        base = name.split(".")[0] if name else None
        if not name or first_at[b.addr] is not b or not oops.lto_suffix(name, base):
            continue
        start, size, printed, _ = next(c for c in elf.function_starts(name) if c[0] <= b.addr < c[0] + c[1])
        at = "%s%s+%#x/%#x%s" % (reg, base, b.addr - start, printed or size, tag)
        heads = [""] + (["WARNING: CPU: 1 PID: 9 at %s:%d %s+%#x/%#x%s\n" % (b.file, b.line, base, b.addr - start,
                                                                          printed or size, tag) if b.warn else
                         "kernel BUG at %s:%d!\n" % (b.file, b.line)] if b.file else [])
        for head in heads:
            m = oops.resolve(oops.parse(head + at), index, elf.function_starts, mod, elf.relocatable)
            assert (m.status, m.address) == ("exact", b.addr) or (m.status == "ambiguous" and b in m.candidates), (
                hex(b.addr), name, head, m.status, m.address and hex(m.address), m.notes)
            assert m.status != "exact" or m.function == name, (name, m.function)
            cut_listed += m.status == "ambiguous"
        cut += 1
    # a log line at an offset with no site, in functions whose printed size (to the next symbol) is not their ELF size:
    # no size note, as the log of this build prints that size
    padded = 0
    for a, e, name in elf.funcs:
        c = next((c for c in elf.function_starts(name) if c[0] == a), None)
        if padded == 200 or c is None or c[2] is None or c[2] == c[1] or a in index.by_addr or len(elf.function_starts(name)) > 1:
            continue
        m = oops.resolve(oops.parse("%s%s+0x0/%#x%s" % (reg, name, c[2], tag)), index, elf.function_starts, mod, elf.relocatable)
        assert m.status in ("near", "function") and not [n for n in m.notes if "size in the log" in n], (name, m)
        padded += 1
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
        # the panic_on_warn report built on this kernel (review s159 NIT 2): one report, exact, no note
        rep = oops.parse(POW_X86)
        m = oops.resolve(rep, index, elf.function_starts)
        assert (rep.reports, m.status, m.address, m.site.where(), m.notes) == (
            1, "exact", 0xFFFFFFFF8E8A531E, "lib/refcount.c:28", []), (rep.reports, m)
        # a RIP after the call trace began or in an NMI backtrace is not the trap (review s161 MAJOR 2); each lands on
        # mfill_atomic_copy's WARN site here
        for text in (KASAN_IRQ, HUNG_NMI, RCU_NMI):
            m = oops.resolve(oops.parse(text), index, elf.function_starts)
            assert (m.status, m.address) == ("none", None), (text[:80], m)
        # syzbot's inline-expanded WARNING / RIP lines (review s161 MAJOR 1): one report, the line with function+offset
        rep = oops.parse(SYZ_SCHED)
        m = oops.resolve(rep, index, elf.function_starts)
        assert (rep.reports, m.status, m.address, m.site.where(), m.notes) == (
            1, "exact", 0xFFFFFFFF8E30DF4D, "kernel/sched/sched.h:1686", []), (rep.reports, m)
    # logs from other builds (review s157): an Ubuntu 6.8 x86_64 WARNING, an Android 5.10 arm64 one; where this file has
    # a site at that function+offset, it is exact only if it is the site the log's WARNING line names
    other = 0
    for text, want in ((OTHER_BUILD_X86, "mm/mmu_notifier.c:848"), (OTHER_BUILD_ARM64, "lib/refcount.c:25")):
        m = oops.resolve(oops.parse(text), index, elf.function_starts, mod, elf.relocatable)
        assert m.status != "exact" or (m.site.where().endswith(want) and m.site.warn), (want, m)
        other += m.status == "mismatch"
    print("OK oops on %s: %d of %d BUG/WARN sites in functions found from their %sfunc+0xoff/0xsize line (%d of them "
          "among same-named functions: listed as candidates); %d also with the WARNING / Kernel BUG line of a kernel "
          "without CONFIG_DEBUG_BUGVERBOSE (%%pS / %%pB), and from that line alone; %d of them also with their own "
          "WARNING / kernel BUG line, "
          "%d with another line or kind: mismatch; %d in functions with a Clang LTO suffix also from the name the kernel "
          "prints (%d of the lookups listed same-named candidates); %d functions whose printed size is not their ELF size: "
          "no size note; "
          "file:line checked for %d lines; %d logs from another build: mismatch; --oops exit status, output and --json "
          "checked" % (os.path.basename(path), done, len(bugs), reg, same_name, unverbose, headed, contradicted, cut,
                       cut_listed, padded, len(lines), other))


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
            start, size, printed, _ = next(c for c in elf.function_starts(name) if c[0] <= site.addr < c[0] + c[1])
            at = "%s+%#x/%#x%s" % (name, site.addr - start, printed or size, tag)
            head = lambda line: ("[  152.334201] WARNING: CPU: 1 PID: 9 at %s:%d %s\n" % (site.file, line, at) if site.warn
                                 else "[  152.334201] kernel BUG at %s:%d!\n[  152.334230] %s%s\n" % (site.file, line, reg, at))
            code, got = run(head(site.line), "--json", out)
            rec = json.load(open(out))["oops"]
            if rec["status"] == "exact":
                assert code == 0 and "%#x" % site.addr in got.splitlines()[2] and got.splitlines()[1].startswith("exact:"), got
                assert rec["address"] == "0x%X" % site.addr and rec["site"]["line"] == site.line, rec
            else:  # same-named functions with a site at this offset
                assert code == 0 and rec["status"] == "ambiguous" and "0x%X" % site.addr in [c["addr"] for c in rec["candidates"]]
            # the log's own line says another file:line: exit 1, the mismatch printed, no site in the JSON
            code, got = run(head(site.line + 100000), "--json", out)
            rec = json.load(open(out))["oops"]
            assert code == 1 and got.splitlines()[1].startswith("mismatch: the %s site at %s+%#x is at %s, but the log's"
                                                                % ("WARN" if site.warn else "BUG", name,
                                                                   site.addr - start, site.where())), got
            assert (rec["status"], rec["address"], rec["site"]) == ("mismatch", None, None), rec
        code, got = run("hello, world\n")
        assert code == 1 and "no match" in got, got
        for more in (["--list", "warn"], ["--limit", "5"]):  # those are for the table listing, not --oops
            with contextlib.redirect_stderr(io.StringIO()) as err:
                try:
                    cli.main([path, "--oops", log] + more)
                    code = 0
                except SystemExit as e:
                    code = e.code
            assert code == 2 and "--oops cannot be combined with --list or --limit" in err.getvalue(), err.getvalue()
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
