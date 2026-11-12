"""From a pasted kernel log to kflow's BUG/WARN site. No IDA imports here.

parse(text) reads one log line or a whole oops / WARNING / syzbot report; resolve() finds the site it names in
kflow's BUG/WARN site table. The line formats are the kernel's own printk formats:

  kernel/panic.c __warn()          'WARNING: CPU: %d PID: %d at %s:%d %pS' and '... PID: %d at %pS' (up to 6.18);
                                   'WARNING: %s:%d at %pS, CPU#%d: %s/%d' and 'WARNING: at %pS, CPU#%d: %s/%d' (6.19+)
  lib/bug.c report_bug()           'kernel BUG at %s:%u!'; 'Kernel BUG at %pB [verbose debug info unavailable]'
                                   (capital K; '%p', a bare address, up to 4.x); 'kernel BUG at' with a symbol accepted
  arch/x86/kernel/dumpstack.c      'RIP: %04x:%pS' (show_ip); call-trace entries ' %s%pBb', '? ' before unreliable
                                   ones; 4.9: 'RIP: %04lx:[<%016lx>]  [<%p>] %pS', 'RIP  [<%p>] %pS', ' [<%p>] %s%pB'
                                   and (arch/x86/mm/fault.c) 'IP: [<%p>] %pS'
  arch/arm64/kernel/process.c      'pc : %pS', 'lr : %pS' (__show_regs); 4.9: 'PC is at %s', 'LR is at %s'
  arch/arm64/kernel/stacktrace.c   call-trace entries ' %pSb', from 6.x followed by ' (P)', ' (C)'...
  lib/vsprintf.c, kernel/kallsyms.c  %pS / %pB print 'symbol+0xoff/0xsize', then ' [module]' or ' [module buildid]'
                                   for module code, or '0x<address>' when no symbol is known
  kernel/printk/printk.c           prefixes '<%u>', '[%5lu.%06lu]', '[%6s]' (caller T<pid> / C<cpu>), /dev/kmsg
                                   'level,seq,usec,flags;'; also dmesg -T '[Thu Nov 12 10:00:00 2026]', -H
                                   '[Nov12 10:00]' / '[  +0.000005]', -d '[  12.345678 <    0.000005>]', -x
                                   'kern  :warn  : ', --time-format iso; a journal's '<date> <host> kernel:' (journalctl
                                   short, -precise, -iso, -monotonic); logcat -b kernel '11-12 10:00:00.123 0 0 W tag:'

syzbot reports also put the source line after a symbol ('func+0x12/0x34 mm/file.c:12') and print inlined frames
as 'func mm/file.c:12 [inline]', also on the WARNING and RIP lines, which they then repeat with the function+offset
(one report, the line with the function+offset counts). The kernel prints the address of the trap itself for a BUG/WARN (RIP / pc and the
WARNING line), so function + offset is the site's address.
"""
import bisect
import re
from dataclasses import dataclass, field

_SYM = re.compile(r"(?P<fn>[A-Za-z_.$][\w.$]*)\+(?P<off>0x[0-9a-fA-F]+)(?:/(?P<size>0x[0-9a-fA-F]+))?"
                  r"(?:\s+\[(?P<mod>[\w-]+)(?:\s+[0-9a-fA-F]+)?\])?")
_ADDR = re.compile(r"0x(?P<addr>[0-9a-fA-F]{8,16})\b")
_SRC = re.compile(r"\s+(?P<file>[\w./+-]+\.(?:c|h|S|rs)):(?P<line>\d+)")
_BRACKETS = re.compile(r"^(?:\[<[0-9a-fA-F]+>\]\s*)+")  # raw addresses before a symbol (4.9 and older)
_PREFIX = re.compile(
    r"^\s*(?:<\d+>|\d+,\d+,\d+,[^;]*;"
    r"|(?:[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d(?:\.\d+)?|\d{4}-\d\d-\d\d[T ][\d:.,]+(?:[+-]\d\d:?\d\d|Z)?"
    r"|\[\s*\d+\.\d+\])\s+\S+\s+kernel:"  # journalctl (short, -precise, -iso, -monotonic): '<when> <host> kernel:'
    r"|\[\s*\d+\.\d+(?:\s*<\s*\d+\.\d+>)?\]|\[\s*[TC]\d+\]"  # printk time (dmesg -d: '<delta>'), caller id
    r"|\[[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+ [\d:]+ \d{4}\]"  # dmesg -T
    r"|\[[A-Z][a-z]{2}\s*\d+ \d\d:\d\d\]|\[\s*[+<]\s*\d+\.\d+>?\]"  # dmesg -H: '[Nov12 10:00]', '[  +0.000005]'
    r"|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[,.]\d+(?:[+-]\d\d:?\d\d|Z)?"  # dmesg --time-format iso
    r"|(?:kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|local\d)\s*:\s*"
    r"(?:emerg|alert|crit|err|warn|notice|info|debug)\s*:"  # dmesg -x
    r"|\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+\s+\d+\s+\d+\s+[VDIWEFA]\s+[^:]*:)")  # logcat -b kernel
_WARN_OLD = re.compile(r"WARNING: CPU: \d+ PID: \d+ at (?:(?P<file>[^\s:]+):(?P<line>\d+) )?(?P<rest>.*)$")
_WARN_NEW = re.compile(r"WARNING: (?:(?P<file>[^\s:]+):(?P<line>\d+) )?at (?P<rest>.*)$")
_WARN_26 = re.compile(r"WARNING: at (?P<file>[^\s:]+):(?P<line>\d+) (?P<rest>.*)$")  # 2.6 / 3.x: 'WARNING: at %s:%d %pS()'
_BUG_LINE = re.compile(r"[Kk]ernel BUG at (?P<file>[^\s:!]+):(?P<line>\d+)!")
_BUG_SYM = re.compile(r"[Kk]ernel BUG at (?P<rest>.*?)\s*\[verbose debug info unavailable\]")
_RIP = re.compile(r"(?:^|\s)(?P<tag>RIP:?|IP:)\s+(?:(?P<cs>[0-9a-fA-F]{4}):)?(?P<rest>.*)$")
_PC = re.compile(r"(?:^|\s)(?:(?P<reg>pc|lr) : |(?P<old>PC|LR) is at )(?P<rest>.*)$")
_TRACE = re.compile(r"(?:^|\s)Call [Tt]race:")
# lib/nmi_backtrace.c: another CPU's registers and stack follow (hung task, RCU stall, sysrq-l)
_NMI = re.compile(r"(?:^|\s)NMI backtrace for cpu \d+")
_INLINE = re.compile(r"^(?P<fn>[A-Za-z_.$][\w.$]*)\s+(?P<file>[\w./+-]+\.(?:c|h|S|rs)):(?P<line>\d+)\s+\[inline\]$")
# syzbot prints a line whose %pS lies in inlined code once per inlined frame, innermost first, with 'func file:line
# [inline]' in place of the symbol (the rest of the line kept), then once with the function+offset: such a WARNING line
# is the same report's, and the next one has the function+offset
_INLINE_AT = re.compile(r"^[A-Za-z_.$][\w.$]*\s+[\w./+-]+\.(?:c|h|S|rs):\d+\s+\[inline\]")
_FILE_LINE = re.compile(r"^(?P<file>[\w./+-]+\.(?:c|h|S|rs)):(?P<line>\d+)$")
# what may follow a call-trace entry or a bare func+0xoff line: an elided size ('/0x...', as people write it), and on
# arm64 ' (P)', ' (C)', ' (F)'...
_TAIL = re.compile(r"^(?:/\S*)?(?:\s+\([A-Z]+\))?\s*$")
# where one report ends and the next begins: lib/bug.c / kernel/panic.c '------------[ cut here ]------------' and
# '---[ end trace %016llx ]---'; the first line of other reports (KASAN / page fault 'BUG: ...', x86 'Oops: ...', arm64
# 'Unable to handle kernel ...' / 'Internal error: ...', lockdep and others 'WARNING: ...', hung task 'INFO: task ...')
_CUT = re.compile(r"-+\[ cut here \]-+")
_END = re.compile(r"-+\[ end (?:trace|Kernel panic)")
_START = re.compile(r"(?:^|\s)(?:BUG: |Oops(?::| -)|Unable to handle kernel|Internal error:|general protection fault|"
                    r"WARNING: |INFO: task )")
# kernel/panic.c panic() 'Kernel panic - not syncing: %s' continues the report in progress: a report that ended already
# printed its end marker (oops_exit() before panic("Fatal exception")), and panic_on_warn panics inside __warn() before
# the marker, so the panic line and panic()'s own stack dump (on x86 with the same trap's RIP again) follow the WARNING
# report's call trace. It starts a report only where none is in progress, never cuts one
_PANIC = re.compile(r"(?:^|\s)Kernel panic - ")


@dataclass
class Loc:
    """One location in the log. source: 'rip', 'pc', 'lr', 'warning', 'bug', 'frame' (call-trace entry), 'text'
    (a line that is only func+0xoff or file:line) or 'regs' (a RIP / pc line that is not the report's trap: after its
    call trace began, where x86 prints the registers of an interrupted context, or in another CPU's NMI backtrace)."""
    source: str
    function: str = None
    offset: int = None
    size: int = None
    module: str = None
    file: str = None
    line: int = None
    address: int = None  # the log printed an address, no symbol
    reliable: bool = True  # False: a call-trace entry printed with '? '
    inline: bool = False  # syzbot: an inlined frame (no address of its own); a WARNING line printed for one: its
    #                       function is not kept, only the line's own file:line
    text: str = ""  # the log line, prefixes removed

    def symbol(self):
        """'func+0x674/0x9d0 [mod]' as the kernel prints it (or the address)."""
        if self.function is None:
            return "0x%x" % self.address if self.address is not None else None
        s = self.function
        if self.offset is not None:
            s += "+%#x" % self.offset + ("/%#x" % self.size if self.size is not None else "")
        return s + (" [%s]" % self.module if self.module else "")

    def where(self):
        return "%s:%d" % (self.file, self.line) if self.file else None

    def record(self):
        h = lambda v: None if v is None else "0x%x" % v
        return {"source": self.source, "function": self.function, "offset": h(self.offset), "size": h(self.size),
                "module": self.module, "address": h(self.address), "file": self.file, "line": self.line,
                "reliable": self.reliable, "inline": self.inline}


@dataclass
class Report:
    primary: Loc = None  # the location to go to: RIP/pc > WARNING caller > kernel BUG at > a bare line > first frame
    #                      (reliable lines only; a frame or a bare line among others counts only if a site is there)
    header: Loc = None  # the WARNING or kernel BUG line, if any
    kind: str = None  # 'WARN', 'BUG', 'oops' (a RIP/pc line without either), or None
    file: str = None  # file:line the report names (WARNING / kernel BUG line, else the primary's own)
    line: int = None
    frames: list = field(default_factory=list)  # call-trace entries in order, '? ' ones with reliable=False
    locations: list = field(default_factory=list)  # every location found in that report, in the order of the text
    reports: int = 0  # how many reports the text holds (the first one with a WARNING / kernel BUG / RIP / pc is used)


def strip_prefix(line):
    """The log line without syslog level, /dev/kmsg header, timestamp, caller id or journal prefix."""
    s = line.rstrip("\r\n")
    while True:
        m = _PREFIX.match(s)
        if not m or not m.end():
            return s.strip()
        s = s[m.end():]


def _loc(source, rest, text, whole=False):
    """The %pS location at the start of rest: 'func+0xoff/0xsize [mod]', then syzbot's ' file:line', or '0x<addr>'.
    whole: nothing else may follow (call-trace entries and bare lines). None if rest does not start with one."""
    rest = _BRACKETS.sub("", rest.strip())
    m = _SYM.match(rest)
    if m:
        loc = Loc(source, m.group("fn"), int(m.group("off"), 16), int(m.group("size"), 16) if m.group("size") else None,
                  m.group("mod"), text=text)
    else:
        m = _ADDR.match(rest)
        if not m:
            return None
        loc = Loc(source, address=int(m.group("addr"), 16), text=text)
    end = m.end()
    s = _SRC.match(rest, end)
    if s:
        loc.file, loc.line = s.group("file"), int(s.group("line"))
        end = s.end()
    if whole and not _TAIL.match(rest[end:]):
        return None
    return loc


def parse(text):
    """Every location in the pasted text (one line or a whole report) and the one to go to: see Report. A text with
    several reports is cut into them and the first one with a WARNING / kernel BUG / RIP / pc line is used (a later
    report's RIP is not mixed with an earlier one's WARNING line)."""
    rep = Report()
    in_trace = False
    # the report's own RIP / pc line comes before its call trace; one after 'Call Trace:' (x86 show_regs_if_on_stack: the
    # interrupted context where the trace crosses an IRQ or exception entry; panic()'s dump) or after 'NMI backtrace for
    # cpu N' (another CPU) is not its trap (review s161 MAJOR 2). Linux 4.9's 'RIP  [<%p>] %pS' after the call trace is
    # the trap's executive summary. Cleared where a report starts
    others = False
    segs, closed = [[]], False
    trap = lambda seg: any(x.source in ("warning", "bug", "rip", "pc") for x in seg)
    started = [False]  # per segment: a report's first line was seen
    for raw in (text or "").splitlines():
        s = strip_prefix(raw)
        if not s:
            continue
        if _CUT.search(s) or _END.search(s):
            if segs[-1] or started[-1]:
                segs.append([])
                started.append(bool(_CUT.search(s)))
            in_trace = others = False
            continue
        found = None
        m = _WARN_OLD.search(s) or _WARN_26.search(s) or _WARN_NEW.search(s)
        if m:
            if _INLINE_AT.match(m.group("rest").strip()):  # syzbot: an inlined frame of the trap (review s161 MAJOR 1)
                found = Loc("warning", inline=True, text=s)
            else:
                found = _loc("warning", m.group("rest"), s) or Loc("warning", text=s)
            if m.group("file"):
                found.file, found.line = m.group("file"), int(m.group("line"))
            if found.function is None and found.file is None:
                found = None  # 'WARNING: possible circular locking dependency detected' and other non-__warn lines
        if found is None:
            m = _BUG_LINE.search(s)
            if m:
                found = Loc("bug", file=m.group("file"), line=int(m.group("line")), text=s)
            else:
                m = _BUG_SYM.search(s)
                found = _loc("bug", m.group("rest"), s) if m else None
                if m and found is None and re.fullmatch(r"[0-9a-fA-F]{8,16}", m.group("rest")):  # '%p' (4.x)
                    found = Loc("bug", address=int(m.group("rest"), 16), text=s)
        if found is None:
            m = _RIP.search(s)
            if m:
                found = _loc("rip", m.group("rest"), s)
                if found is not None and m.group("cs") and int(m.group("cs"), 16) & 3:
                    found = None  # 'RIP: 0033:0x7f...': user mode
                if found is not None and others and m.group("tag") != "RIP":  # 'RIP  [<%p>]' (4.9): the summary
                    found.source = "regs"
        if found is None:
            m = _PC.search(s)
            if m:
                found = _loc("pc" if (m.group("reg") or m.group("old")).lower() == "pc" else "lr", m.group("rest"), s)
                if found is not None and others and found.source == "pc":
                    found.source = "regs"
        if found is None and _TRACE.search(s):
            in_trace = others = True
            continue
        if found is None and _NMI.search(s):
            others = True
        if found is None:
            q = re.match(r"^(?:\[<[0-9a-fA-F]+>\]\s*)*(\?\s+)?(.*)$", s)
            body = q.group(2)
            found = _loc("frame" if in_trace else "text", body, s, whole=True)
            if found is None:
                im = _INLINE.match(body)
                if im:
                    found = Loc("frame" if in_trace else "text", im.group("fn"), file=im.group("file"),
                                line=int(im.group("line")), inline=True, text=s)
            if found is None and not in_trace:
                fm = _FILE_LINE.match(body)
                if fm:
                    found = Loc("text", file=fm.group("file"), line=int(fm.group("line")), text=s)
            if found is not None and q.group(1):
                found.reliable = False
        header = found is not None and found.source in ("warning", "bug")
        # a WARNING line after syzbot's inline-expanded one(s) of the same trap continues that report; a register dump
        # that is not a trap ('regs') still ends one
        if (header and any(x.source in ("warning", "bug", "rip", "pc", "regs") and not x.inline for x in segs[-1])) or (
                not header and _START.search(s) and any(x.source in ("rip", "pc", "regs") for x in segs[-1])):  # the next
            segs.append([])
            started.append(True)
            in_trace = others = False
        elif _START.search(s) or _PANIC.search(s):
            started[-1] = True
        if header or _START.search(s):  # a report's first line (not 'Kernel panic -': panic()'s dump follows)
            others = False
        if found is None:
            continue
        segs[-1].append(found)
    reports = [seg for seg, st in zip(segs, started) if seg and (st or trap(seg))]
    rep.reports = len(reports)
    rep.locations = next((seg for seg in reports if trap(seg)), None) or next((seg for seg in segs if seg), [])
    rep.frames = [x for x in rep.locations if x.source == "frame"]
    locs = rep.locations
    first = lambda pred: next((x for x in locs if pred(x)), None)
    rep.header = first(lambda x: x.source in ("warning", "bug") and not x.inline) or first(
        lambda x: x.source in ("warning", "bug"))
    rep.kind = {"warning": "WARN", "bug": "BUG"}.get(rep.header.source) if rep.header else None
    addressable = lambda x: x.offset is not None or x.address is not None
    rep.primary = (first(lambda x: x.source in ("rip", "pc") and addressable(x))
                   or first(lambda x: x.source == "warning" and addressable(x))
                   or first(lambda x: x.source == "bug")
                   or first(lambda x: x.source == "warning")
                   or first(lambda x: x.source == "text" and not x.inline and x.reliable)
                   or first(lambda x: x.source == "frame" and x.reliable and addressable(x)))
    if rep.kind is None and rep.primary is not None and rep.primary.source in ("rip", "pc"):
        rep.kind = "oops"
    src = rep.header if rep.header is not None and rep.header.file else rep.primary
    if src is not None and src.file:
        rep.file, rep.line = src.file, src.line
    return rep


def same_file(a, b):
    """mm/userfaultfd.c matches mm/userfaultfd.c, userfaultfd.c, ./mm/userfaultfd.c and /build/linux/mm/userfaultfd.c."""
    if not a or not b:
        return False
    a, b = (x[2:] if x.startswith("./") else x for x in (a, b))
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def module_name(path):
    """The kernel's name for a module file (nf_tables.ko.xz -> nf_tables, also nf_tables.ko.debug as Fedora / RHEL
    debuginfo packages name it; '-' becomes '_'), None for anything else."""
    base = re.split(r"[\\/]", path or "")[-1]
    m = re.match(r"^(.+)\.ko(?:\.(?:xz|gz|zst|debug))?$", base)
    return m.group(1).replace("-", "_") if m else None


class SiteIndex:
    """kflow's BUG/WARN sites by address (build it once to resolve many reports against the same file)."""

    def __init__(self, sites):
        self.sites = sorted(sites, key=lambda s: s.addr)
        self.addrs = [s.addr for s in self.sites]
        self.by_addr, self.by_line = {}, {}
        for s in self.sites:
            self.by_addr.setdefault(s.addr, s)
            self.by_line.setdefault(s.line, []).append(s)

    def between(self, lo, hi):
        return self.sites[bisect.bisect_left(self.addrs, lo):bisect.bisect_left(self.addrs, hi)]

    def at_line(self, file, line):
        return [s for s in self.by_line.get(line, []) if same_file(s.file, file)]


@dataclass
class Match:
    """status: 'exact' (a site at the log's address), 'near' (no site there; candidates = the sites in that function,
    those at the log's file:line first, then nearest first; when the offset is past the end of the function in this
    file there is no address and they are in address order), 'function' (the function has no site), 'line' (no
    function+offset; one site at file:line), 'ambiguous' (no usable function+offset; several sites at file:line),
    'mismatch' (a site is at the log's address, but the log itself says it is another one: its WARNING / kernel BUG
    line names another file:line or kind, or it prints another function size; a log from another build, or two
    reports in one paste; candidates = the sites at the log's file:line, else that site; nothing to go to) or 'none'.
    address: where to go (the log's address for exact/near/function, the site for line), else None.
    site: the site found (exact, line), else None.
    label: what the candidates of 'line' / 'ambiguous' / 'mismatch' share ('mm/userfaultfd.c:755', or 'func+0x10' when
    functions of the same name each have a site there).
    reason: for 'mismatch', why the site at the log's address is not the one the log names.
    function: the full name of the function used in this file (foo.123 for the log's foo on a Clang LTO kernel)."""
    status: str
    address: int = None
    site: object = None
    candidates: list = field(default_factory=list)
    loc: Loc = None
    function_start: int = None
    notes: list = field(default_factory=list)
    label: str = None
    reason: str = None
    function: str = None


@dataclass(frozen=True)
class Func:
    """A function of the file being looked at. size: its code size (ELF st_size, IDA's function), None if not known
    (a symbol that is not a function). printed: the size the kernel prints after the '/' for it, None if not known:
    kallsyms measures to the next symbol, so alignment padding (and a __pfx_ symbol after it) counts, and on real logs
    it is often larger than size. name: its full name, None if not known."""
    start: int
    size: int = None
    printed: int = None
    name: str = None


def _func(c):
    """A Func from what symbols() returns: a Func, or a tuple (start, size[, printed[, name]]). A size of 0 (a label
    the symbol table calls a function, sharing its address with the next one) is not known."""
    f = c if isinstance(c, Func) else Func(*c)
    return f if f.size != 0 else Func(f.start, None, f.printed, f.name)


def _same_size(f, size):
    """The log's size is this function's: the size the kernel prints for it, or its code size."""
    return size is not None and size in (f.printed, f.size)


# the suffixes Clang LTO adds to a local function's name, which the kernel's kallsyms leaves out when it prints the
# name (cut at the first dot): foo.llvm.123, foo.123 (also hex), foo.cfi, foo.cfi_jt. GCC's .part.N, .isra.N,
# .constprop.N and .cold are printed in full, so foo+0x10 never means foo.part.0.
_LTO_SUFFIX = re.compile(r"^(?:\.(?:llvm\.[0-9a-f]+|[0-9a-f]+|cfi|cfi_jt))+$")


def lto_suffix(full, name):
    """full is name plus suffixes that Clang LTO adds and the kernel does not print."""
    return full.startswith(name + ".") and bool(_LTO_SUFFIX.match(full[len(name):]))


def _starts(loc, symbols):
    """([Func] that may be loc's function, how many functions have that name). Every function that holds the offset:
    the ones of exactly that name and those whose name only adds a Clang LTO suffix (lto_suffix; the kernel prints
    foo.123 and foo as foo), only those whose size is the log's if any is. When none holds the offset (a log from
    another build), the ones of exactly that name (else the suffixed ones), to list their sites."""
    exact = [_func(c) for c in symbols(loc.function) or []]
    seen = {f.start for f in exact}
    lto = [f for f in map(_func, symbols(loc.function, True) or [])
           if f.start not in seen and (f.name is None or lto_suffix(f.name, loc.function))]
    inside = [f for f in exact + lto if f.size is None or loc.offset < f.size]
    if not inside:
        return exact or lto, len(exact or lto)
    return [f for f in inside if _same_size(f, loc.size)] or inside, len(inside)


def _used(loc, func):
    """A note when the function used is not named exactly as the log prints it (Clang LTO suffixes)."""
    if func.name and func.name != loc.function:
        return ["%s in the log is %s in this file (Clang LTO: the kernel prints the name without the suffix)" % (
            loc.function, func.name)]
    return []


def _kind(site):
    return "WARN" if site.warn else "BUG"


def confirms(report, site):
    """The log's WARNING / kernel BUG line names this very site: its file:line (the same build prints the site's own)
    and its kind."""
    h = report.header
    return (h is not None and h.file is not None and site.file is not None and report.kind == _kind(site)
            and site.line == h.line and same_file(site.file, h.file))


def _named(name, symbols):
    """[Func] the log's name can be in this file: that name, and that name with a Clang LTO suffix (see _starts)."""
    exact = [_func(c) for c in symbols(name) or []]
    return exact + [f for f in map(_func, symbols(name, True) or []) if f.name is None or lto_suffix(f.name, name)]


def _contradicts(report, site, loc, func=None, symbols=None):
    """Why the site at the log's address cannot be the one the log names, or None. The same build prints the bug
    entry's own file:line and kind on the WARNING / kernel BUG line, and the function's size after the '/'. A WARNING /
    kernel BUG line without file:line contradicts the site only if its function+offset is another address: report_bug()
    prints 'Kernel BUG at %pB', which looks up addr-1 and prints offset+1, so a BUG at a function's first byte is
    printed as the previous symbol + its size (review s161 MINOR 1)."""
    h = report.header
    at = "%s+%#x" % (loc.function, loc.offset) if loc.function is not None else "0x%x" % loc.address
    if h is not None and h.file and site.file and not (site.line == h.line and same_file(site.file, h.file)):
        return "the %s site at %s is at %s, but the log's %s line says %s:%d" % (
            _kind(site), at, site.where(), "WARNING" if report.kind == "WARN" else "kernel BUG", h.file, h.line)
    if report.kind in ("WARN", "BUG") and report.kind != _kind(site):
        return "the site at %s is a %s, but the log reports a %s" % (at, _kind(site), report.kind)
    if h is not None and not h.file and h is not loc and h.function is not None and h.offset is not None and loc.function is not None \
            and (h.function, h.offset) != (loc.function, loc.offset) \
            and not (symbols and any(f.start + h.offset == site.addr for f in _named(h.function, symbols))):
        # review s159 MINOR 1: a header without file:line naming another address (a hand-mixed paste)
        return "the site at %s is not the log's %s line's %s+%#x" % (
            at, "WARNING" if report.kind == "WARN" else "kernel BUG", h.function, h.offset)
    if func is not None and loc.size is not None and func.size is not None and not _same_size(func, loc.size) \
            and not confirms(report, site):
        return "the log prints %s's size as %#x, this file has %#x" % (loc.function, loc.size, func.printed or func.size)
    return None


def _mismatch(report, index, site, loc, func, notes, why, symbols):
    """A 'mismatch': the sites at the log's own file:line (those in a function of the log's name first), else the
    site at the log's address; nothing to go to."""
    h = report.header
    cands, label = [], None
    if h is not None and h.file:
        label = "%s:%d" % (h.file, h.line)
        spans = [(f.start, f.start + f.size) for f in map(_func, symbols(loc.function) or []) if f.size] \
            if loc.function else []
        cands = sorted(index.at_line(h.file, h.line), key=lambda s: not any(a <= s.addr < e for a, e in spans))
    if not cands:
        cands, label = [site], ("%s+%#x" % (loc.function, loc.offset) if loc.function is not None else
                                "0x%x" % loc.address)
    return Match("mismatch", None, None, cands, loc, func.start if func else None, notes, label, why,
                 func.name or loc.function if func else None)


def resolve(report, sites, symbols, module=None, is_module=False):
    """Find the BUG/WARN site the report names.

    sites: kflow's BugSite list (addr, file, line, warn) or a SiteIndex of it.
    symbols(name, suffixed=False) -> [Func, or a tuple (start, size[, printed size[, name]])]: the functions of that
    name in the file being looked at (several for static functions that share a name); with suffixed=True the ones
    named name.<suffix>.
    module: the module name of that file (module_name()), is_module: the file is a module (else vmlinux); both only
    for the notes."""
    loc = report.primary
    if loc is None:
        return Match("none", notes=["no WARNING / kernel BUG / RIP / pc line, func+0xoff or file:line in the text"]
                     + not_traps(report))
    m = _resolve(report, sites, symbols, module, is_module)
    if report.reports > 1:
        m.notes.append("the text holds %d reports; the first one with a WARNING / kernel BUG / RIP / pc line is used "
                       "(paste one report to look up another)" % report.reports)
    if loc.source in ("frame", "text") and len(report.locations) > 1 and m.status not in ("exact", "ambiguous"):
        # a call trace or a list of lines (KASAN, lockdep, hung task...): its first entry is a caller, not a trap
        return Match("none", loc=loc, notes=m.notes + not_traps(report) + [
            "no BUG/WARN trap in this report (no WARNING / kernel BUG / RIP / pc line), and no BUG/WARN site at its "
            "first %s %s" % ("call-trace entry" if loc.source == "frame" else "line", loc.symbol() or loc.where())])
    return m


def not_traps(report):
    """A note on the report's RIP / pc lines that are not its trap ('regs'), if it has any."""
    regs = [x for x in report.locations if x.source == "regs"]
    if not regs:
        return []
    return ["not a trap line: %s (after the report's call trace began or in an NMI backtrace: the registers of an "
            "interrupted context or of another CPU)%s" % (regs[0].text, "; %d more such lines" % (len(regs) - 1)
                                                          if len(regs) > 1 else "")]


def _resolve(report, sites, symbols, module=None, is_module=False):
    loc = report.primary
    index = sites if isinstance(sites, SiteIndex) else SiteIndex(sites)
    by_addr = index.by_addr
    notes = []
    if loc.module and loc.module != module:
        notes.append("the log puts %s in module %s; this file is %s" % (
            loc.function or "it", loc.module, ("module " + module) if is_module and module else
            "a module" if is_module else "not that module (vmlinux?): open %s.ko" % loc.module))
    elif is_module and not loc.module and loc.function:
        notes.append("the log puts %s in the kernel image (no [module] after it), and this file is a module" % loc.function)
    want_file, want_line = report.file, report.line
    tries = [loc] + [x for x in (report.header,) if x is not None and x is not loc and x.function and x.offset is not None
                     and (x.function, x.offset) != (loc.function, loc.offset)]
    found_fn = None
    for cur in tries:
        if cur.function is not None and cur.offset is not None:
            starts, count = _starts(cur, symbols)
            if not starts:
                notes.append("no function %s in this file" % cur.function)
                continue
            # inside the function as this file has it, not on the next one's site (review s161 MINOR 2); a lone 'Kernel
            # BUG at %pB' names a trap at a function's first byte as the previous symbol + its size (see _contradicts)
            hits = [f for f in starts if f.start + cur.offset in by_addr and (
                f.size is None or cur.offset < f.size or (cur.source == "bug" and cur.offset in (f.size, f.printed)))]
            if len(hits) > 1 and want_file:  # static functions of the same name, each with a site at this offset
                hits = [f for f in hits if by_addr[f.start + cur.offset].line == want_line
                        and same_file(by_addr[f.start + cur.offset].file, want_file)] or hits
            if len(hits) > 1:
                return Match("ambiguous", None, None, [by_addr[f.start + cur.offset] for f in hits], cur, None, notes,
                             "%s+%#x" % (cur.function, cur.offset))
            if hits:
                a = hits[0].start + cur.offset
                notes += _used(cur, hits[0])
                bad = _contradicts(report, by_addr[a], cur, hits[0], symbols)
                if bad:
                    return _mismatch(report, index, by_addr[a], cur, hits[0], notes, bad, symbols)
                if cur.size is not None and hits[0].size is not None and not _same_size(hits[0], cur.size):
                    notes.append("size in the log %#x, here %#x: another build, but the log's %s line names this "
                                 "site" % (cur.size, hits[0].printed or hits[0].size,
                                           "WARNING" if report.kind == "WARN" else "kernel BUG"))
                return Match("exact", a, by_addr[a], [by_addr[a]], cur, hits[0].start, notes,
                             function=hits[0].name or cur.function)
            if found_fn is None:
                found_fn = (cur, starts[0], count)
        elif cur.address is not None:
            if cur.address in by_addr:
                bad = _contradicts(report, by_addr[cur.address], cur)
                if bad:
                    return _mismatch(report, index, by_addr[cur.address], cur, None, notes, bad, symbols)
                return Match("exact", cur.address, by_addr[cur.address], [by_addr[cur.address]], cur, None, notes)
            notes.append("the log has only the address 0x%x (no symbol), and no BUG/WARN site is there (with KASLR "
                         "the running kernel's addresses differ from the file's)" % cur.address)
    if found_fn is not None:
        cur, f, count = found_fn
        st, sz = f.start, f.size
        a = st + cur.offset
        notes += _used(cur, f)
        if count > 1:
            notes.append("%d functions are named %s; the one%s is used" % (
                count, cur.function, " whose size matches the log's" if _same_size(f, cur.size) else " found first"))
        if cur.size is not None and sz is not None and not _same_size(f, cur.size):
            notes.append("size in the log %#x, here %#x: another build, or another function of that name" % (
                cur.size, f.printed or sz))
        # the function as this file has it (the log's size is another build's when they differ)
        span = sz or cur.size
        at_line = lambda s: s.line == want_line and same_file(s.file, want_file)
        inside = index.between(st, st + span) if span else []
        if sz and cur.offset >= sz:  # no address of this function: list its sites, go nowhere
            notes.append("%s+%#x is past the end of %s here (%#x bytes): a log from another build?" % (
                cur.function, cur.offset, f.name or cur.function, sz))
            if inside:
                return Match("near", None, None, sorted(inside, key=lambda s: (not at_line(s), s.addr)), cur, st, notes,
                             function=f.name or cur.function)
        else:
            inside = sorted(inside, key=lambda s: (not at_line(s), abs(s.addr - a)))
            return Match("near" if inside else "function", a, None, inside, cur, st, notes,
                         function=f.name or cur.function)
    if want_file and want_line is not None:
        cands = index.at_line(want_file, want_line)
        label = "%s:%d" % (want_file, want_line)
        named = next((t for t in tries if t.function is not None and t.offset is not None), None)
        if len(cands) == 1:
            if report.kind in ("WARN", "BUG") and report.kind != _kind(cands[0]):
                why = "the site at %s is a %s, but the log reports a %s" % (label, _kind(cands[0]), report.kind)
                return Match("mismatch", None, None, cands, loc, None, notes, label, why)
            if named is not None:  # the function the log names is not here: that line's site may be another one
                why = "the log's %s+%#x is not in this file, so the one site at %s may be another one" % (
                    named.function, named.offset, label)
                return Match("mismatch", None, None, cands, loc, None, notes, label, why)
            return Match("line", cands[0].addr, cands[0], cands, loc, None, notes, label)
        if cands:
            return Match("ambiguous", None, None, cands, loc, None, notes, label)
        notes.append("no BUG/WARN site at %s:%d in this file" % (want_file, want_line))
    return Match("none", loc=loc, notes=notes)


def site_row(s, func_of):
    """One line per site, as python3 -m kflow --list warn prints it."""
    return "%#x %-5s %-40s %s" % (s.addr, "WARN" if s.warn else "BUG", func_of(s.addr) or "?", s.where() or "")


def describe(report, match, func_of):
    """The lines to show for a match (the command line prints them, the plugin writes them to the Output window).
    func_of(ea) -> function name or ''."""
    out = []
    loc = match.loc or report.primary
    if loc is not None:
        what = []
        h = report.header
        if h is not None:
            what.append(("WARNING" if report.kind == "WARN" else "kernel BUG") +
                        (" at %s:%d" % (report.file, report.line) if report.file else ""))
            if h is not loc and h.function is not None and (h.function, h.offset) != (loc.function, loc.offset):
                what[-1] += " " + h.symbol()  # another function+offset than the line used (review s161 NIT 2)
        if loc.function is not None or loc.address is not None:
            label = {"rip": "RIP: ", "pc": "pc : ", "frame": "call trace: "}.get(loc.source, "")
            if loc is report.header:
                what[-1] += " " + loc.symbol()
            else:
                what.append(label + loc.symbol())
        elif not what and loc.file:
            what.append("%s:%d (no function+offset)" % (loc.file, loc.line))
        out.append("from the log: " + "; ".join(what))
    rows = lambda items: ["  " + site_row(s, func_of) for s in items]
    st = match.status
    fn = match.function or loc.function if loc is not None else None
    if st == "exact":
        out.append("exact: the %s site at %s (%#x)" % ("WARN" if match.site.warn else "BUG",
                                                         "%s+%#x" % (fn, loc.offset) if loc.function else
                                                         "the log's address", match.address))
        out += rows([match.site])
    elif st == "near":
        same = sum(1 for s in match.candidates if s.line == report.line and same_file(s.file, report.file))
        n = len(match.candidates)
        if match.address is None:
            out.append("not exact: %s+%#x is past the end of %s in this file; the %d site%s in %s, %sin address order:"
                       % (fn, loc.offset, fn, n, "" if n == 1 else "s", fn,
                          "those at %s:%d first, then " % (report.file, report.line) if same else ""))
            out += rows(match.candidates[:10])
        else:
            out.append("not exact: no BUG/WARN site at %s+%#x (%#x); the %d site%s in %s, %snearest first:"
                       % (fn, loc.offset, match.address, n, "" if n == 1 else "s", fn,
                          "those at %s:%d first, then " % (report.file, report.line) if same else ""))
            out += ["%s  (%+#x)" % (r, s.addr - match.address) for r, s in zip(rows(match.candidates[:10]), match.candidates)]
        if len(match.candidates) > 10:
            out.append("  ... %d more" % (len(match.candidates) - 10))
    elif st == "function":
        out.append("not a BUG/WARN site: %s+%#x (%#x) is in a function without one (an oops, not a BUG/WARN trap?)"
                   % (fn, loc.offset, match.address))
    elif st == "mismatch":
        out.append("mismatch: %s (a log from another build, or two reports in one paste?); not taken as the match"
                   % match.reason)
        n = len(match.candidates)
        out.append("the %d BUG/WARN site%s at %s in this file:" % (n, "" if n == 1 else "s", match.label))
        out += rows(match.candidates[:10])
        if n > 10:
            out.append("  ... %d more" % (n - 10))
    elif st == "line":
        out.append("one BUG/WARN site at %s:" % match.label)
        out += rows(match.candidates)
    elif st == "ambiguous":
        out.append("ambiguous: %d BUG/WARN sites at %s; %s:" % (
            len(match.candidates), match.label, "the function+offset of the RIP: / pc : / WARNING line picks one"
            if ":" in match.label else "functions of this name"))
        out += rows(match.candidates)
    else:
        out.append("no match")
    out += ["note: " + n for n in match.notes]
    return out


def match_record(report, match, func_of):
    """--json: the match as plain data (addresses as hex strings)."""
    h = lambda v: None if v is None else "0x%X" % v
    site = lambda s: {"addr": h(s.addr), "kind": "WARN" if s.warn else "BUG", "function": func_of(s.addr) or None,
                      "file": s.file, "line": s.line}
    return {"status": match.status, "address": h(match.address), "site": site(match.site) if match.site else None,
            "candidates": [site(s) for s in match.candidates], "label": match.label, "reason": match.reason,
            "function": match.function,
            "from": match.loc.record() if match.loc else None,
            "report": {"kind": report.kind, "file": report.file, "line": report.line},
            "frames": [f.record() for f in report.frames], "notes": list(match.notes)}
