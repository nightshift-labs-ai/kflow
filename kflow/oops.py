"""From a pasted kernel log to kflow's BUG/WARN site. No IDA imports here.

parse(text) reads one log line or a whole oops / WARNING / syzbot report; resolve() finds the site it names in
kflow's BUG/WARN site table. The line formats are the kernel's own printk formats:

  kernel/panic.c __warn()          'WARNING: CPU: %d PID: %d at %s:%d %pS' and '... PID: %d at %pS' (up to 6.18);
                                   'WARNING: %s:%d at %pS, CPU#%d: %s/%d' and 'WARNING: at %pS, CPU#%d: %s/%d' (6.19+)
  lib/bug.c report_bug()           'kernel BUG at %s:%u!'; 'kernel BUG at %pB [verbose debug info unavailable]'
                                   ('Kernel BUG at ...' in 5.10)
  arch/x86/kernel/dumpstack.c      'RIP: %04x:%pS' (show_ip); call-trace entries ' %s%pBb', '? ' before unreliable
                                   ones; 4.9: 'RIP: %04lx:[<%016lx>]  [<%p>] %pS', 'RIP  [<%p>] %pS', ' [<%p>] %s%pB'
                                   and (arch/x86/mm/fault.c) 'IP: [<%p>] %pS'
  arch/arm64/kernel/process.c      'pc : %pS', 'lr : %pS' (__show_regs); 4.9: 'PC is at %s', 'LR is at %s'
  arch/arm64/kernel/stacktrace.c   call-trace entries ' %pSb', from 6.x followed by ' (P)', ' (C)'...
  lib/vsprintf.c, kernel/kallsyms.c  %pS / %pB print 'symbol+0xoff/0xsize', then ' [module]' or ' [module buildid]'
                                   for module code, or '0x<address>' when no symbol is known
  kernel/printk/printk.c           prefixes '<%u>', '[%5lu.%06lu]', '[%6s]' (caller T<pid> / C<cpu>), /dev/kmsg
                                   'level,seq,usec,flags;'; also dmesg -T '[Thu Nov 12 10:00:00 2026]' and a journal's
                                   '<date> <host> kernel:'

syzbot reports also put the source line after a symbol ('func+0x12/0x34 mm/file.c:12') and print inlined frames
as 'func mm/file.c:12 [inline]'. The kernel prints the address of the trap itself for a BUG/WARN (RIP / pc and the
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
_PREFIX = re.compile(r"^\s*(?:<\d+>|\d+,\d+,\d+,[^;]*;|\[\s*\d+\.\d+\]|\[\s*[TC]\d+\]"
                     r"|\[[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+ [\d:]+ \d{4}\]"  # dmesg -T
                     r"|(?:[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ][\d:.]+(?:[+-]\d\d:?\d\d|Z)?)"
                     r"\s+\S+\s+kernel:)")
_WARN_OLD = re.compile(r"WARNING: CPU: \d+ PID: \d+ at (?:(?P<file>[^\s:]+):(?P<line>\d+) )?(?P<rest>.*)$")
_WARN_NEW = re.compile(r"WARNING: (?:(?P<file>[^\s:]+):(?P<line>\d+) )?at (?P<rest>.*)$")
_BUG_LINE = re.compile(r"[Kk]ernel BUG at (?P<file>[^\s:!]+):(?P<line>\d+)!")
_BUG_SYM = re.compile(r"[Kk]ernel BUG at (?P<rest>.*?)\s*\[verbose debug info unavailable\]")
_RIP = re.compile(r"(?:^|\s)(?:RIP:?|IP:)\s+(?:(?P<cs>[0-9a-fA-F]{4}):)?(?P<rest>.*)$")
_PC = re.compile(r"(?:^|\s)(?:(?P<reg>pc|lr) : |(?P<old>PC|LR) is at )(?P<rest>.*)$")
_TRACE = re.compile(r"(?:^|\s)Call [Tt]race:")
_INLINE = re.compile(r"^(?P<fn>[A-Za-z_.$][\w.$]*)\s+(?P<file>[\w./+-]+\.(?:c|h|S|rs)):(?P<line>\d+)\s+\[inline\]$")
_FILE_LINE = re.compile(r"^(?P<file>[\w./+-]+\.(?:c|h|S|rs)):(?P<line>\d+)$")
# what may follow a call-trace entry or a bare func+0xoff line: an elided size ('/0x...', as people write it), and on
# arm64 ' (P)', ' (C)', ' (F)'...
_TAIL = re.compile(r"^(?:/\S*)?(?:\s+\([A-Z]+\))?\s*$")


@dataclass
class Loc:
    """One location in the log. source: 'rip', 'pc', 'lr', 'warning', 'bug', 'frame' (call-trace entry) or 'text'
    (a line that is only func+0xoff or file:line)."""
    source: str
    function: str = None
    offset: int = None
    size: int = None
    module: str = None
    file: str = None
    line: int = None
    address: int = None  # the log printed an address, no symbol
    reliable: bool = True  # False: a call-trace entry printed with '? '
    inline: bool = False  # syzbot: an inlined frame (no address of its own)
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
    header: Loc = None  # the WARNING or kernel BUG line, if any
    kind: str = None  # 'WARN', 'BUG', 'oops' (a RIP/pc line without either), or None
    file: str = None  # file:line the report names (WARNING / kernel BUG line, else the primary's own)
    line: int = None
    frames: list = field(default_factory=list)  # call-trace entries in order, '? ' ones with reliable=False
    locations: list = field(default_factory=list)  # every location found, in the order of the text


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
    """Every location in the pasted text (one line or a whole report) and the one to go to: see Report."""
    rep = Report()
    in_trace = False
    for raw in (text or "").splitlines():
        s = strip_prefix(raw)
        if not s:
            continue
        found = None
        m = _WARN_OLD.search(s) or _WARN_NEW.search(s)
        if m:
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
        if found is None:
            m = _RIP.search(s)
            if m:
                found = _loc("rip", m.group("rest"), s)
                if found is not None and m.group("cs") and int(m.group("cs"), 16) & 3:
                    found = None  # 'RIP: 0033:0x7f...': user mode
        if found is None:
            m = _PC.search(s)
            if m:
                found = _loc("pc" if (m.group("reg") or m.group("old")).lower() == "pc" else "lr", m.group("rest"), s)
        if found is None and _TRACE.search(s):
            in_trace = True
            continue
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
        if found is None:
            continue
        rep.locations.append(found)
        if found.source == "frame":
            rep.frames.append(found)
    locs = rep.locations
    first = lambda pred: next((x for x in locs if pred(x)), None)
    rep.header = first(lambda x: x.source in ("warning", "bug"))
    rep.kind = {"warning": "WARN", "bug": "BUG"}.get(rep.header.source) if rep.header else None
    addressable = lambda x: x.offset is not None or x.address is not None
    rep.primary = (first(lambda x: x.source in ("rip", "pc") and addressable(x))
                   or first(lambda x: x.source == "warning" and addressable(x))
                   or first(lambda x: x.source == "bug")
                   or first(lambda x: x.source == "warning")
                   or first(lambda x: x.source == "text" and not x.inline)
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
    """The kernel's name for a module file (nf_tables.ko.xz -> nf_tables; '-' becomes '_'), None for anything else."""
    base = re.split(r"[\\/]", path or "")[-1]
    m = re.match(r"^(.+)\.ko(?:\.(?:xz|gz|zst))?$", base)
    return m.group(1).replace("-", "_") if m else None


class SiteIndex:
    """kflow's BUG/WARN sites by address (build it once to resolve many reports against the same file)."""

    def __init__(self, sites):
        self.sites = sorted(sites, key=lambda s: s.addr)
        self.addrs = [s.addr for s in self.sites]
        self.by_addr = {}
        for s in self.sites:
            self.by_addr.setdefault(s.addr, s)

    def between(self, lo, hi):
        return self.sites[bisect.bisect_left(self.addrs, lo):bisect.bisect_left(self.addrs, hi)]

    def at_line(self, file, line):
        return [s for s in self.sites if s.line == line and same_file(s.file, file)]


@dataclass
class Match:
    """status: 'exact' (a site at the log's address), 'near' (no site there; candidates = the sites in that function,
    those at the log's file:line first, then nearest first; when the offset is past the end of the function in this
    file there is no address and they are in address order), 'function' (the function has no site), 'line' (no
    function+offset; one site at file:line), 'ambiguous' (no usable function+offset; several sites at file:line) or
    'none'.
    address: where to go (the log's address for exact/near/function, the site for line), else None.
    site: the site found (exact, line), else None.
    label: what the candidates of 'line' / 'ambiguous' share ('mm/userfaultfd.c:755', or 'func+0x10' when functions
    of the same name each have a site there)."""
    status: str
    address: int = None
    site: object = None
    candidates: list = field(default_factory=list)
    loc: Loc = None
    function_start: int = None
    notes: list = field(default_factory=list)
    label: str = None


def _starts(loc, symbols):
    """[(start, size or None)] for loc's function: the exact name first; names with a suffix the log leaves out
    (name.cfi, name.llvm.123, an LTO number) only when no exact-name function contains the offset."""
    exact = symbols(loc.function) or []
    inside = [c for c in exact if c[1] is None or loc.offset < c[1]]
    if inside:
        return inside, False
    more = [c for c in (symbols(loc.function, True) or []) if c not in exact and (c[1] is None or loc.offset < c[1])]
    return (more, True) if more else (exact, False)


def resolve(report, sites, symbols, module=None, is_module=False):
    """Find the BUG/WARN site the report names.

    sites: kflow's BugSite list (addr, file, line, warn) or a SiteIndex of it.
    symbols(name, suffixed=False) -> [(start, size or None)]: the functions of that name in the file being looked at
    (several for static functions that share a name); with suffixed=True the ones named name.<suffix>.
    module: the module name of that file (module_name()), is_module: the file is a module (else vmlinux); both only
    for the notes."""
    loc = report.primary
    if loc is None:
        return Match("none", notes=["no WARNING / kernel BUG / RIP / pc line, func+0xoff or file:line in the text"])
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
            starts, suffixed = _starts(cur, symbols)
            if not starts:
                notes.append("no function %s in this file" % cur.function)
                continue
            hits = [(st + cur.offset, st, sz) for st, sz in starts if st + cur.offset in by_addr]
            if len(hits) > 1:  # static functions of the same name, each with a site at this offset
                hits = [h for h in hits if cur.size is not None and h[2] == cur.size] or hits
            if len(hits) > 1 and want_file:
                hits = [h for h in hits if by_addr[h[0]].line == want_line and same_file(by_addr[h[0]].file, want_file)] or hits
            if suffixed and hits:
                notes.append("matched a function named %s.<suffix> (the log prints the name without it)" % cur.function)
            if len(hits) > 1:
                return Match("ambiguous", None, None, [by_addr[h[0]] for h in hits], cur, None, notes,
                             "%s+%#x" % (cur.function, cur.offset))
            if hits:
                a, st, sz = hits[0]
                return Match("exact", a, by_addr[a], [by_addr[a]], cur, st, notes)
            if found_fn is None:
                pick = [c for c in starts if cur.size is not None and c[1] == cur.size] or starts
                found_fn = (cur, pick[0], suffixed, len(starts))
        elif cur.address is not None:
            if cur.address in by_addr:
                return Match("exact", cur.address, by_addr[cur.address], [by_addr[cur.address]], cur, None, notes)
            notes.append("the log has only the address 0x%x (no symbol), and no BUG/WARN site is there (with KASLR "
                         "the running kernel's addresses differ from the file's)" % cur.address)
    if found_fn is not None:
        cur, (st, sz), suffixed, count = found_fn
        a = st + cur.offset
        if count > 1:
            notes.append("%d functions are named %s; the one%s is used" % (
                count, cur.function, " whose size matches the log's" if cur.size is not None and sz == cur.size else
                " found first"))
        if cur.size is not None and sz is not None and sz != cur.size:
            notes.append("size in the log %#x, here %#x: another build, or another function of that name" % (cur.size, sz))
        # the function as this file has it (the log's size is another build's when they differ)
        span = sz or cur.size
        at_line = lambda s: s.line == want_line and same_file(s.file, want_file)
        inside = index.between(st, st + span) if span else []
        if sz and cur.offset >= sz:  # no address of this function: list its sites, go nowhere
            notes.append("%s+%#x is past the end of %s here (%#x bytes): a log from another build?" % (
                cur.function, cur.offset, cur.function, sz))
            if inside:
                return Match("near", None, None, sorted(inside, key=lambda s: (not at_line(s), s.addr)), cur, st, notes)
        else:
            inside = sorted(inside, key=lambda s: (not at_line(s), abs(s.addr - a)))
            return Match("near" if inside else "function", a, None, inside, cur, st, notes)
    if want_file and want_line is not None:
        cands = index.at_line(want_file, want_line)
        label = "%s:%d" % (want_file, want_line)
        if len(cands) == 1:
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
        if report.header is not None:
            what.append(("WARNING" if report.kind == "WARN" else "kernel BUG") +
                        (" at %s:%d" % (report.file, report.line) if report.file else ""))
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
    if st == "exact":
        out.append("exact: the %s site at %s (%#x)" % ("WARN" if match.site.warn else "BUG",
                                                         "%s+%#x" % (loc.function, loc.offset) if loc.function else
                                                         "the log's address", match.address))
        out += rows([match.site])
    elif st == "near":
        same = sum(1 for s in match.candidates if s.line == report.line and same_file(s.file, report.file))
        n = len(match.candidates)
        if match.address is None:
            out.append("not exact: %s+%#x is past the end of %s in this file; the %d site%s in %s, %sin address order:"
                       % (loc.function, loc.offset, loc.function, n, "" if n == 1 else "s", loc.function,
                          "those at %s:%d first, then " % (report.file, report.line) if same else ""))
            out += rows(match.candidates[:10])
        else:
            out.append("not exact: no BUG/WARN site at %s+%#x (%#x); the %d site%s in %s, %snearest first:"
                       % (loc.function, loc.offset, match.address, n, "" if n == 1 else "s", loc.function,
                          "those at %s:%d first, then " % (report.file, report.line) if same else ""))
            out += ["%s  (%+#x)" % (r, s.addr - match.address) for r, s in zip(rows(match.candidates[:10]), match.candidates)]
        if len(match.candidates) > 10:
            out.append("  ... %d more" % (len(match.candidates) - 10))
    elif st == "function":
        out.append("not a BUG/WARN site: %s+%#x (%#x) is in a function without one (an oops, not a BUG/WARN trap?)"
                   % (loc.function, loc.offset, match.address))
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
            "candidates": [site(s) for s in match.candidates], "label": match.label,
            "from": match.loc.record() if match.loc else None,
            "report": {"kind": report.kind, "file": report.file, "line": report.line},
            "frames": [f.record() for f in report.frames], "notes": list(match.notes)}
