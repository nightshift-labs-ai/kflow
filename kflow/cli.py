"""kflow command line: decode the site tables of a kernel ELF (vmlinux, a MemLens kernel.elf, or a module .ko).

    python3 -m kflow <kernel.elf> [--list bug|warn|jump|ex] [--limit N] [--json out.json]
"""
import argparse
import bisect
import collections
import json
import struct
import sys

from . import __version__
from .core import TABLES, decode_bug_table, decode_ex_table, decode_jump_table, key_label


class InputError(Exception):
    pass


def _unpack(path, d):
    """Distributions ship modules as .ko.xz / .ko.gz / .ko.zst: unpack the first two in memory."""
    if d[:6] == b"\xfd7zXZ\x00":
        try:
            import lzma
        except ImportError:
            raise InputError("%s is xz-compressed and this Python has no lzma module: run xz -dk on it first" % path)
        try:
            return lzma.decompress(d)
        except (lzma.LZMAError, EOFError) as e:
            raise InputError("%s: cannot decompress (%s)" % (path, e))
    if d[:2] == b"\x1f\x8b":
        import gzip
        import zlib
        try:
            return gzip.decompress(d)
        except (OSError, EOFError, zlib.error) as e:
            raise InputError("%s: cannot decompress (%s)" % (path, e))
    if d[:4] == b"\x28\xb5\x2f\xfd":
        raise InputError("%s is zstd-compressed: run zstd -d on it first" % path)
    return d


class Elf:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            d = _unpack(path, fh.read())
        if d[:4] != b"\x7fELF":
            raise InputError("%s is not an ELF file" % path)
        if d[4] != 2 or d[5] != 1:
            raise InputError("only 64-bit little-endian ELF is supported")
        self.data = d
        try:
            self._parse()
        except (struct.error, IndexError, ValueError, OverflowError, KeyError) as e:
            raise InputError("%s: malformed or truncated ELF (%s: %s)" % (path, type(e).__name__, e))

    def _parse(self):
        d = self.data
        shoff, = struct.unpack_from("<Q", d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3A)
        machine, = struct.unpack_from("<H", d, 0x12)
        etype, = struct.unpack_from("<H", d, 0x10)
        self.arch = {62: "x86_64", 183: "aarch64"}.get(machine, "machine %d" % machine)
        self.secs, names, extra = [], [], []
        for i in range(shnum):
            name, typ, flags, addr, off, size, link, info, align = struct.unpack_from("<IIQQQQIIQ", d, shoff + i * shentsize)
            self.secs.append((typ, flags, addr, off, size, link))
            names.append(name)
            extra.append((info, align))
        self.secnames = []
        if shstrndx < len(self.secs):
            so = self.secs[shstrndx][3]
            self.secnames = [d[so + n:d.index(b"\0", so + n)].decode("utf-8", "replace") for n in names]
        self.relocatable = etype == 1  # a kernel module (.ko): sections get addresses here and relocations are applied
        self.externs = {}
        if self.relocatable:
            self._layout(extra)
        self.sections = {}
        for i, nm in enumerate(self.secnames):
            t, f, a, o, s, l = self.secs[i]
            if nm and a and s:
                self.sections.setdefault(nm, (a, a + s))
        self.loaded = sorted((a, a + s, o) for t, f, a, o, s, l in self.secs if t == 1 and a and s)
        self._starts = [x[0] for x in self.loaded]
        self.text = [(a, a + s) for t, f, a, o, s, l in self.secs if t == 1 and f & 4 and a and s]
        self.symbols = {}
        funcs = []
        for t, f, a, o, s, link in self.secs:
            if t != 2:
                continue
            stro = self.secs[link][3]
            for k in range(s // 24):
                st_name, st_info, _, shndx, value, size = struct.unpack_from("<IBBHQQ", d, o + 24 * k)
                end = d.index(b"\0", stro + st_name)
                name = d[stro + st_name:end].decode("utf-8", "replace")
                if self.relocatable:
                    value = self._symval(name, shndx, value)
                if name and name not in self.symbols:
                    self.symbols[name] = value
                if st_info & 0xF == 2 and value:
                    funcs.append((value, value + size, name))
        funcs.sort()
        # kallsyms-derived ELFs (vmlinux-to-elf) give every function size 0: end it at the next function
        for k, (a, e, n) in enumerate(funcs):
            if e == a:
                nxt = funcs[k + 1][0] if k + 1 < len(funcs) else a + 1
                funcs[k] = (a, min(nxt, a + 0x100000), n)
        self.funcs = funcs
        self._fstarts = [f[0] for f in funcs]
        self.by_addr = {}
        for n, a in self.symbols.items():
            self.by_addr.setdefault(a, n)

    # --- kernel modules (ET_REL): lay the allocated sections out from BASE in file order, put undefined symbols in
    # 8-byte slots after them (like a disassembler's extern segment), then apply the relocations the tables need.
    BASE = 0x10000
    EXTERN_SLOT = 0x100  # room for "symbol + member offset" (a tracepoint's key is __tracepoint_X + 8)
    REL = {  # type: (size, pc-relative, signed)
        "x86_64": {1: (8, False, False), 2: (4, True, True), 4: (4, True, True), 10: (4, False, False),
                   11: (4, False, True), 24: (8, True, True)},
        "aarch64": {257: (8, False, False), 258: (4, False, True), 260: (8, True, True), 261: (4, True, True)},
    }

    def _layout(self, extra):
        addr = self.BASE
        for i, (t, f, a, o, s, l) in enumerate(self.secs):
            if f & 2 and s and t in (1, 8):  # SHF_ALLOC, PROGBITS or NOBITS
                al = max(extra[i][1], 1)
                addr = (addr + al - 1) // al * al
                self.secs[i] = (t, f, addr, o, s, l)
                addr += s
        self._ext_next = (addr + 0xFFF) // 0x1000 * 0x1000
        data = bytearray(self.data)
        symvals = self._all_symbol_values()
        rules = self.REL.get(self.arch, {})
        for i, (t, f, a, o, s, l) in enumerate(self.secs):
            if t != 4:  # SHT_RELA
                continue
            target = extra[i][0]
            if target >= len(self.secs):
                continue
            tt, tf, ta, to, ts, tl = self.secs[target]
            if not (tf & 2) or tt != 1:
                continue
            for k in range(s // 24):
                r_off, r_info, addend = struct.unpack_from("<QQq", self.data, o + 24 * k)
                rule = rules.get(r_info & 0xFFFFFFFF)
                if rule is None or r_off + rule[0] > ts:
                    continue
                size, pcrel, signed = rule
                v = symvals.get(r_info >> 32, 0) + addend - ((ta + r_off) if pcrel else 0)
                lo, hi = (-(1 << (8 * size - 1)), 1 << (8 * size - 1)) if signed else (0, 1 << (8 * size))
                if size == 8:
                    v &= (1 << 64) - 1
                elif not lo <= v < hi:
                    continue  # does not fit: leave the bytes alone
                data[to + r_off:to + r_off + size] = (v & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        self.data = bytes(data)

    def _all_symbol_values(self):
        """Index in .symtab -> address, for the relocations (section symbols = their section's address)."""
        out = {}
        for t, f, a, o, s, link in self.secs:
            if t != 2:
                continue
            stro = self.secs[link][3]
            for k in range(s // 24):
                st_name, st_info, _, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, o + 24 * k)
                name = self.data[stro + st_name:self.data.index(b"\0", stro + st_name)].decode("utf-8", "replace")
                out[k] = self._symval(name, shndx, value)
            break
        return out

    def _symval(self, name, shndx, value):
        if shndx == 0 or shndx == 0xFFF2:  # undefined or common: an extern slot, one per name
            if not name:
                return 0
            if name not in self.externs:
                self.externs[name] = self._ext_next
                self._ext_next += self.EXTERN_SLOT
            return self.externs[name]
        if shndx == 0xFFF1:  # absolute
            return value
        if shndx < len(self.secs):
            return self.secs[shndx][2] + value
        return value

    def read(self, ea, size):
        i = bisect.bisect_right(self._starts, ea) - 1
        if i < 0:
            return None
        a, e, o = self.loaded[i]
        if ea >= e:
            return None
        size = min(size, e - ea)
        return self.data[o + ea - a:o + ea - a + size]

    def key_name(self, ea):
        return key_label(lambda a: self.by_addr.get(a, ""), ea, self.read)

    def in_text(self, ea):
        return any(a <= ea < e for a, e in self.text)

    def func(self, ea):
        i = bisect.bisect_right(self._fstarts, ea) - 1
        if i >= 0 and self.funcs[i][0] <= ea < self.funcs[i][1]:
            return self.funcs[i][2]
        return None


def load(elf):
    """Decode every table that has __start_/__stop_ symbols. Returns dict."""
    out = {"missing": [], "found_by": {}, "errors": {}}
    for kind, (s, e) in TABLES.items():
        if s in elf.symbols and e in elf.symbols:
            start, stop = elf.symbols[s], elf.symbols[e]
            out["found_by"][kind] = "symbols"
        elif s[len("__start_"):] in elf.sections:  # stripped vmlinux keeps __bug_table / __ex_table as sections
            start, stop = elf.sections[s[len("__start_"):]]
            out["found_by"][kind] = "section"
        else:
            out["missing"].append(kind)
            continue
        try:  # one table in a layout kflow does not know must not hide the others
            if kind == "bug":
                out["bug_layout"], out["bug"] = decode_bug_table(elf.read, start, stop, in_text=elf.in_text)
            elif kind == "jump":
                out["jump"] = decode_jump_table(elf.read, start, stop, in_text=elf.in_text)
            else:
                out["ex_layout"], out["ex"] = decode_ex_table(elf.read, start, stop, in_text=elf.in_text)
        except ValueError as error:
            out["errors"][kind] = str(error)
    return out


TRAPS = {"x86_64": (b"\x0f\x0b", "ud2"), "aarch64": (b"\x00\x00\x21\xd4", "brk #0x800")}


def summary(elf, t):
    lines = []
    bugs = t.get("bug")
    if bugs is not None:
        warn = [b for b in bugs if b.warn]
        files = collections.Counter(b.file for b in bugs if b.file)
        trap, tname = TRAPS.get(elf.arch, (None, "?"))
        ud2 = sum(1 for b in warn if trap and elf.read(b.addr, len(trap)) == trap)
        lines.append("__bug_table (%s): %d sites, %d WARN (resume after the trap), %d BUG; %d with file:line in %d source files"
                     % (t["bug_layout"], len(bugs), len(warn), len(bugs) - len(warn),
                        sum(1 for b in bugs if b.file), len(files)))
        args = sum(1 for b in warn if b.args)
        lines.append("  WARN sites that are %s here: %d; sites inside a function symbol: %d%s"
                     % (tname, ud2, sum(1 for b in bugs if elf.func(b.addr)),
                        "; WARN with a message, reported through a call (Linux 6.19+): %d" % args if args else ""))
    jumps = t.get("jump")
    if jumps is not None:
        labels = [elf.key_name(j.key) or "" for j in jumps]
        named = sum(1 for n in labels if n)
        tps = sum(1 for n in labels if n.startswith("tracepoint "))
        dds = sum(1 for n in labels if n.startswith("pr_debug "))
        offs = sum(1 for n in labels if n and not n.startswith(("tracepoint ", "pr_debug ")) and "+0x" in n)
        same = sum(1 for j in jumps if elf.func(j.code) and elf.func(j.code) == elf.func(j.target))
        lines.append("__jump_table: %d static-key sites, %d keys named (%d tracepoints, %d pr_debug sites, "
                     "%d as symbol+offset), %d targets in the same function" % (len(jumps), named, tps, dds, offs, same))
    exs = t.get("ex")
    if exs is not None:
        types = collections.Counter(("handler " + elf.by_addr.get(x.handler, hex(x.handler))) if x.handler is not None
                                    else x.type_name(elf.arch) for x in exs)
        same = sum(1 for x in exs if elf.func(x.insn) and elf.func(x.insn) == elf.func(x.fixup))
        lines.append("__ex_table (%s): %d faulting instructions with a fixup, %d fixups in the same function; types %s"
                     % (t["ex_layout"], len(exs), same, ", ".join("%s %d" % kv for kv in types.most_common(6))))
    if t["missing"]:
        lines.append("not found (no __start_/__stop_ symbols or section): %s" % ", ".join(t["missing"]))
    for kind, error in t.get("errors", {}).items():
        lines.append("not decoded: %s (%s)" % (kind, error))
    by_section = [k for k, v in t["found_by"].items() if v == "section"]
    if by_section:
        lines.append("found by section name (no __start_/__stop_ symbols): %s" % ", ".join(by_section))
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(prog="kflow", description=__doc__.splitlines()[0])
    ap.add_argument("kernel")
    ap.add_argument("--list", choices=["bug", "warn", "jump", "ex"])
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--json")
    ap.add_argument("--version", action="version", version="kflow " + __version__)
    a = ap.parse_args(argv)
    try:
        elf = Elf(a.kernel)
        t = load(elf)
    except (InputError, ValueError, OSError) as e:
        print("kflow: %s" % e, file=sys.stderr)
        return 2
    for line in summary(elf, t):
        print(line)
    if a.list:
        rows = []
        if a.list in ("bug", "warn"):
            for b in t.get("bug", []):
                if a.list == "warn" and not b.warn:
                    continue
                rows.append("%#x %-5s %-40s %s" % (b.addr, "WARN" if b.warn else "BUG", elf.func(b.addr) or "?", b.where() or ""))
        elif a.list == "jump":
            for j in t.get("jump", []):
                rows.append("%#x -> %#x  %-40s key %s%s" % (j.code, j.target, elf.func(j.code) or "?",
                            elf.key_name(j.key) or "%#x" % j.key, " (likely)" if j.branch else ""))
        else:
            for x in t.get("ex", []):
                rows.append("%#x -> %#x  %-40s %s" % (x.insn, x.fixup, elf.func(x.insn) or "?",
                            ("handler " + elf.by_addr.get(x.handler, hex(x.handler))) if x.handler is not None else x.type_name(elf.arch)))
        for r in rows[:a.limit]:
            print(r)
        if len(rows) > a.limit:
            print("... %d more (--limit)" % (len(rows) - a.limit))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"bug_layout": t.get("bug_layout"),
                       "bug": [[b.addr, b.flags, b.file, b.line] for b in t.get("bug", [])],
                       "jump": [[j.code, j.target, j.key, int(j.branch), int(j.init)] for j in t.get("jump", [])],
                       "ex_layout": t.get("ex_layout"),
                       "ex": [[x.insn, x.fixup, x.data] for x in t.get("ex", [])]}, fh)
    return 0
