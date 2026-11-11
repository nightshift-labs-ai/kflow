"""kflow command line: decode the site tables of a kernel ELF (vmlinux, or a MemLens kernel.elf).

    python3 -m kflow <kernel.elf> [--list bug|warn|jump|ex] [--limit N] [--json out.json]
"""
import argparse
import bisect
import collections
import json
import struct
import sys

from . import __version__
from .core import TABLES, decode_bug_table, decode_ex_table, decode_jump_table


class InputError(Exception):
    pass


class Elf:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = d = fh.read()
        if d[:4] != b"\x7fELF":
            raise InputError("%s is not an ELF file" % path)
        if d[4] != 2 or d[5] != 1:
            raise InputError("only 64-bit little-endian ELF is supported")
        shoff, = struct.unpack_from("<Q", d, 0x28)
        shentsize, shnum = struct.unpack_from("<HH", d, 0x3A)
        self.secs = []
        for i in range(shnum):
            name, typ, flags, addr, off, size, link = struct.unpack_from("<IIQQQQI", d, shoff + i * shentsize)
            self.secs.append((typ, flags, addr, off, size, link))
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
                st_name, st_info, _, _, value, size = struct.unpack_from("<IBBHQQ", d, o + 24 * k)
                end = d.index(b"\0", stro + st_name)
                name = d[stro + st_name:end].decode("utf-8", "replace")
                if name and name not in self.symbols:
                    self.symbols[name] = value
                if st_info & 0xF == 2 and size:
                    funcs.append((value, value + size, name))
        funcs.sort()
        self.funcs = funcs
        self._fstarts = [f[0] for f in funcs]
        self.by_addr = {}
        for n, a in self.symbols.items():
            self.by_addr.setdefault(a, n)

    def read(self, ea, size):
        i = bisect.bisect_right(self._starts, ea) - 1
        if i < 0:
            return None
        a, e, o = self.loaded[i]
        if ea >= e:
            return None
        size = min(size, e - ea)
        return self.data[o + ea - a:o + ea - a + size]

    def in_text(self, ea):
        return any(a <= ea < e for a, e in self.text)

    def func(self, ea):
        i = bisect.bisect_right(self._fstarts, ea) - 1
        if i >= 0 and self.funcs[i][0] <= ea < self.funcs[i][1]:
            return self.funcs[i][2]
        return None


def load(elf):
    """Decode every table that has __start_/__stop_ symbols. Returns dict."""
    out = {"missing": []}
    for kind, (s, e) in TABLES.items():
        if s not in elf.symbols or e not in elf.symbols:
            out["missing"].append(kind)
            continue
        start, stop = elf.symbols[s], elf.symbols[e]
        if kind == "bug":
            out["bug_layout"], out["bug"] = decode_bug_table(elf.read, start, stop, in_text=elf.in_text)
        elif kind == "jump":
            out["jump"] = decode_jump_table(elf.read, start, stop)
        else:
            out["ex"] = decode_ex_table(elf.read, start, stop)
    return out


def summary(elf, t):
    lines = []
    bugs = t.get("bug")
    if bugs is not None:
        warn = [b for b in bugs if b.warn]
        files = collections.Counter(b.file for b in bugs if b.file)
        ud2 = sum(1 for b in warn if elf.read(b.addr, 2) == b"\x0f\x0b")
        lines.append("__bug_table (%s): %d sites, %d WARN (resume after the trap), %d BUG; %d with file:line in %d source files"
                     % (t["bug_layout"], len(bugs), len(warn), len(bugs) - len(warn),
                        sum(1 for b in bugs if b.file), len(files)))
        lines.append("  WARN sites that are ud2 (0f 0b) here: %d; sites inside a function symbol: %d"
                     % (ud2, sum(1 for b in bugs if elf.func(b.addr))))
    jumps = t.get("jump")
    if jumps is not None:
        named = sum(1 for j in jumps if j.key in elf.by_addr)
        same = sum(1 for j in jumps if elf.func(j.code) and elf.func(j.code) == elf.func(j.target))
        lines.append("__jump_table: %d static-key sites, %d keys named by a symbol, %d targets in the same function"
                     % (len(jumps), named, same))
    exs = t.get("ex")
    if exs is not None:
        types = collections.Counter(x.type_name() for x in exs)
        lines.append("__ex_table: %d faulting instructions with a fixup; types %s"
                     % (len(exs), ", ".join("%s %d" % kv for kv in types.most_common(6))))
    if t["missing"]:
        lines.append("no __start_/__stop_ symbols for: %s" % ", ".join(t["missing"]))
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
                            elf.by_addr.get(j.key, "%#x" % j.key), " (likely)" if j.branch else ""))
        else:
            for x in t.get("ex", []):
                rows.append("%#x -> %#x  %-40s %s" % (x.insn, x.fixup, elf.func(x.insn) or "?", x.type_name()))
        for r in rows[:a.limit]:
            print(r)
        if len(rows) > a.limit:
            print("... %d more (--limit)" % (len(rows) - a.limit))
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"bug_layout": t.get("bug_layout"),
                       "bug": [[b.addr, b.flags, b.file, b.line] for b in t.get("bug", [])],
                       "jump": [[j.code, j.target, j.key, int(j.branch), int(j.init)] for j in t.get("jump", [])],
                       "ex": [[x.insn, x.fixup, x.data] for x in t.get("ex", [])]}, fh)
    return 0
