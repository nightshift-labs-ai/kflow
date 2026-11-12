#!/usr/bin/env python3
"""How much of the code kflow points at does ordinary control flow reach? (x86_64 kernel ELFs; stdlib + objdump)

    python3 tools/reach.py <kernel ELF> [--json out.json] [--objdump PATH] [--section .text ...]

kflow adds a reference from each site to a target that IDA's own flow analysis may never reach:
  warn  a WARN ud2 trap      -> the instruction after the trap (where the kernel resumes)
  key   a static-key site    -> its out-of-line branch target (__jump_table)
  ex    a faulting insn      -> its fixup (__ex_table)
This tool disassembles every executable section of the ELF with objdump (linear sweep) and, for each site's target,
decides whether ordinary flow reaches it WITHOUT kflow. The rules, in this order (first match wins):

  branch       some direct jmp / jcc / loop / call anywhere in an executable section targets it
  fallthrough  the instruction that ends exactly at the target can fall into it: anything except an unconditional
               direct jmp, an indirect jmp, ret / iret / sysret, ud0 / ud1 / ud2, int3 and (bad). Calls are
               assumed to return (conservative: a call to a noreturn function counts as falling through). A static-key
               site counts as falling through whatever its current form (its NOP state falls through). hlt
               falls through (execution resumes after it on an interrupt).
  padding      the instruction before the target is NOP padding (nop, nopw, nopl, xchg %ax,%ax; not a static-key
               site), and walking back over the NOP run reaches an instruction that falls through, or a NOP of the
               run is itself a branch target. This is the "via padding" bucket: reachable, but only by executing
               alignment NOPs.
  HIDDEN       none of the above: no instruction in the file branches to the target or falls into it, so kflow's
               reference is the only thing that points there. int3 padding (0xcc) never falls through.
  unaligned    the target is not an instruction start in objdump's linear sweep and nothing branches to it
               or lies outside every disassembled section (e.g. init code a memory image no longer has), and
               nothing branches to it: reported apart, counted neither hidden nor reachable, and left out of the
               HIDDEN % (HIDDEN % = HIDDEN / (sites - unaligned))

Branch targets are taken from every direct branch in every executable section (also .init.text,
.altinstr_replacement...), so the HIDDEN count is a lower bound for "nothing points there". For static keys the
site's own current form matters: a site that is a jmp in this file (a key already flipped, or a jump the compiler
emitted) already branches to its target. The key line counts that jmp (what IDA sees in this file); the line "key,
site jmps ignored" does not (the code with every key in its NOP state), and "key, NOP sites" keeps only sites that
are NOPs in this file.

For each kind: sites, HIDDEN sites and %, the reason counts, the distinct HIDDEN targets, and the size of their
out-of-line blocks. A block runs from the target up to and including the next unconditional transfer (jmp, ret,
ud2...); it ends earlier, before the next instruction that some direct branch targets (from that join on, ordinary
flow reaches the code anyway), before int3/(bad) or a gap in the listing, and at 4096 instructions. Bytes and
instructions are counted once per DISTINCT target ("bytes" sums the blocks, "union" counts overlapping blocks once).
"""
import argparse
import bisect
import json
import os
import subprocess
import sys
import time
from array import array

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# instruction kinds
NORMAL, COND, JMP, CALL, STOP, NOP, INT3, BAD = range(8)
FALLS = (NORMAL, COND, CALL)  # kinds that fall through to the next instruction (NOP handled apart)
PREFIXES = {"cs", "ds", "ss", "es", "fs", "gs", "data16", "data32", "addr32", "bnd", "notrack", "lock", "rep", "repz",
            "repnz", "repe", "repne", "xacquire", "xrelease"}
STOPS = {"ret", "retq", "retl", "retw", "lret", "lretq", "lretl", "iret", "iretq", "iretl", "iretw", "sysret",
         "sysretq", "sysretl", "sysexit", "sysexitq", "ud0", "ud1", "ud2", "ud2a", "ud2b", "eretu"}
# hlt is not a stop: the CPU resumes at the next instruction after an interrupt (sti; hlt; ret in the idle code)
NOPS = {"nop", "nopw", "nopl", "nopq"}
BLOCK_CAP = 4096
VARIABLE = ("rex", "j", "call", "loop", "xbegin", "xchg", "l")  # mnemonics classify() must see with their operands


def classify(text):
    """(kind, direct target or None) for one objdump instruction text (AT&T syntax), e.g. 'jne ffffffff81000010 <f+0x10>'."""
    toks = text.split()
    while toks and (toks[0] in PREFIXES or toks[0].startswith("rex")):
        toks = toks[1:]
    if not toks:
        return NORMAL, None  # a lone prefix
    m = toks[0]
    if m == "(bad)" or m.startswith("(bad"):
        return BAD, None
    if m == "int3":
        return INT3, None
    if m in NOPS or (m == "xchg" and len(toks) > 1 and toks[1] == "%ax,%ax"):
        return NOP, None
    if m in STOPS:
        return STOP, None
    if m in ("jmp", "jmpq", "call", "callq") or (m[0] == "j" and m != "jmp") or m.startswith("loop") or m == "xbegin":
        op = toks[1] if len(toks) > 1 else ""
        if m in ("jmp", "jmpq"):
            if op.startswith("*") or op.startswith("%"):
                return STOP, None  # indirect jmp: no fall-through, target unknown
            kind = JMP
        elif m in ("call", "callq"):
            if op.startswith("*") or op.startswith("%"):
                return NORMAL, None  # indirect call: falls through, target unknown
            kind = CALL
        else:
            kind = COND
        try:
            return kind, int(op, 16)
        except ValueError:
            return (STOP if kind == JMP else NORMAL), None  # far jmp/call with selector: treat as indirect
    if m in ("ljmp", "ljmpq"):
        return STOP, None
    return NORMAL, None


class Listing:
    """A linear-sweep objdump listing: instruction addresses (sorted), lengths, kinds, and the direct branch targets."""

    def __init__(self):
        self.addrs = array("Q")
        self.lens = bytearray()
        self.kinds = bytearray()
        self.targets = {}  # target -> list of branch source addresses (only the first few kept)
        self.ntargets_total = 0
        self.ninsns = 0

    def feed(self, lines):
        """Add objdump -d -w lines (one section, ascending)."""
        addrs, lens, kinds, targets = self.addrs, self.lens, self.kinds, self.targets
        cache = {}
        for line in lines:
            parts = line.split("\t")
            if len(parts) < 2 or not parts[0].endswith(":"):
                continue
            head = parts[0].strip()[:-1]
            if not head or " " in head:
                continue
            try:
                ea = int(head, 16)
            except ValueError:
                continue
            n = len(parts[1].split())
            if len(parts) < 3 or not parts[2].strip():  # continuation of the previous instruction's bytes
                if lens and addrs[-1] + lens[-1] == ea:
                    lens[-1] = min(255, lens[-1] + n)
                continue
            text = parts[2].strip()
            mn = text.split(" ", 1)[0]
            kind = cache.get(mn)
            tgt = None
            if kind is None:
                kind, tgt = classify(text)
                if not (mn in PREFIXES or mn.startswith(VARIABLE)):
                    cache[mn] = kind  # a mnemonic whose kind does not depend on its operands
            addrs.append(ea)
            lens.append(min(255, n))
            kinds.append(kind)
            if tgt is not None:
                lst = targets.get(tgt)
                if lst is None:
                    targets[tgt] = [ea]
                elif len(lst) < 4:
                    lst.append(ea)
                self.ntargets_total += 1
        self.ninsns = len(addrs)

    def finish(self):
        """Sort by address if sections were fed out of order."""
        if any(self.addrs[i] > self.addrs[i + 1] for i in range(len(self.addrs) - 1)):
            order = sorted(range(len(self.addrs)), key=self.addrs.__getitem__)
            self.addrs = array("Q", (self.addrs[i] for i in order))
            self.lens = bytearray(self.lens[i] for i in order)
            self.kinds = bytearray(self.kinds[i] for i in order)

    def index(self, ea):
        i = bisect.bisect_left(self.addrs, ea)
        return i if i < len(self.addrs) and self.addrs[i] == ea else None

    def kind_at(self, ea):
        i = self.index(ea)
        return None if i is None else self.kinds[i]

    def branched(self, ea, ignore=frozenset()):
        """True when a direct branch (not one located at an address in ignore) targets ea."""
        src = self.targets.get(ea)
        if not src:
            return False
        if not ignore:
            return True
        if len(src) < 4:
            return any(s not in ignore for s in src)
        return True  # four or more branches: at most one per site, conservatively reachable

    def reason(self, t, sites=frozenset(), ignore=frozenset()):
        """Why ordinary flow reaches t: 'branch', 'fallthrough', 'padding', or 'hidden' / 'unaligned' when it does not.
        sites: static-key site addresses (they fall through and are never padding); ignore: branch sources to skip."""
        if self.branched(t, ignore):
            return "branch"
        i = self.index(t)
        if i is None:
            return "unaligned"
        p = i - 1
        if p < 0 or self.addrs[p] + self.lens[p] != t:
            return "hidden"  # start of a section or a gap (zero bytes objdump skipped)
        k = self.kinds[p]
        if self.addrs[p] in sites or k in FALLS:
            return "fallthrough"
        if k != NOP:
            return "hidden"
        # NOP padding: walk back over the run
        while p >= 0 and self.kinds[p] == NOP and self.addrs[p] not in sites:
            if self.branched(self.addrs[p], ignore):
                return "padding"
            if p == 0 or self.addrs[p - 1] + self.lens[p - 1] != self.addrs[p]:
                return "hidden"
            p -= 1
        if p >= 0 and (self.addrs[p] in sites or self.kinds[p] in FALLS):
            return "padding"
        return "hidden"

    def block(self, t):
        """(instructions, bytes) of the block from t up to and including the next unconditional transfer, or up to
        (not including) the next instruction that a direct branch targets."""
        i = self.index(t)
        if i is None:
            return 0, 0
        n = b = 0
        end = len(self.addrs)
        while i < end and n < BLOCK_CAP:
            k = self.kinds[i]
            if k in (INT3, BAD) or (n and self.addrs[i] in self.targets):
                break  # padding, or a join: ordinary flow reaches the code from here on anyway
            n += 1
            b += self.lens[i]
            if k in (JMP, STOP):
                break
            if i + 1 < end and self.addrs[i + 1] != self.addrs[i] + self.lens[i]:
                break
            i += 1
        return n, b


def measure(listing, targets, sites=frozenset(), ignore=frozenset()):
    """targets: one target address per site. Returns the stats dict for one row."""
    reasons = {"branch": 0, "fallthrough": 0, "padding": 0, "hidden": 0, "unaligned": 0}
    hidden = set()
    memo = {}
    for t in targets:
        r = memo.get(t)
        if r is None:
            r = memo[t] = listing.reason(t, sites, ignore)
        reasons[r] += 1
        if r == "hidden":
            hidden.add(t)
    insns = nbytes = 0
    spans = []
    for t in sorted(hidden):
        n, b = listing.block(t)
        insns += n
        nbytes += b
        spans.append((t, t + b))
    union, cur_s, cur_e = 0, None, None
    for s, e in spans:
        if cur_e is None or s > cur_e:
            if cur_e is not None:
                union += cur_e - cur_s
            cur_s, cur_e = s, e
        else:
            cur_e = max(cur_e, e)
    if cur_e is not None:
        union += cur_e - cur_s
    sites_n = len(targets)
    judged = sites_n - reasons["unaligned"]  # sites whose target is an instruction in the listing
    return {"sites": sites_n, "judged": judged, "hidden": reasons["hidden"],
            "hidden_pct": round(100.0 * reasons["hidden"] / judged, 1) if judged else 0.0,
            "reasons": reasons, "distinct_targets": len(set(targets)), "hidden_distinct": len(hidden),
            "hidden_insns": insns, "hidden_bytes": nbytes, "hidden_union_bytes": union,
            "avg_insns": round(insns / len(hidden), 1) if hidden else 0.0}


def exec_sections(elf):
    """[(name, start, end)] of the ELF's executable sections with contents."""
    out = []
    for i, (t, f, a, o, s, l) in enumerate(elf.secs):
        if t == 1 and f & 4 and a and s:
            out.append((elf.secnames[i] if i < len(elf.secnames) else "#%d" % i, a, a + s))
    return out


def disassemble(path, sections, objdump="objdump"):
    listing = Listing()
    for name, a, e in sorted(sections, key=lambda x: x[1]):
        cmd = [objdump, "-d", "-w", "--insn-width=16", "-j", name, path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20)
        listing.feed(proc.stdout)
        if proc.wait() != 0:
            raise SystemExit("reach: %s failed with status %d" % (" ".join(cmd), proc.returncode))
    listing.finish()
    return listing


def rows_for(elf, t, listing):
    """The measured rows: [(label, stats)] plus notes."""
    from kflow.cli import TRAPS
    rows, notes = [], {}
    trap, _ = TRAPS.get(elf.arch, (None, None))
    jumps = t.get("jump") or []
    key_sites = frozenset(j.code for j in jumps)
    bugs = [b for b in (t.get("bug") or []) if b.warn]
    if bugs:
        traps = [b for b in bugs if trap and elf.read(b.addr, len(trap)) == trap]
        notes["warn_not_ud2"] = len(bugs) - len(traps)
        rows.append(("warn", measure(listing, [b.addr + len(trap) for b in traps], key_sites)))
    if jumps:
        targets = [j.target for j in jumps]
        jmp_now = [j for j in jumps if listing.kind_at(j.code) == JMP]
        nop_now = [j for j in jumps if listing.kind_at(j.code) == NOP]
        notes["key_sites_jmp_now"] = len(jmp_now)
        notes["key_sites_nop_now"] = len(nop_now)
        notes["key_sites_other"] = len(jumps) - len(jmp_now) - len(nop_now)
        rows.append(("key", measure(listing, targets, key_sites)))
        rows.append(("key, NOP sites", measure(listing, [j.target for j in nop_now], key_sites)))
        rows.append(("key, site jmps ignored", measure(listing, targets, key_sites, ignore=key_sites)))
    exs = t.get("ex") or []
    if exs:
        rows.append(("ex", measure(listing, [x.fixup for x in exs], key_sites)))
    return rows, notes


def table(rows):
    head = "%-23s %6s %15s %7s %8s %7s %6s %9s %8s %9s %9s %6s" % (
        "kind", "sites", "HIDDEN", "branch", "fallthr", "padding", "unal.", "distinct", "insns", "bytes", "union", "avg")
    out = [head, "-" * len(head)]
    for label, s in rows:
        r = s["reasons"]
        out.append("%-23s %6d %7d (%4.1f%%) %7d %8d %7d %6d %9d %8d %9d %9d %6.1f" % (
            label, s["sites"], s["hidden"], s["hidden_pct"], r["branch"], r["fallthrough"], r["padding"],
            r["unaligned"], s["hidden_distinct"], s["hidden_insns"], s["hidden_bytes"], s["hidden_union_bytes"],
            s["avg_insns"]))
    out.append("HIDDEN %: of sites - unal.; unal.: the target is not an instruction start in the listing (or outside "
               "every disassembled section)")
    out.append("distinct, insns, bytes, union, avg: the distinct HIDDEN targets and their out-of-line blocks")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("kernel")
    ap.add_argument("--json", help="write the numbers here")
    ap.add_argument("--objdump", default="objdump")
    ap.add_argument("--section", action="append", metavar="NAME",
                    help="disassemble only this executable section (repeatable; default: all of them). Targets "
                         "outside the chosen sections count as unaligned")
    a = ap.parse_args(argv)
    from kflow.cli import Elf, InputError, load
    t0 = time.time()
    try:
        elf = Elf(a.kernel)
    except (InputError, OSError) as e:
        print("reach: %s" % e, file=sys.stderr)
        return 2
    if elf.arch != "x86_64" or elf.relocatable:
        print("reach: x86_64 kernel images only (this is %s%s)" % (elf.arch, ", a module" if elf.relocatable else ""),
              file=sys.stderr)
        return 2
    t = load(elf)
    secs = exec_sections(elf)
    if a.section:
        missing = set(a.section) - {n for n, s, e in secs}
        if missing:
            print("reach: no executable section %s" % ", ".join(sorted(missing)), file=sys.stderr)
            return 2
        secs = [x for x in secs if x[0] in a.section]
    listing = disassemble(a.kernel, secs, a.objdump)
    rows, notes = rows_for(elf, t, listing)
    secs_text = ", ".join("%s %d KB" % (n, (e - s) // 1024) for n, s, e in secs[:6])
    if len(secs) > 6:
        secs_text += ", ... (%d sections)" % len(secs)
    print("kernel: %s" % a.kernel)
    print("disassembled: %s; %d instructions, %d direct branches/calls to %d distinct targets (%.0f s)"
          % (secs_text, listing.ninsns, listing.ntargets_total, len(listing.targets), time.time() - t0))
    if "key_sites_jmp_now" in notes:
        print("static-key sites in this file: %d NOP, %d jmp (already branch to their target), %d other"
              % (notes["key_sites_nop_now"], notes["key_sites_jmp_now"], notes["key_sites_other"]))
    if notes.get("warn_not_ud2"):
        print("WARN sites that are not ud2 here (skipped): %d" % notes["warn_not_ud2"])
    for line in table(rows):
        print(line)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"kernel": a.kernel, "sections": [[n, s, e] for n, s, e in secs], "instructions": listing.ninsns,
                       "notes": notes, "rows": {label: s for label, s in rows}}, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
