"""Loads kflow_entry.py (the IDA plugin) on fake ida_* modules backed by a kernel ELF and runs its annotation, list,
Go to oops/WARN line and remove actions, then the Hex-Rays pseudocode comments on a fake ida_hexrays: it proves the
plugin wiring runs, not that IDA or the real decompiler behave like the fakes.
Usage: python3 tests/test_entry_stub.py <kernel.elf>   (SKIPs without a path)"""
import bisect
import collections
import dataclasses
import importlib
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
if len(sys.argv) < 2:
    print("SKIP: pass a kernel ELF path")
    sys.exit(0)
import test_ida_stub as T  # noqa: E402
from kflow.cli import Elf  # noqa: E402

cli_elf = Elf(sys.argv[1])
elf = T.PackedElf(sys.argv[1]) if cli_elf.relocatable else cli_elf  # a module as IDA lays it out: imports packed
w = T.world_from(elf)
T.install(w)
log = []
ui = T.install_ui(w, log)  # fake ida_kernwin / ida_funcs / ida_lines / plugin_t, shared with test_warnflow_stub.py
get_func = ui.get_func
sys.modules["ida_hexrays"] = None  # no decompiler: "import ida_hexrays" fails, the plugin works as before
sys.path.insert(0, os.path.join(HERE, ".."))
sys.modules.pop("kflow_entry", None)
m = importlib.import_module("kflow_entry")
p = m.PLUGIN_ENTRY()
ACTION_NAMES = ["kflow:annotate", "kflow:list", "kflow:keys", "kflow:oops", "kflow:remove", "kflow:warnflow",
                "kflow:warnflow_off"]
assert p.init() == 1 and [x[1] for x in log if x[0] == "reg"] == ACTION_NAMES
assert m.STATE["hx"] is None
assert m.AnnotateAction().activate(None) == 1
assert [x for x in log if x[0] == "msg" and "jump references added: " in x[1] and "static-key site -> key references: " in x[1]], "Annotate reports its counts"
assert not [x for x in log if x[0] == "msg" and "auto-analysis is still running" in x[1]]
# Annotate while auto-analysis still runs (no instructions, no functions yet): it works, adds no reference from a site
# that is not an instruction yet, and says to run it again afterwards
w["auto_ok"], w["code"] = False, set()
before = (dict(w["xrefs"]), dict(w["drefs"]))
assert m.AnnotateAction().activate(None) == 1
assert [x for x in log if x[0] == "msg" and "auto-analysis is still running" in x[1]]
# the count names static-key / exception-table sites only (BUG/WARN sites get comments, no references): a module with
# neither table (Debian arm64 vfat.ko: 5 BUG/WARN sites) has nothing to count and no such line
refd = bool(m.STATE["tables"].get("jump") or m.STATE["tables"].get("ex"))
assert bool([x for x in log if x[0] == "msg" and "sites are not instructions yet" in x[1]]) == refd, refd
assert (w["xrefs"], w["drefs"]) == before, "references added from addresses that are not instructions"
w["auto_ok"] = True
w.pop("code")
assert any(c.startswith("kflow: ") for c in w["cmts"].values())
assert ("hide", None) in log and not [x for x in log if x[0] == "warning"], log[-3:]
assert m.ListAction().activate(None) == 1
shown = [x for x in log if x[0] == "show"]
assert shown and shown[0][2] == len(m.STATE["tables"]["bug"]), shown
ch = m.SitesChooser([(0x10, "0x10", "WARN", "f", "a.c:1")])
assert ch.OnGetLine(0) == ("0x10", "WARN", "f", "a.c:1") and ch.OnSelectLine(0) == (0,) and ("jump", 0x10) in log
keys = m.KeySitesAction().activate(None)
jumps = m.STATE["tables"]["jump"]
if jumps:
    assert keys == 1, keys
    kshown = [x for x in log if x[0] == "show"][-1]
    assert kshown[1] == "kflow: static-key sites" and kshown[2] == len(jumps), kshown
    rows = m.key_site_rows(m.STATE["tables"])
    j = jumps[0]
    assert rows[0][0] == j.code and rows[0][3] == ("likely" if j.branch else "unlikely") and rows[0][4] in ("jump", "no jump")
    nj = sum(r[4] == "jump" for r in rows)
    assert 0 < nj < len(rows) or len(rows) < 50 or elf.relocatable, nj  # kernels have both states; a module on disk is all NOPs
    if elf.relocatable:  # the list names each module key as the command line does, although IDA packs the imports
        want = [cli_elf.key_name(c.key) or "0x%X" % c.key for c in T.load(cli_elf).get("jump", [])]
        bad = [(r[1], r[2], x) for r, x in zip(rows, want) if r[2] != x]
        assert len(want) == len(rows) and not bad, bad[:5]
        print("  static-key list on the packed module: %d rows, every key named as on the command line" % len(rows))
else:
    assert keys == 0


# ---- Go to oops/WARN line: pasted kernel log text -> the BUG/WARN site (ask_text answers w["ask_text"]) ----
def ask(text):
    w["ask_text"] = text
    n = len(log)
    return m.OopsAction().activate(None), log[n:]


def went(new):
    return [x[1] for x in new if x[0] == "jump"]


def said(new, text):
    return [x[1] for x in new if x[0] == "msg" and text in x[1]]


bugs = m.STATE["tables"]["bug"]
at_addr = collections.Counter(b.addr for b in bugs)
mod = m.oops.module_name(sys.argv[1])
modtag = " [%s]" % mod if mod else ""  # the kernel prints module code as 'func+0x10/0x20 [mod]'
reg, trace = {"x86_64": ("RIP: 0010:", "Call Trace:"), "aarch64": ("pc : ", "Call trace:")}[elf.arch]


def only_function(b):  # (name, start, size) of the function IDA has under that name, if the site is in it
    f, name = get_func(b.addr), ui.fn.get_func_name(b.addr)
    if f is None or not name or [c[:2] for c in m.function_starts(name)] != [(f.start_ea, f.end_ea - f.start_ea)]:
        return None
    return name, f.start_ea, f.end_ea - f.start_ea


site = next((b for b in bugs if b.warn and b.file and at_addr[b.addr] == 1 and only_function(b)), None)
oops_done = []
if site is not None:
    name, start, size = only_function(site)
    off = site.addr - start
    text = "\n".join(["[  152.334198][  T123] ------------[ cut here ]------------",
                      "[  152.334201][  T123] WARNING: CPU: 1 PID: 123 at %s:%d %s+%#x/%#x%s" % (site.file, site.line, name,
                                                                                            off, size, modtag),
                      "[  152.334230][  T123] Modules linked in:%s" % (" " + mod if mod else ""),
                      "[  152.334270][  T123] %s%s+%#x/%#x%s" % (reg, name, off, size, modtag),
                      "[  152.334300][  T123] " + trace,
                      "[  152.334305][  T123]  ? __warn+0x89/0x130",
                      "[  152.334340][  T123]  some_caller+0x5d1/0x1e70"])
    r, new = ask(text)
    assert r == 1 and went(new) == [site.addr], new
    assert new[0] == ("ask", 0, "", m.OOPS_PROMPT), new[0]
    assert said(new, "exact: the WARN site at %s+%#x (%#x)" % (name, off, site.addr)), new
    assert not [x for x in new if x[0] in ("warning", "show")], new
    r, new = ask("%s+%#x" % (name, off))  # just func+0xoff; the dialog offers the last text
    assert r == 1 and went(new) == [site.addr] and new[0][2] == text, new
    # the module the log names is passed on (review s157 m7, M65): a note says this file is not that module
    r, new = ask("%s%s+%#x/%#x [kflow_other_mod]" % (reg, name, off, size))
    assert went(new) == [site.addr] and said(new, "the log puts %s in module kflow_other_mod; this file is %s" % (
        name, ("module " + mod) if mod else "not that module (vmlinux?): open kflow_other_mod.ko")), new
    gap = next((d for d in range(1, size - off) if start + off + d not in at_addr), None)
    if gap is not None:  # an offset with no site: go to the log's address and list the function's sites
        r, new = ask("%s%s+%#x/%#x%s" % (reg, name, off + gap, size, modtag))
        assert r == 1 and went(new) == [site.addr + gap] and said(new, "not exact: no BUG/WARN site at %s+%#x" % (name, off + gap))
    # an offset past the end of the function here (a log from another build): its sites in a chooser, no jump
    r, new = ask("%s%s+%#x/%#x%s" % (reg, name, size, 2 * size, modtag))
    want = sorted(b.addr for b in bugs if start <= b.addr < start + size)
    assert r == 1 and not went(new) and [x for x in new if x[0] == "show"] == [
        ("show", "kflow: BUG/WARN sites in %s" % name, len(want))], new
    assert sorted(row[0] for row in w["shown"].rows) == want and said(new, "is past the end of %s" % name), new
    # the log's own WARNING line names another file:line (another build, or two reports pasted): a warning and the
    # chooser, never a jump
    r, new = ask(text.replace("at %s:%d " % (site.file, site.line), "at %s:%d " % (site.file, site.line + 100000)))
    assert r == 1 and not went(new) and [x[:2] for x in new if x[0] == "show"] == [
        ("show", "kflow: BUG/WARN sites at %s+%#x" % (name, off))], new
    assert [x for x in new if x[0] == "warning" and "does not fit this file: the WARN site at %s+%#x is at %s"
            % (name, off, site.where()) in x[1]] and said(new, "mismatch: "), new
    oops_done.append("WARNING/%s line and func+0xoff -> 0x%X (%s+%#x)%s; past the end -> %d rows; another line -> "
                     "mismatch, no jump" % (reg.split(":")[0].strip(), site.addr, name, off,
                                            ", near offset" if gap is not None else "", len(want)))
# a static function (IDA shows one function under a name; the kernel may have several static functions of that name):
# found from the RIP / pc line alone, a note says another one is not tried; its own WARNING / kernel BUG line confirms
# the site (no note); a global or weak function needs no note (review s157 m3)
b = next((b for b in bugs if b.file and at_addr[b.addr] == 1 and only_function(b)), None)
if b is not None:
    name, start, size = only_function(b)
    at = "%s+%#x/%#x%s" % (name, b.addr - start, size, modtag)
    head = ("WARNING: CPU: 1 PID: 9 at %s:%d %s\n" % (b.file, b.line, at) if b.warn else
            "kernel BUG at %s:%d!\n" % (b.file, b.line))
    saved = {k: set(getattr(elf, k, ())) for k in ("public", "weak")}
    for kind in ("static", "global", "weak"):  # the function's symbol made each kind in turn (IDA: neither, public, weak)
        elf.public, elf.weak = saved["public"] - {start}, saved["weak"] - {start}
        if kind != "static":
            getattr(elf, "public" if kind == "global" else "weak").add(start)
        r, new = ask(reg + at)
        assert r == 1 and went(new) == [b.addr] and bool(said(new, "%s is a static function, and IDA names only one "
                                                                 "function so" % name)) == (kind == "static"), new
        r, new = ask(head + reg + at)
        assert r == 1 and went(new) == [b.addr] and not said(new, "is a static function"), new
        # review s159 NIT 1: its own line names another file:line (a mismatch, no jump): for a static function the
        # warning and the note also name IDA's one function of that name as a cause (gki61's two gic_smp_init)
        r, new = ask(head.replace("%s:%d" % (b.file, b.line), "%s:%d" % (b.file, b.line + 100000)) + reg + at)
        warned = [x[1] for x in new if x[0] == "warning" and "does not fit this file" in x[1]]
        cause = "or IDA shows another static function of that name (IDA names only one)"
        assert r == 1 and not went(new) and len(warned) == 1 and said(new, "mismatch: "), new
        assert (cause in warned[0]) == (kind == "static") and bool(said(new, cause)) == (kind == "static"), new
        assert kind == "static" or "(a log from another build, or two reports in one paste?)" in warned[0], warned
    elf.public, elf.weak = saved["public"], saved["weak"]
    oops_done.append("%s as a static function: note without its own line; global or weak: no note; another line: "
                     "mismatch, warning and note name IDA's one static function of that name as a cause" % name)
if any(b.addr == 0xFFFFFFFF8E629BC4 and b.where() == "mm/userfaultfd.c:755" for b in bugs):  # the MemLens demo kernel
    # the review's example: four functions share mm/userfaultfd.c:755; the WARNING line's func+0xoff picks one
    r, new = ask("WARNING: CPU: 1 PID: 9 at mm/userfaultfd.c:755 mfill_atomic_copy+0x674/0x...")
    assert r == 1 and went(new) == [0xFFFFFFFF8E629BC4], new
    r, new = ask("mm/userfaultfd.c:755")
    assert [ui.fn.get_func_name(row[0]) for row in w["shown"].rows] == [
        "mfill_atomic_copy", "mfill_atomic_zeropage", "mfill_atomic_continue", "mfill_atomic_poison"], new
    oops_done.append("demo kernel: mfill_atomic_copy+0x674 -> 0xFFFFFFFF8E629BC4, mm/userfaultfd.c:755 -> 4 rows")
# the size the kernel prints is measured to the next symbol (padding included): IDA's next name gives it, so a log of this
# build whose size is larger than the function's code gets no "size in the log" note
padded = None
for a, e, name in elf.funcs:
    c = m.function_starts(name)
    if len(c) == 1 and c[0][0] == a and c[0][1] and c[0][2] and c[0][2] != c[0][1] and a not in at_addr:
        padded = (name, c[0])
        break
# review s159 NIT 3: the check must not skip silently when this kernel has a function whose printed size differs from its code
assert padded is not None or not any(cli_elf.printed_size(a) not in (None, e - a) for a, e, _ in elf.funcs
                                     if len(m.function_starts(_)) == 1 and a not in at_addr), "printed() found no padded function"
if padded is not None:
    name, (a, size, printed, _) = padded
    assert printed == cli_elf.printed_size(a) or cli_elf.relocatable, (name, printed, cli_elf.printed_size(a))
    r, new = ask("%s%s+0x0/%#x%s" % (reg, name, printed, modtag))
    assert r == 1 and went(new) == [a] and not said(new, "size in the log"), new
    r, new = ask("%s%s+0x0/%#x%s" % (reg, name, printed + 8, modtag))
    assert said(new, "size in the log %#x, here %#x" % (printed + 8, printed)), new
    oops_done.append("printed size %#x of %s (code %#x): no size note" % (printed, name, size))
# a name the log prints without the suffix the database has (Clang LTO: the kernel cuts foo.123 at the first dot); GCC's
# foo.isra.0 / foo.part.0 are printed in full, so the cut name must not lead there
def cut_site(lto):
    for b in bugs:
        full = ui.fn.get_func_name(b.addr)
        base = full.split(".")[0] if full else ""
        if (at_addr[b.addr] == 1 and "." in full and m.oops.lto_suffix(full, base) == lto and get_func(b.addr) is not None
                and get_func(b.addr).start_ea == elf.symbols.get(full)
                and sys.modules["ida_name"].get_name_ea(T.BAD, base) == T.BAD):
            return b, base, full
    return None


# the plain name exists too (Clang LTO, review s157 M1: gic_smp_init and gic_smp_init.30554): the copy holding the
# site's offset is tried as well; with the site's own WARNING / kernel BUG line it is found, without one it is found or
# listed among the copies, never another site
both = next((b for b in bugs if at_addr[b.addr] == 1 and b.file and m.oops.lto_suffix(ui.fn.get_func_name(b.addr) or "",
                                                                                    ui.fn.get_func_name(b.addr).split(".")[0])
             and get_func(b.addr) is not None and get_func(b.addr).start_ea == elf.symbols.get(ui.fn.get_func_name(b.addr))
             and sys.modules["ida_name"].get_name_ea(T.BAD, ui.fn.get_func_name(b.addr).split(".")[0]) != T.BAD), None)
if both is not None:
    f, full = get_func(both.addr), ui.fn.get_func_name(both.addr)
    at = "%s%s+%#x/%#x%s" % (reg, full.split(".")[0], both.addr - f.start_ea, f.end_ea - f.start_ea, modtag)
    head = ("WARNING: CPU: 1 PID: 9 at %s:%d %s\n" % (both.file, both.line, at.split(reg, 1)[1]) if both.warn else
            "kernel BUG at %s:%d!\n" % (both.file, both.line))
    how = []
    for text in (head + at, at):  # copies at the same file:line (inlined code) stay candidates also with the line
        r, new = ask(text)
        shown = [x for x in new if x[0] == "show"]
        assert r == 1 and (went(new) == [both.addr] or (not went(new) and shown and both.addr in [
            row[0] for row in w["shown"].rows] and not [x for x in new if x[0] == "warning"])), new
        how.append("%d rows" % shown[0][2] if shown else "jump")
    oops_done.append("%s+off: %s with its own line -> %s, without -> %s" % (full.split(".")[0], full, how[0], how[1]))
for lto in (True, False):
    c = cut_site(lto)
    if c is None:
        continue
    b, base, full = c
    f = get_func(b.addr)
    r, new = ask("%s%s+%#x/%#x%s" % (reg, base, b.addr - f.start_ea, f.end_ea - f.start_ea, modtag))
    if lto:
        assert r == 1 and went(new) == [b.addr] and said(new, "exact: the %s site at %s+%#x" % (
            "WARN" if b.warn else "BUG", full, b.addr - f.start_ea)) and said(new, "%s in the log is %s in this file"
                                                                             % (base, full)), new
        oops_done.append("%s+off -> %s" % (base, full))
    else:
        assert r == 0 and not went(new) and said(new, "no function %s in this file" % base), new
        oops_done.append("%s+off -> not %s (GCC prints that name in full)" % (base, full))
# file:line only: one site -> go there; several -> the chooser with exactly those rows, Enter jumps
per_line = collections.Counter((b.file, b.line) for b in bugs if b.file)
one = next((k for k, n in per_line.items() if n == 1), None)
if one is not None:
    warn1 = next(b.warn for b in bugs if (b.file, b.line) == one)
    r, new = ask(("%s:%d" if warn1 else "kernel BUG at %s:%d!") % one)  # a WARNING line has a function+offset too
    want = next(b.addr for b in bugs if (b.file, b.line) == one)
    assert r == 1 and went(new) == [want] and said(new, "one BUG/WARN site at %s:%d" % one), new
    oops_done.append("%sfile:line (one site) -> 0x%X" % ("" if warn1 else "kernel BUG at ", want))
    # the same line, but the log names a function this file does not have: listed, not jumped to (review s157 m2)
    r, new = ask(("WARNING: CPU: 0 PID: 1 at %s:%d kflow_other_fn+0x10/0x20" if warn1 else
                  "kernel BUG at %s:%d!\n" + reg + "kflow_other_fn+0x10/0x20") % one)
    assert r == 1 and not went(new) and [x[:2] for x in new if x[0] == "show"] == [
        ("show", "kflow: BUG/WARN sites at %s:%d" % one)] and [x for x in new if x[0] == "warning"
                                                               and "kflow_other_fn+0x10 is not in this file" in x[1]], new
    oops_done.append("the same with a function not in this file -> listed, no jump")
many = max(per_line, key=per_line.get) if per_line and max(per_line.values()) > 1 else None
if many is not None:
    want = sorted(b.addr for b in bugs if (b.file, b.line) == many)
    r, new = ask("<4>[   12.345678] %s:%d" % many)
    assert r == 1 and not went(new), new
    assert [x for x in new if x[0] == "show"] == [("show", "kflow: BUG/WARN sites at %s:%d" % many, len(want))], new
    assert [row[0] for row in w["shown"].rows] == want and said(new, "ambiguous: %d BUG/WARN sites" % len(want))
    w["shown"].OnSelectLine(len(want) - 1)
    assert log[-1] == ("jump", want[-1])
    oops_done.append("file:line -> %d candidate rows" % len(want))
if site is not None:  # jumpto() fails (an address outside the database): a warning, not silence
    jumpto = sys.modules["ida_kernwin"].jumpto
    sys.modules["ida_kernwin"].jumpto = lambda ea: False
    r, new = ask("%s+%#x" % (only_function(site)[0], site.addr - only_function(site)[1]))
    sys.modules["ida_kernwin"].jumpto = jumpto
    assert r == 0 and [x for x in new if x[0] == "warning" and "could not jump to 0x%X" % site.addr in x[1]], new
    oops_done.append("jumpto failing -> warned")
r, new = ask("hello, world")  # nothing usable: a warning, no jump
assert r == 0 and not went(new) and [x for x in new if x[0] == "warning" and "found no WARNING" in x[1]], new
r, new = ask("%skflow_no_such_function+0x10/0x20" % reg)  # a function this file does not have
assert r == 0 and not went(new) and [x for x in new if x[0] == "warning" and "no BUG/WARN site or function" in x[1]]
assert said(new, "no function kflow_no_such_function in this file"), new
r, new = ask(None)  # the dialog was cancelled
assert r == 0 and [x[0] for x in new] == ["ask"], new
print("OK oops: %s; no match / unknown function warned; cancel does nothing"
      % ("; ".join(oops_done) or "no site with a function symbol in this file"))

assert m.RemoveAction().activate(None) == 1
assert not any(c.startswith("kflow") for c in w["cmts"].values())
# a database that is not a supported kernel: one warning, nothing written
sys.modules["ida_ida"].inf_is_64bit = lambda: False
m.STATE["tables"] = None
assert m.AnnotateAction().activate(None) == 0 and "not a 64-bit" in [x for x in log if x[0] == "warning"][-1][1]
p.term()
assert [x[1] for x in log if x[0] == "unreg"] == ACTION_NAMES
assert not [x for x in log if x[0] == "msg" and "pseudocode" in x[1]], "no decompiler: no pseudocode messages"
print("OK entry: plugin loads, Annotate / List (%d rows) / List static keys (%d rows) / Remove run, unsupported database warned" % (shown[0][2], len(jumps)))
sys.modules["ida_ida"].inf_is_64bit = lambda: True

# ---- Hex-Rays pseudocode comments, on a fake ida_hexrays ----
hx_log = {"hooked": 0, "flushed": 0}


def fake_hexrays(available=True):
    hx = types.ModuleType("ida_hexrays")

    class Hexrays_Hooks:
        def hook(self):
            hx_log["hooked"] += 1
            return True

        def unhook(self):
            hx_log["hooked"] -= 1
            return True
    hx.Hexrays_Hooks = Hexrays_Hooks
    hx.init_hexrays_plugin = lambda flags=0: available() if callable(available) else available
    hx.clear_cached_cfuncs = lambda: hx_log.update(flushed=hx_log["flushed"] + 1)
    hx_log["dc"] = T.add_decompiler(hx, lambda: sys.modules["kflow.idalayer"].annotated())
    sys.modules["ida_hexrays"] = hx


def load_plugin():
    sys.modules.pop("kflow_entry", None)
    mod = importlib.import_module("kflow_entry")
    plugin = mod.PLUGIN_ENTRY()
    assert plugin.init() == 1
    return mod, plugin


def msgs(text):
    return [x[1] for x in log if x[0] == "msg" and text in x[1]]


# a decompiler that is there but refuses (init_hexrays_plugin() false): no hook, Annotate as before
fake_hexrays(available=False)
m, p = load_plugin()
assert m.AnnotateAction().activate(None) == 1 and m.STATE["hx"] is None and hx_log["hooked"] == 0
assert any(c.startswith("kflow: ") for c in w["cmts"].values()) and not msgs("pseudocode")
assert m.RemoveAction().activate(None) == 1 and hx_log["flushed"] == 0
p.term()


class Line:
    def __init__(self, text):
        self.line = text


class FakeCfunc:
    """A decompiled function: pseudocode lines, an eamap (address -> statements) and each statement's (x, y);
    find_item_coords returns (None, None) for an item that is not in the text, like IDAPython."""

    def __init__(self, lines, eamap, coords, entry_ea):
        self.sv, self.eamap, self.coords, self.entry_ea = [Line(t) for t in lines], eamap, coords, entry_ea

    def get_eamap(self):
        return self.eamap

    def get_pseudocode(self):
        return self.sv

    def find_item_coords(self, item):
        return self.coords.get(item, (None, None))


def decompile(eas, entry=0, extra=()):
    """Print a fake function with one statement line per address in eas through the hook; returns {address: the
    comment appended to its line, '' if none}. extra: more items at eas[0] (one not in the text, one off the end)."""
    lines = ["void f(void)", "{"] + ["  s%d;" % i for i in range(len(eas))] + ["}"]
    eamap = {ea: ["s%d" % i] for i, ea in enumerate(eas)}
    coords = {"s%d" % i: (2, 2 + i) for i in range(len(eas))}
    for item in extra:
        eamap[eas[0]].append(item)
    coords["far"] = (0, 99)
    coords["same"] = (6, 2)  # a second item of eas[0] on the same line (an expression inside the statement)
    cf = FakeCfunc(lines, eamap, coords, entry)
    m.STATE["hx_error"] = False  # a crash inside the hook must not pass as "no comment"
    assert m.STATE["hx"].func_printed(cf) == 0
    assert not m.STATE["hx_error"], "the pseudocode hook raised (see the Output messages)"
    out = {}
    for i, ea in enumerate(eas):
        line = cf.sv[2 + i].line
        assert line.startswith(lines[2 + i])
        tail = line[len(lines[2 + i]):]
        if tail:
            assert tail.startswith("\x01\x04  // ") and tail.endswith("\x02\x04"), repr(tail)
            tail = tail[len("\x01\x04  // "):-len("\x02\x04")]
        out[ea] = tail
    assert [ln.line for ln in cf.sv[:2]] + [cf.sv[-1].line] == lines[:2] + [lines[-1]]
    return out


fake_hexrays()
m, p = load_plugin()
il = m.idalayer
assert hx_log["hooked"] == 1 and m.STATE["hx"] is not None and not w["netnodes"]
arch = il.current_arch()
t = il.scan()
count = {}
for ea in [b.addr for b in t["bug"]] + [j.code for j in t["jump"]] + [x.insn for x in t["ex"]]:
    count[ea] = count.get(ea, 0) + 1
all_eas = sorted(count)
one = lambda ea: count[ea] == 1 and il.in_text(ea)  # a site alone at its address
TRAP = {"x86_64": b"\x0f\x0b", "aarch64": b"\x00\x00\x20\xd4"}[elf.arch]  # ud2, brk #0x800
bug = next((b for b in t["bug"] if b.warn and b.file and one(b.addr) and elf.read(b.addr, len(TRAP)) == TRAP), None) or \
    next((b for b in t["bug"] if one(b.addr)), None)
ex = next((x for x in t["ex"] if one(x.insn)), None)
key = next((j for j in t["jump"] if one(j.code)), None)
NOPS = {"x86_64": {b"\x0f\x1f\x44\x00\x00": 5, b"\x66\x90": 2}, "aarch64": {b"\x1f\x20\x03\xd5": 4}}[elf.arch]


def nop_len(ea):
    return next((n for raw, n in NOPS.items() if elf.read(ea, len(raw)) == raw), None)


def lone_nop(j):  # a NOP site in a function, the next site more than NOP_WINDOW + 1 bytes on, not at its entry
    if not one(j.code) or not nop_len(j.code) or get_func(j.code) is None or get_func(j.code).start_ea == j.code:
        return False
    i = bisect.bisect_right(all_eas, j.code)
    return i == len(all_eas) or all_eas[i] > j.code + m.NOP_WINDOW + 1


nop = next((j for j in t["jump"] if j is not key and lone_nop(j)), None) or next((j for j in t["jump"] if lone_nop(j)), None)
samples = [s for s in (bug, key, ex) if s is not None]
sample_eas = [getattr(s, "addr", None) or getattr(s, "code", None) or s.insn for s in samples]
assert samples and (nop is not None or not t["jump"] or not elf.funcs), "no NOP static-key site to test"

# before Annotate: the hook is there, the lines are untouched
assert set(decompile(sample_eas).values()) == {""}
assert m.AnnotateAction().activate(None) == 1 and hx_log["flushed"] == 1 and msgs("pseudocode comments on")
shown_texts = []
if bug is not None:
    got = decompile([bug.addr], extra=("lost", "far"))[bug.addr]
    assert got == il.bug_comment(bug) and got.startswith("kflow: " + ("WARN" if bug.warn else "BUG")), got
    assert (bug.where() or "") in got and (("continues" in got) if bug.warn else ("does not return" in got)), got
    shown_texts.append(("BUG/WARN", bug.addr, got))
    assert decompile([bug.addr], extra=("same",))[bug.addr] == got  # two items of one address on one line: one copy
if ex is not None:
    got = decompile([ex.insn])[ex.insn]
    assert got == il.ex_comment(ex, arch) and "fixup at 0x%X" % ex.fixup in got, got
    shown_texts.append(("exception", ex.insn, got))
if key is not None:
    when = "jumps to 0x%X when the key is %s" % (key.target, "off" if key.branch else "on")
    want = "kflow: static key %s (%s): %s" % (il.key_name(key.key), "likely" if key.branch else "unlikely", when)
    got = decompile([key.code])[key.code]
    assert got == want and il.jump_comment(key).endswith("; " + when), (got, il.jump_comment(key))
    shown_texts.append(("static key", key.code, got))
    # the site has its own statement: the next statement (within 16 bytes, same function) gets no second copy
    kf, nxt = get_func(key.code), key.code + 5
    if kf is not None and not any(key.code < e <= nxt for e in m.STATE["pseudo"]["eas"]):  # no other site up to nxt
        assert decompile([key.code, nxt], entry=kf.start_ea) == {key.code: want, nxt: ""}
exact = list(shown_texts)  # (kind, address, text) of the sites whose own address has a statement
if nop is not None:
    f = get_func(nop.code)
    n = nop_len(nop.code)
    want = "kflow: static key %s (%s) at 0x%X, just before this line: jumps to 0x%X when the key is %s" % (
        il.key_name(nop.key), "likely" if nop.branch else "unlikely", nop.code, nop.target, "off" if nop.branch else "on")
    assert decompile([f.start_ea, nop.code + n], entry=f.start_ea) == {f.start_ea: "", nop.code + n: want}
    shown_texts.append(("static key, NOP not in eamap", nop.code, "line of 0x%X: %s" % (nop.code + n, want)))
    w16 = nop.code + m.NOP_WINDOW
    assert decompile([w16], entry=f.start_ea) == {w16: want}  # 16 bytes on: still attached
    assert decompile([w16 + 1], entry=f.start_ea) == {w16 + 1: ""}  # 17: too far, no comment
    k2 = nop.code + n + 1  # only the first address after the site that has a statement gets the comment
    assert decompile([nop.code + n, k2], entry=f.start_ea) == {nop.code + n: want, k2: ""}
    assert decompile([nop.code + n], entry=f.start_ea + 1) == {nop.code + n: ""}  # site not in this function
    # another kflow site in between (a synthetic BUG one byte on): the static key stops there, nothing shown
    pm = m.STATE["pseudo"]
    pm["sites"][nop.code + 1] = [("bug", il.core.BugSite(nop.code + 1, "x.c", 1, 0))]
    pm["eas"] = sorted(pm["sites"])
    assert decompile([nop.code + n], entry=f.start_ea) == {nop.code + n: ""}
    del pm["sites"][nop.code + 1]
    pm["eas"] = sorted(pm["sites"])
    # a static-key site a few bytes before the NEXT function's entry: that function's first line gets nothing (the
    # site's function decides, not the function of the line); synthetic site 8 bytes before a function start
    g = next((fs for fs in sorted({get_func(e).start_ea for e in all_eas if get_func(e) is not None})
              if not any(fs - 8 <= e <= fs for e in pm["eas"])), None)
    if g is not None:
        pm["sites"][g - 8] = [("jump", dataclasses.replace(nop, code=g - 8))]
        pm["eas"] = sorted(pm["sites"])
        assert decompile([g], entry=g) == {g: ""}, "comment crossed into the next function"
        del pm["sites"][g - 8]
        pm["eas"] = sorted(pm["sites"])
    # a statement before the first site of a database that has one site: nothing (no wrap-around to the last site)
    saved_sites, saved_eas = pm["sites"], pm["eas"]
    pm["sites"], pm["eas"] = {nop.code: saved_sites[nop.code]}, [nop.code]
    assert decompile([f.start_ea], entry=f.start_ea) == {f.start_ea: ""}, "a line before the only site got its comment"
    pm["sites"], pm["eas"] = saved_sites, saved_eas
# a function with none of the sites
assert decompile([1, 2, 3]) == {1: "", 2: "", 3: ""}
# Annotate again: the map is rebuilt, the comments are not doubled
old_map = m.STATE["pseudo"]
assert m.AnnotateAction().activate(None) == 1 and m.STATE["pseudo"] is not old_map and hx_log["flushed"] == 2
for kind, ea, text in exact:
    assert decompile([ea])[ea] == text, (kind, text)
# the annotation record disappears without Remove (IDA undo of Annotate, or the headless runner's --remove): the
# cached map must not keep showing comments
saved = w["netnodes"].pop(il.NODE)
for kind, ea, text in exact:
    assert decompile([ea])[ea] == "", ("record gone, comment still shown", kind)
w["netnodes"][il.NODE] = saved
p.term()
assert hx_log["hooked"] == 0 and m.STATE["hx"] is None and m.STATE["pseudo"] is None

# a new IDA session on the annotated database in which the decompiler loads after kflow (review s158 F3): IDAPython
# initialises its Hex-Rays bindings on ui_plugin_loaded, so init_hexrays_plugin() is False at kflow's init and True
# later; when a plugin loads after that, the pseudocode hook goes in and the comments show without Annotate again
hx_now = [False]
fake_hexrays(available=lambda: hx_now[0])
n0 = len(log)
m, p = load_plugin()
assert m.STATE["hx"] is None and hx_log["hooked"] == 0
late = [x[1] for x in log[n0:] if x[0] == "ui_hook"]


def plugin_loaded():
    for h in late:
        h.plugin_loaded(None)


plugin_loaded()  # another plugin, still no decompiler: nothing
assert m.STATE["hx"] is None and hx_log["hooked"] == 0
hx_now[0] = True  # the decompiler loads
plugin_loaded()
assert m.STATE["hx"] is not None and hx_log["hooked"] == 1, "no pseudocode hook after the decompiler loaded late"
assert msgs("decompiler loaded: pseudocode comments on")
for kind, ea, text in exact:
    assert decompile([ea])[ea] == text, (kind, text)
plugin_loaded()  # more plugins later: still one hook
assert hx_log["hooked"] == 1
p.term()
assert hx_log["hooked"] == 0 and [x[1] for x in log[n0:] if x[0] == "ui_unhook"] == late and len(late) == 1
seen = len(msgs("database annotated earlier"))
fake_hexrays()
# a new IDA session on the annotated database: the first function printed reads the tables again
m, p = load_plugin()
il = m.idalayer
assert hx_log["hooked"] == 1 and il.annotated()
assert not [x for x in log[n0:] if x[0] == "ui_hook" and x[1] not in late], "no UI hook when the decompiler is there"
for kind, ea, text in exact:
    assert decompile([ea])[ea] == text, (kind, text)
assert len(msgs("database annotated earlier")) == seen + 1
# rebase: the segments change, the map is rebuilt from the tables at their new addresses; old addresses show nothing
delta = 0x200000
real_scan, scans = il.scan, []


def shifted_scan():
    scans.append(1)
    t0 = real_scan()
    sh = lambda v: None if v is None else v + delta
    return dict(t0, bug=[dataclasses.replace(b, addr=b.addr + delta) for b in t0["bug"]],
                jump=[dataclasses.replace(j, code=j.code + delta, target=j.target + delta, key=j.key + delta) for j in t0["jump"]],
                ex=[dataclasses.replace(x, insn=x.insn + delta, fixup=x.fixup + delta, handler=sh(x.handler)) for x in t0["ex"]])


il.scan = shifted_scan
w["segs"][-1].end_ea += 0x1000
moved = {s.addr if hasattr(s, "addr") else s.code if hasattr(s, "code") else s.insn: s for s in samples}
for ea, s in moved.items():
    assert decompile([ea])[ea] == "", "stale address after a rebase"
    got = decompile([ea + delta])[ea + delta]
    if hasattr(s, "addr"):
        assert got == il.bug_comment(s), got
    elif hasattr(s, "insn"):
        assert got == il.ex_comment(dataclasses.replace(s, fixup=s.fixup + delta, handler=None if s.handler is None else s.handler + delta), arch)
        assert "fixup at 0x%X" % (s.fixup + delta) in got, got
    else:
        assert "jumps to 0x%X when" % (s.target + delta) in got, got
assert scans == [1] and len(msgs("rebase?")) == 1, (scans, msgs("rebase?"))
il.scan = real_scan
w["segs"][-1].end_ea -= 0x1000
# an exception inside the hook: caught, reported once, the decompiler gets 0
hooks = m.STATE["hx"]


class Broken:
    entry_ea = 0

    def get_eamap(self):
        raise RuntimeError("boom")


assert hooks.func_printed(Broken()) == 0 and hooks.func_printed(Broken()) == 0 and hooks.func_printed(None) == 0
assert len(msgs("pseudocode comment failed")) == 1
# Remove: the comments go, cached decompilations are dropped
flushed = hx_log["flushed"]
assert m.RemoveAction().activate(None) == 1 and hx_log["flushed"] == flushed + 1 and m.STATE["pseudo"] is None
assert not il.annotated() and set(decompile([ea for _, ea, _ in exact] or [1]).values()) == {""}
p.term()
assert hx_log["hooked"] == 0 and not any(c.startswith("kflow") for c in w["cmts"].values())
# ---- the decompile check inside Annotate (kflow/selfcheck.py), on the fake decompiler ----
fake_hexrays()
m, p = load_plugin()
il, sc = m.idalayer, m.selfcheck
dc = hx_log["dc"]
t = il.scan()
picked = sc.pick_functions(t, arch)
assert len(picked) <= sc.MAX_FUNCS and len(set(picked)) == len(picked)
assert all(get_func(ea) is not None and get_func(ea).start_ea == ea for ea in picked)
# review s174 api MINOR 4: very large functions are not picked (one huge decompile could blow the time budget)
if picked:
    big = max(picked, key=lambda ea: get_func(ea).end_ea - get_func(ea).start_ea)
    real_max = getattr(sc, "MAX_FUNC_BYTES", None)
    sc.MAX_FUNC_BYTES = get_func(big).end_ea - get_func(big).start_ea - 1
    small = sc.pick_functions(t, arch)
    sc.MAX_FUNC_BYTES = real_max
    assert big not in small and all(get_func(ea).end_ea - get_func(ea).start_ea <= get_func(big).end_ea - get_func(big).start_ea - 1
                                    for ea in small), (hex(big), len(small))


def check_lines(remove=True):
    """Annotate once (after Remove, so BEFORE sees the database without kflow's references); its decompile check
    lines. Annotate itself must always report its counts."""
    if remove:
        assert m.RemoveAction().activate(None) == 1 and not il.annotated()
    n = len(log)
    assert m.AnnotateAction().activate(None) == 1 and il.annotated()
    new = [x[1] for x in log[n:] if x[0] == "msg"]
    assert [x for x in new if "jump references added: " in x], new
    return [x for x in new if "decompile check" in x]


got = check_lines()
if picked:
    assert got == ["[kflow] decompile check: %d functions with static-key sites decompile before and after Annotate\n"
                   % len(picked)], got
    assert sorted(dc["calls"][-2 * len(picked):]) == sorted(picked * 2), "each picked function decompiled twice"
    # review s174 api MINOR 5: no Hex-Rays wait box of its own (a user Cancel there would read as a kflow failure)
    assert dc["flags"] and all(f & 1 for f in dc["flags"][-2 * len(picked):]), dc["flags"][-3:]
    # review s174 api MAJOR 1: IDA's auto-analysis runs after Annotate and before the AFTER pass
    assert T.AUTO_WAITS and T.AUTO_WAITS[-1] == len(dc["calls"]) - len(picked), (T.AUTO_WAITS[-3:], len(dc["calls"]))
    # fails after Annotate: blamed by name; the AFTER decompile is not the cached BEFORE result
    victim = picked[len(picked) // 2]
    dc["after"] = {victim}
    got = check_lines()
    assert len(got) == 1 and ("1 of %d functions decompiled before Annotate but fail after (%s)"
                              % (len(picked), ui.fn.get_func_name(victim) or "0x%X" % victim)) in got[0], got
    assert "kflow: Remove annotations takes them out" in got[0], got
    # review s174 api MINOR 6: the same when decompile() returns None instead of raising (current IDA)
    dc["none"] = True
    got_none = check_lines()
    dc["none"] = False
    assert got_none == got, (got_none, got)
    # fails already before Annotate (and after): counted apart, never blamed on kflow
    dc["always"], dc["after"] = {victim}, {victim}
    got = check_lines()
    assert len(got) == 1 and "fail after" not in got[0] and "1 more failed already before Annotate" in got[0], got
    if len(picked) > 1:
        assert "%d functions with static-key sites decompile before and after" % (len(picked) - 1) in got[0], got
    dc["always"], dc["after"] = set(), set()
    # re-review s174 MINOR 2: nothing decompiled before Annotate → nothing to re-check, so no auto_wait() either
    dc["always"] = set(picked)
    n_waits = len(T.AUTO_WAITS)
    got = check_lines()
    dc["always"] = set()
    assert len(T.AUTO_WAITS) == n_waits, "auto_wait with nothing to re-check"
    assert len(got) == 1 and "none of %d functions with static-key sites decompiled before Annotate" % len(picked) in got[0], got
    # time bound: each decompile takes 1.5 s on a fake clock; BEFORE stops after 5 s, AFTER gets its own 5 s (s174 F1)
    ticks = [0.0]

    def fake_clock():
        ticks[0] += 1.5
        return ticks[0]
    real_clock, sc.clock = sc.clock, fake_clock
    n_calls = len(dc["calls"])
    got = check_lines()
    sc.clock = real_clock
    if len(picked) >= 4:
        assert len(dc["calls"]) - n_calls == 4 + 4, dc["calls"][n_calls:]
        assert ("stopped after 12 s of decompiling: 4 of %d picked functions checked" % len(picked)) in got[0], got
        assert "4 functions with static-key sites decompile before and after Annotate" in got[0], got
    # reviews s174 api MINOR 3 / claims F1: one slow BEFORE decompile (12 s) must not leave AFTER without budget, and the
    # line must not say that nothing decompiled
    steps = iter([0.0, 12.0])

    def slow_first():
        ticks[0] += next(steps, 1.5)
        return ticks[0]
    ticks[0], sc.clock = 0.0, slow_first
    n_calls = len(dc["calls"])
    got = check_lines()
    sc.clock = real_clock
    assert len(dc["calls"]) - n_calls == 1 + 1, dc["calls"][n_calls:]
    assert "1 function with static-key sites decompiles before and after Annotate" in got[0], got
    assert "none of" not in got[0] and ("1 of %d picked functions checked" % len(picked)) in got[0], got
    # an exception inside the check: one 'skipped' line, Annotate still adds its comments and references
    dc["crash"] = "fake decompiler crash"
    got = check_lines()
    dc["crash"] = None
    assert got == ["[kflow] decompile check skipped: fake decompiler crash\n"], got
    # review s174 claims F2: an error inside the AFTER pass, and one from IDA's auto_wait(), also give one 'skipped' line
    dc["crash"], dc["crash_after_only"] = "fake crash after Annotate", True
    got = check_lines()
    dc["crash"], dc["crash_after_only"] = None, False
    assert got == ["[kflow] decompile check skipped: fake crash after Annotate\n"], got
    real_wait = sys.modules["ida_auto"].auto_wait

    def bad_wait():
        raise RuntimeError("fake auto_wait failure")
    sys.modules["ida_auto"].auto_wait = bad_wait
    got = check_lines()
    sys.modules["ida_auto"].auto_wait = real_wait
    assert got == ["[kflow] decompile check skipped: fake auto_wait failure\n"], got
    assert any(c.startswith("kflow: ") for c in w["cmts"].values()) and any(w["xrefs"].values())
    assert any(c.startswith("kflow: ") for c in w["cmts"].values()) and any(w["xrefs"].values())
else:
    assert got == ["[kflow] decompile check: no function has a static-key site that gets a new jump reference\n"], got
# s174 own review MINOR 1: while IDA's auto-analysis still runs, BEFORE/AFTER would compare a changing database, so the
# check is skipped (no decompile at all) and says why
assert picked, "the gate kernel must give the check something to pick"
w["auto_ok"] = False
n_calls, n_waits = len(dc["calls"]), len(T.AUTO_WAITS)
got = check_lines()
w["auto_ok"] = True
assert len(T.AUTO_WAITS) == n_waits, "no auto_wait while the check is skipped"
assert got == ["[kflow] decompile check skipped: IDA's auto-analysis is still running; after it finishes, Remove "
               "annotations and Annotate again to run the check\n"], got
assert len(dc["calls"]) == n_calls, "no decompile while auto-analysis runs"
real_pick = sc.pick_functions
sc.pick_functions = lambda t, arch, limit=0: 1 // 0
got = check_lines()
sc.pick_functions = real_pick
assert len(got) == 1 and got[0].startswith("[kflow] decompile check skipped: "), got
p.term()
# no decompiler (or it refuses): no check, no line
fake_hexrays(available=False)
m, p = load_plugin()
assert m.selfcheck.start(t, arch) is None
n_calls = len(hx_log["dc"]["calls"])
assert check_lines() == [] and len(hx_log["dc"]["calls"]) == n_calls
p.term()
print("OK decompile check: %d functions picked; all OK / fails after (blamed) / fails before (not blamed) / time bound / "
      "exception / no decompiler" % len(picked))
for kind, ea, text in shown_texts:
    print("  pseudocode, %s site 0x%X:  %s" % (kind, ea, text))
print("OK pseudocode: comments on BUG/WARN %s, static key %s, NOP static key %s, exception %s; none before Annotate, "
      "after Remove or at stale addresses after a rebase; no decompiler: no hook; decompiler loaded after kflow: hooked "
      "then; hook error reported once"
      % tuple("yes" if s is not None else "none in file" for s in (bug, key, nop, ex)))
