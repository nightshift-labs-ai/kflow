"""Loads kflow_entry.py (the IDA plugin) on fake ida_* modules backed by a kernel ELF and runs its four actions, then
the Hex-Rays pseudocode comments on a fake ida_hexrays: it proves the plugin wiring runs, not that IDA or the real
decompiler behave like the fakes.
Usage: python3 tests/test_entry_stub.py <kernel.elf>   (SKIPs without a path)"""
import bisect
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
kw = types.ModuleType("ida_kernwin")
kw.msg = lambda text: log.append(("msg", text))
kw.warning = lambda text: log.append(("warning", text))
kw.show_wait_box = lambda text: log.append(("wait", text))
kw.hide_wait_box = lambda: log.append(("hide", None))
kw.jumpto = lambda ea: log.append(("jump", ea)) or True
kw.AST_ENABLE_ALWAYS, kw.SETMENU_APP = 1, 0
kw.register_action = lambda desc: log.append(("reg", desc.name)) or True
kw.unregister_action = lambda name: log.append(("unreg", name)) or True
kw.attach_action_to_menu = lambda path, name, flags: True
kw.process_ui_action = lambda name: log.append(("ui", name)) or True


class action_handler_t:
    pass


class action_desc_t:
    def __init__(self, name, label, handler, *rest):
        self.name, self.label, self.handler = name, label, handler


class Choose:
    CHCOL_HEX, NOTHING_CHANGED = 1, 0

    def __init__(self, title, cols, flags=0):
        self.title, self.cols = title, cols

    def Show(self):
        log.append(("show", self.title, self.OnGetSize()))
        return 0


kw.action_handler_t, kw.action_desc_t, kw.Choose = action_handler_t, action_desc_t, Choose
fn = types.ModuleType("ida_funcs")
fn.get_func_name = lambda ea: elf.func(ea) or ""
FSTARTS = [f[0] for f in elf.funcs]


def get_func(ea):  # the function's entry chunk, from the ELF's function symbols
    i = bisect.bisect_right(FSTARTS, ea) - 1
    if i >= 0 and elf.funcs[i][0] <= ea < elf.funcs[i][1]:
        return types.SimpleNamespace(start_ea=elf.funcs[i][0], end_ea=elf.funcs[i][1])
    return None


fn.get_func = get_func
lines_mod = types.ModuleType("ida_lines")
lines_mod.SCOLOR_AUTOCMT = "\x04"
lines_mod.COLSTR = lambda text, tag: "\x01" + tag + text + "\x02" + tag  # SCOLOR_ON tag text SCOLOR_OFF tag
api = sys.modules["ida_idaapi"]


class plugin_t:
    pass


api.plugin_t, api.PLUGIN_KEEP = plugin_t, 1
sys.modules.update({"ida_kernwin": kw, "ida_funcs": fn, "ida_lines": lines_mod})
sys.modules["ida_hexrays"] = None  # no decompiler: "import ida_hexrays" fails, the plugin works as before
sys.path.insert(0, os.path.join(HERE, ".."))
sys.modules.pop("kflow_entry", None)
m = importlib.import_module("kflow_entry")
p = m.PLUGIN_ENTRY()
assert p.init() == 1 and [x[1] for x in log if x[0] == "reg"] == ["kflow:annotate", "kflow:list", "kflow:keys", "kflow:remove"]
assert m.STATE["hx"] is None
assert m.AnnotateAction().activate(None) == 1
assert [x for x in log if x[0] == "msg" and "jump references added: " in x[1] and "static-key site -> key references: " in x[1]], "Annotate reports its counts"
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
assert m.RemoveAction().activate(None) == 1
assert not any(c.startswith("kflow") for c in w["cmts"].values())
# a database that is not a supported kernel: one warning, nothing written
sys.modules["ida_ida"].inf_is_64bit = lambda: False
m.STATE["tables"] = None
assert m.AnnotateAction().activate(None) == 0 and "not a 64-bit" in [x for x in log if x[0] == "warning"][-1][1]
p.term()
assert [x[1] for x in log if x[0] == "unreg"] == ["kflow:annotate", "kflow:list", "kflow:keys", "kflow:remove"]
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
    hx.init_hexrays_plugin = lambda flags=0: available
    hx.clear_cached_cfuncs = lambda: hx_log.update(flushed=hx_log["flushed"] + 1)
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

# a new IDA session on the annotated database: the first function printed reads the tables again
m, p = load_plugin()
il = m.idalayer
assert hx_log["hooked"] == 1 and il.annotated()
for kind, ea, text in exact:
    assert decompile([ea])[ea] == text, (kind, text)
assert len(msgs("database annotated earlier")) == 1
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
for kind, ea, text in shown_texts:
    print("  pseudocode, %s site 0x%X:  %s" % (kind, ea, text))
print("OK pseudocode: comments on BUG/WARN %s, static key %s, NOP static key %s, exception %s; none before Annotate, "
      "after Remove or at stale addresses after a rebase; no decompiler: no hook; hook error reported once"
      % tuple("yes" if s is not None else "none in file" for s in (bug, key, nop, ex)))
