"""WARN fall-through (kflow/warnflow.py, experimental) through the plugin's two actions, on fake ida_* modules backed by
a kernel ELF. It proves the wiring against fakes that model what the IDA SDK documents, not that IDA behaves like them.

What the fakes model (and the shortcuts they take):
  * auto-analysis: plan_ea() queues an address; auto_wait() re-emulates each queued instruction the way the SDK says
    IDA does: first it drops the item's non-user code xrefs and the flow bit of the next item (xref.hpp: on reanalysis
    all non-user xrefs are deleted; ordinary flow lives in the flags), then it calls the hooked IDP_Hooks listeners in
    order until one returns non-zero, else the processor module's own emulation adds flow unless the instruction is a
    stop (ud2 0F 0B, jmp EB/E9, ret C3). Flow to an address makes IDA disassemble it there (it becomes code).
  * functions: from the ELF function symbols, except that IDA builds a function from the code reachable from its
    entry. The fake has no disassembler, so it leaves out only the clearest case: a direct jmp right after a ud2 trap
    (the out-of-line "ud2; jmp back" pattern) that jumps back into the same function is reached only through the
    trap, so it is not in any function and not even disassembled. Every other next instruction is taken as reached
    from elsewhere in the function. Real IDA may leave out more (a review counted 6,740 of the demo kernel's 7,504
    WARN sites with an unreachable next instruction), so real tail counts are likely higher. One such orphan jmp after
    a WARN site is made a function of its own (as IDA's final pass may do) to check that kflow never takes code of
    another function. append_func_tail fails when any byte of the range already belongs to a function or the start is
    not code; with BADADDR the end is where the orphan code ends. remove_func_tail removes only a tail (never the
    entry chunk) of the given function. reanalyze_function re-emulates the function's trap sites.
  * hooks: IDP_Hooks records the hook flags it was made with, hook() appends to the listener list (twice if called
    twice), unhook() removes. A database close drops listeners made without HKCB_GLOBAL.
  * Hex-Rays: udc_filter_t records init(decl) (it cannot parse the declaration: it accepts it unless told to refuse);
    install_microcode_filter installs/removes.
Usage: python3 tests/test_warnflow_stub.py <kernel.elf>   (SKIPs without a path)"""
import bisect
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
from kflow.cli import Elf, load  # noqa: E402

BAD = T.BAD
NN_UD2, NN_CALL, NN_JMP, NN_RETN, ARM_BRK = 632, 16, 86, 159, 542  # ida_allins.pyi values
FL_F, CF_STOP, FF_CODE, FF_FLOW = 21, 1, 0x600, 0x10000  # ida_xref / ida_idp / ida_bytes.pyi values
UD2 = b"\x0f\x0b"

elf = Elf(sys.argv[1])
w = T.world_from(elf)
T.install(w)
log = []
T.install_ui(w, log)
ref = load(elf)  # the command line's own decoder: the expected sites come from here, not from kflow/warnflow.py


def rd(ea, n):
    return elf.read(ea - w["shift"], n)


# ---- the fake database state ----
w["shift"] = 0  # bytes are read from the ELF at (address - shift): a rebase moves everything else
w["imagebase"] = min(s.start_ea for s in w["segs"])  # not 0, so offsets and absolute addresses differ
w.update(flow=set(), code=set(), planned=[], listeners=[], filters=[], decls=[], hooks_made=[], tail_calls=[],
         reanalysed=[], emulated=0, udc_ok=True, hx_ok=True, brk_stop=False)
traps = {}  # ud2 address -> True for WARN, False for BUG (from the reference decoder and the bytes)
calls = set()  # Linux 6.19+ WARN-with-message sites (a call)
for b in ref.get("bug", []):
    if elf.in_text(b.addr):
        raw = elf.read(b.addr, 2)
        if raw == UD2:
            traps[b.addr] = traps.get(b.addr, False) or b.warn
        elif b.warn and b.args and raw and raw[:1] == b"\xe8":
            calls.add(b.addr)
EXP_WARN = {a for a, warn in traps.items() if warn and elf.in_text(a + 2)}
EXP_BUG = {a for a, warn in traps.items() if not warn}


def decode(ea):
    """(itype, size, stop) of the few instructions the fake needs; anything else is a fake error."""
    b = rd(ea, 5) or b""
    if b[:2] == UD2:
        return NN_UD2, 2, True
    if b[:1] == b"\xe8" and len(b) == 5:
        return NN_CALL, 5, False
    if b[:1] == b"\xeb":
        return NN_JMP, 2, True
    if b[:1] == b"\xe9" and len(b) == 5:
        return NN_JMP, 5, True
    if b[:1] == b"\xc3":
        return NN_RETN, 1, True
    raise AssertionError("the fake cannot emulate 0x%X (%s)" % (ea, b.hex()))


# functions: ELF symbol ranges split around the orphan jmps; pieces [start, end, owner] sorted, not overlapping
FUNCS = []
for a, e, n in elf.funcs:
    if e > a and (not FUNCS or a >= FUNCS[-1][1]):
        FUNCS.append((a, e))
FSTARTS = [f[0] for f in FUNCS]


def elf_func(ea):
    i = bisect.bisect_right(FSTARTS, ea) - 1
    return FUNCS[i] if i >= 0 and ea < FUNCS[i][1] else None


HOLES = {}  # start of an orphan jmp after a trap -> (end, trap address)
for s in sorted(traps):
    f, nxt = elf_func(s), s + 2
    raw = elf.read(nxt, 5) or b""
    if f is None or not raw:
        continue
    if raw[:1] == b"\xeb" and len(raw) >= 2:
        n, target = 2, nxt + 2 + int.from_bytes(raw[1:2], "little", signed=True)
    elif raw[:1] == b"\xe9" and len(raw) == 5:
        n, target = 5, nxt + 5 + int.from_bytes(raw[1:5], "little", signed=True)
    else:
        continue
    if f[0] <= target < f[1] and not nxt <= target < nxt + n and nxt + n <= f[1] and \
            not any(nxt <= o < nxt + n for o in (s + 1, s + 2, s + 3, s + 4, s + 5, s + 6) if o in traps or o in calls):
        HOLES[nxt] = (nxt + n, s)
ORPHAN_FN = None  # (site, start of the orphan jmp IDA made a function of)
warn_holes = [h for h in sorted(HOLES) if traps[HOLES[h][1]]]
if len(warn_holes) >= 2:
    ORPHAN_FN = (HOLES[warn_holes[0]][1], warn_holes[0])
P = []
by_func = {}
for h, (he, s) in HOLES.items():
    by_func.setdefault(elf_func(h), []).append((h, he))
for a, e in FUNCS:
    cur = a
    for h, he in sorted(by_func.get((a, e), ())):
        if h > cur:
            P.append([cur, h, a])
        cur = he
    if cur < e:
        P.append([cur, e, a])
if ORPHAN_FN is not None:
    h = ORPHAN_FN[1]
    P.append([h, HOLES[h][0], h])
P.sort()
PS = [p[0] for p in P]
for s in traps:
    w["code"].add(s)
    if s + 2 not in HOLES or (ORPHAN_FN and s + 2 == ORPHAN_FN[1]):
        w["code"].add(s + 2)  # reached from elsewhere (or IDA's function there): disassembled
for s in calls:
    w["code"].add(s)
    w["flow"].add(s + 5)


def piece_at(ea):
    i = bisect.bisect_right(PS, ea) - 1
    return P[i] if i >= 0 and ea < P[i][1] else None


OWNER_SITES = {}
for s in sorted(set(traps) | calls):
    pc = piece_at(s)
    if pc is not None:
        OWNER_SITES.setdefault(pc[2], []).append(s)

# ---- fake ida_* modules on top of test_ida_stub.install ----
xr = sys.modules["ida_xref"]
xr.fl_F = FL_F
by = sys.modules["ida_bytes"]
by.get_bytes = lambda ea, n: rd(ea, n)
by.is_loaded = lambda ea: rd(ea, 1) is not None
by.get_flags = lambda ea: (FF_CODE if ea in w["code"] else 0) | (FF_FLOW if ea in w["flow"] else 0)
by.is_flow = lambda F: bool(F & FF_FLOW)
by.is_code = lambda F: F & 0x600 == FF_CODE  # MS_CLS
allins = types.ModuleType("ida_allins")
allins.NN_ud2, allins.ARM_brk = NN_UD2, ARM_BRK
idp = types.ModuleType("ida_idp")
idp.CF_STOP, idp.HKCB_GLOBAL = CF_STOP, 1
idp.has_insn_feature = lambda icode, bit: bit == CF_STOP and (
    (elf.arch == "x86_64" and icode in (NN_UD2, NN_JMP, NN_RETN)) or (elf.arch == "aarch64" and icode == ARM_BRK and w["brk_stop"]))


class IDP_Hooks:
    def __init__(self, _flags=0, _hkcb_flags=1):
        self._hk = (_flags, _hkcb_flags)
        w["hooks_made"].append(self._hk)

    def hook(self):
        assert hasattr(self, "_hk"), "IDP_Hooks.__init__ was not called"
        w["listeners"].append(self)
        return True

    def unhook(self):
        if self in w["listeners"]:
            w["listeners"].remove(self)
            return True
        return False

    def ev_emu_insn(self, insn):
        return 0


idp.IDP_Hooks = IDP_Hooks


class Insn:  # ida_ua.insn_t: the members kflow uses
    def __init__(self, ea, size, itype):
        self.ea, self.size, self.itype = ea, size, itype

    def add_cref(self, to, opoff, type):
        if type == FL_F and to == self.ea + self.size:
            add_flow(to)
        else:
            w["xrefs"][(self.ea, to)] = False
            w["by_from"].setdefault(self.ea, set()).add(to)


def add_flow(to):
    w["flow"].add(to)
    w["code"].add(to)  # IDA disassembles where ordinary flow goes


def emulate(ea):
    itype, size, stop = decode(ea)
    w["emulated"] += 1
    for to in list(w["by_from"].get(ea, ())):  # non-user code xrefs of the item go; the user's stay
        if not w["xrefs"].get((ea, to)):
            w["xrefs"].pop((ea, to), None)
            w["by_from"][ea].discard(to)
    w["flow"].discard(ea + size)
    insn = Insn(ea, size, itype)
    for h in list(w["listeners"]):
        if h.ev_emu_insn(insn):
            break
    else:
        if not stop:
            add_flow(ea + size)


auto = types.ModuleType("ida_auto")
auto.plan_ea = lambda ea: w["planned"].append(ea)


def auto_wait():
    while w["planned"]:
        emulate(w["planned"].pop(0))
    return True


auto.auto_wait = auto_wait
fn = sys.modules["ida_funcs"]


def get_func(ea):
    pc = piece_at(ea)
    if pc is None:
        return None
    entry = piece_at(pc[2])
    return types.SimpleNamespace(start_ea=pc[2], end_ea=entry[1])


def free_end(ea1):
    if ea1 in HOLES:
        return HOLES[ea1][0]
    i = bisect.bisect_right(PS, ea1)  # otherwise: up to the next function code
    return PS[i] if i < len(PS) else ea1 + 1


def append_func_tail(pfn, ea1, ea2):
    owner = pfn.start_ea
    ok = piece_at(owner) is not None and piece_at(owner)[0] == owner and ea1 in w["code"]
    if ok and ea2 == BAD:
        ea2 = free_end(ea1)
    ok = ok and ea1 < ea2 and piece_at(ea1) is None
    if ok:
        i = bisect.bisect_left(PS, ea1)
        ok = i == len(PS) or PS[i] >= ea2  # no byte of the range in a function
    if ok:
        P.insert(i, [ea1, ea2, owner])
        PS.insert(i, ea1)
    w["tail_calls"].append(("append", owner, ea1, ea2, ok))
    return ok


def remove_func_tail(pfn, tail_ea):
    pc = piece_at(tail_ea)
    ok = pc is not None and pc[2] == pfn.start_ea and pc[0] != pc[2]
    if ok:
        i = bisect.bisect_left(PS, pc[0])
        del P[i], PS[i]
    w["tail_calls"].append(("remove", pfn.start_ea, tail_ea, ok))
    return ok


def reanalyze_function(pfn, *rest):
    w["reanalysed"].append(pfn.start_ea)
    for s in OWNER_SITES.get(pfn.start_ea, ()):
        auto.plan_ea(s)


fn.get_func, fn.append_func_tail, fn.remove_func_tail, fn.reanalyze_function = \
    get_func, append_func_tail, remove_func_tail, reanalyze_function
fn.get_func_name = lambda ea: elf.func(ea - w["shift"]) or ""
hx_log = {"hooked": 0, "flushed": 0}


def fake_hexrays():
    hx = types.ModuleType("ida_hexrays")

    class Hexrays_Hooks:
        def hook(self):
            hx_log["hooked"] += 1
            return True

        def unhook(self):
            hx_log["hooked"] -= 1
            return True

    class udc_filter_t:
        def __init__(self):
            self._made = True

        def init(self, decl):
            assert getattr(self, "_made", False), "udc_filter_t.__init__ was not called"
            w["decls"].append(decl)
            return w["udc_ok"]

        def match(self, cdg):
            return False

    def install_microcode_filter(flt, install=True):
        if w.get("install_raises"):
            raise RuntimeError("fake: install_microcode_filter failed")
        if install:
            w["filters"].append(flt)
            return True
        if flt in w["filters"]:
            w["filters"].remove(flt)
            return True
        return False

    hx.Hexrays_Hooks, hx.udc_filter_t, hx.install_microcode_filter = Hexrays_Hooks, udc_filter_t, install_microcode_filter
    hx.init_hexrays_plugin = lambda flags=0: w["hx_ok"]
    hx.clear_cached_cfuncs = lambda: hx_log.update(flushed=hx_log["flushed"] + 1)
    return hx


sys.modules.update({"ida_allins": allins, "ida_idp": idp, "ida_auto": auto, "ida_hexrays": fake_hexrays()})


def load_plugin():
    sys.modules.pop("kflow_entry", None)
    mod = importlib.import_module("kflow_entry")
    plugin = mod.PLUGIN_ENTRY()
    assert plugin.init() == 1
    return mod, plugin


def close_database():
    """IDA closes the database: listeners made without HKCB_GLOBAL go with it (idp.hpp)."""
    w["listeners"][:] = [h for h in w["listeners"] if h._hk[1] & 1]


def msgs(text):
    return [x[1] for x in log if x[0] in ("msg", "warning", "info") and text in x[1]]


def replan(eas):
    for ea in sorted(eas):
        auto.plan_ea(ea)
    auto.auto_wait()


def snap(m):
    node = w["netnodes"].get(m.idalayer.WARN_NODE)
    return {"flow": set(w["flow"]), "pieces": [tuple(p) for p in P], "node": None if node is None else dict(node),
            "filters": len(w["filters"]), "listeners": len(w["listeners"])}


def recorded(m, bit):
    base = w["imagebase"]
    return {(o + base) & (2 ** 64 - 1) for o, v in w["netnodes"].get(m.idalayer.WARN_NODE, {}).items() if v & bit}


def rebase(delta):
    """Edit > Segments > Rebase program: every address moves, the image base too; netnode values stay as stored."""
    global P, PS
    sh = lambda ea: ea + delta  # noqa: E731
    w["shift"] += delta
    w["imagebase"] += delta
    for s in w["segs"]:
        s.start_ea, s.end_ea = s.start_ea + delta, s.end_ea + delta
    w["starts"] = [s.start_ea for s in w["segs"]]
    w["flow"] = {sh(a) for a in w["flow"]}
    w["code"] = {sh(a) for a in w["code"]}
    P[:] = [[sh(a), sh(e), sh(o)] for a, e, o in P]
    PS[:] = [p[0] for p in P]
    for d in (HOLES, OWNER_SITES, traps):
        items = list(d.items())
        d.clear()
        for k, v in items:
            d[sh(k)] = (sh(v[0]), sh(v[1])) if d is HOLES else [sh(x) for x in v] if d is OWNER_SITES else v
    w["xrefs"] = {(sh(f), sh(t)): u for (f, t), u in w["xrefs"].items()}
    w["by_from"] = {}
    for f, t in w["xrefs"]:
        w["by_from"].setdefault(f, set()).add(t)


def shifted(state, delta):
    return dict(state, flow={a + delta for a in state["flow"]},
                pieces=[(a + delta, e + delta, o + delta) for a, e, o in state["pieces"]])


name = os.path.basename(sys.argv[1])

# ======== arm64: nothing to do, nothing installed ========
if elf.arch == "aarch64":
    m, p = load_plugin()
    pre = snap(m)
    assert m.WarnFlowAction().activate(None) == 0
    assert msgs("not needed on arm64: IDA continues after brk #0x800") and msgs("marks brk as the end of flow: no")
    w["brk_stop"] = True  # an IDA whose ARM module did stop at brk: still x86_64 only, nothing installed
    assert m.WarnFlowAction().activate(None) == 0 and msgs("supports only x86_64")
    assert m.WarnFlowOffAction().activate(None) == 0 and msgs("not on in this database")
    assert snap(m) == pre and pre["listeners"] == 0 and pre["filters"] == 0 and pre["node"] is None
    assert not w["hooks_made"] and not w["emulated"] and not w["tail_calls"] and m.STATE["wf"] is None
    p.term()
    print("OK warnflow %s (arm64): nothing installed (no hook made, no filter, no record, nothing reanalysed); "
          "the action says it is not needed" % name)
    sys.exit(0)

# ======== x86_64 ========
assert EXP_WARN, "no WARN ud2 site in this file"
m, p = load_plugin()
il = m.idalayer
assert not w["listeners"] and not w["filters"] and not w["hooks_made"], "no hook before the action is run"
pre = snap(m)
assert pre["node"] is None
holes_before = {h: (piece_at(h), h in w["code"]) for h in HOLES}
t = il.scan()
wf = importlib.import_module("kflow.warnflow")
assert wf.warn_sites(t) == EXP_WARN, (len(wf.warn_sites(t)), len(EXP_WARN))
assert wf.bug_traps(t) == len(EXP_BUG)


def annotate_remove():
    """Annotate then Remove annotations: what they write and leave (to compare with WARN fall-through on and off)."""
    assert m.AnnotateAction().activate(None) == 1
    a = (dict(w["cmts"]), dict(w["xrefs"]), dict(w["drefs"]), dict(w["netnodes"].get(il.NODE, {})),
         dict(w["netnodes"].get(il.KEY_NODE, {})), [x[1] for x in log if x[0] == "msg"][-1])
    assert m.RemoveAction().activate(None) == 1
    r = (dict(w["cmts"]), dict(w["xrefs"]), dict(w["drefs"]), il.NODE in w["netnodes"], il.KEY_NODE in w["netnodes"],
         [x[1] for x in log if x[0] == "msg"][-1])
    return a, r


ar_off = annotate_remove()
assert snap(m) == pre, "Annotate / Remove touch nothing of WARN fall-through"

# ---- 1. flow after exactly the WARN sites, never after a BUG trap ----
assert m.WarnFlowAction().activate(None) == 1
res = dict(m.STATE["wf_last"])
hook = m.STATE["wf"]
assert w["listeners"] == [hook] and w["hooks_made"] == [(0, 0)], (w["listeners"], w["hooks_made"])  # not HKCB_GLOBAL
on = snap(m)
assert on["flow"] - pre["flow"] == {s + 2 for s in EXP_WARN} and pre["flow"] <= on["flow"]
assert not on["flow"] & {s + 2 for s in EXP_BUG}, "flow after a BUG trap"
assert res["sites"] == res["flow"] == len(EXP_WARN), res
tails = recorded(m, 2)
assert recorded(m, 1) == EXP_WARN and len(on["node"]) == len(EXP_WARN | tails)
exp_tails = {h for h, (he, s) in HOLES.items() if traps[s] and (ORPHAN_FN is None or h != ORPHAN_FN[1])}
assert tails == exp_tails and res["tails"] == len(exp_tails), (len(tails), len(exp_tails), res)
assert res["other_func"] == (ORPHAN_FN is not None) and res["tail_failed"] == 0, res
assert res["no_func"] == sum(1 for s in EXP_WARN if piece_at(s) is None), res
for h in tails:  # each tail is the orphan jmp, now a tail of the site's own function
    pc = piece_at(h)
    assert pc == [h, HOLES[h][0], piece_at(HOLES[h][1])[2]] and pc[0] != pc[2], pc
new_pieces = set(on["pieces"]) - set(pre["pieces"])
assert set(pre["pieces"]) <= set(on["pieces"]) and {p0 for p0, _, _ in new_pieces} == tails, "no function lost code"
for h, (pc, code) in holes_before.items():
    if not traps[HOLES[h][1]]:
        assert piece_at(h) == pc and (h in w["code"]) == code, "the code after a BUG trap is left alone"
if ORPHAN_FN is not None:
    assert piece_at(ORPHAN_FN[1]) == [ORPHAN_FN[1], HOLES[ORPHAN_FN[1]][0], ORPHAN_FN[1]], "another function's code taken"
assert all(c[-1] for c in w["tail_calls"]), "every append_func_tail kflow tried was valid"
assert set(w["reanalysed"]) == {piece_at(s)[2] for s in EXP_WARN if piece_at(s) is not None}
assert on["filters"] == 1 and w["filters"] == [m.STATE["wf_filter"]] and w["decls"] == ["void __spoils<> __WARN(void);"]
assert msgs("IDA marks ud2 as the end of flow: yes") and msgs("decompiler part on")
assert hx_log["flushed"] >= 1, "cached decompilations dropped"
# the hook's own contract: 1 (handled, ordinary flow added) at a WARN site, 0 (IDA's emulation) for anything else
s0 = min(EXP_WARN)
w["flow"].discard(s0 + 2)
assert hook.ev_emu_insn(Insn(s0, 2, NN_UD2)) == 1 and s0 + 2 in w["flow"]
assert hook.ev_emu_insn(Insn(s0, 2, NN_CALL)) == 0 and hook.ev_emu_insn(Insn(s0 + 1, 2, NN_UD2)) == 0
if EXP_BUG:
    b0 = min(EXP_BUG)
    had = b0 + 2 in w["flow"]
    assert hook.ev_emu_insn(Insn(b0, 2, NN_UD2)) == 0 and (b0 + 2 in w["flow"]) == had
assert hook.ev_emu_insn(None) == 0, "a broken insn must not raise inside IDA"

# ---- 6. the decompiler filter matches exactly the WARN sites ----
flt = m.STATE["wf_filter"]
cdg = lambda ea, itype=NN_UD2: types.SimpleNamespace(insn=Insn(ea, 2, itype))  # noqa: E731
assert all(flt.match(cdg(s)) for s in EXP_WARN)
assert not any(flt.match(cdg(s)) for s in EXP_BUG)
assert not flt.match(cdg(s0, NN_CALL)) and not flt.match(cdg(s0 + 1)) and not flt.match(types.SimpleNamespace(insn=None))

# ---- 2. running it again changes nothing ----
assert m.WarnFlowAction().activate(None) == 1
res2 = m.STATE["wf_last"]
assert snap(m) == on and len(w["listeners"]) == 1 and len(w["filters"]) == 1
assert res2["flow"] == res2["sites"] == res["sites"] and res2["tails"] == 0 and res2["other_func"] == res["other_func"]

# ---- 5b. Annotate / Remove give the same results with WARN fall-through on ----
assert annotate_remove() == ar_off
assert snap(m) == on, "Annotate / Remove leave WARN fall-through alone"

# ---- 3. the hook lives in memory: term unhooks, the next load hooks again from the record ----
replan(traps)
assert w["flow"] == on["flow"], "IDA reanalyses the traps with kflow loaded: the flow stays"
p.term()
assert not w["listeners"] and not w["filters"] and m.STATE["wf"] is None and m.STATE["wf_filter"] is None
close_database()
replan(traps)  # the database reanalysed without kflow: IDA drops the flow
assert w["flow"] == pre["flow"]
m, p = load_plugin()
assert len(w["listeners"]) == 1 and w["listeners"][0] is m.STATE["wf"] and len(w["filters"]) == 1
assert msgs("%d of them have no flow now" % len(EXP_WARN)), [x for x in log if x[0] == "msg"][-3:]
assert m.WarnFlowAction().activate(None) == 1 and snap(m) == on, "running it again restores the flow"
p.term()
close_database()
m, p = load_plugin()
assert msgs("processor hook installed for %d WARN sites, decompiler part on; all of them have flow" % len(EXP_WARN))
replan(traps)
assert w["flow"] == on["flow"]

# ---- fail soft: Hex-Rays refuses the declaration / the filter / is not there; the disassembly part stays ----
for how in ("udc_ok", "install_raises", "hx_ok"):
    p.term()
    w["udc_ok"], w["install_raises"], w["hx_ok"] = how != "udc_ok", how == "install_raises", how != "hx_ok"
    before = len(msgs("decompiler part could not be installed"))
    m, p = load_plugin()
    assert len(w["listeners"]) == 1 and not w["filters"] and m.STATE["wf_filter"] is None
    assert m.WarnFlowAction().activate(None) == 1 and snap(m) == dict(on, filters=0)
    assert len(msgs("decompiler part could not be installed")) == before + (how != "hx_ok"), "reported once"
    assert msgs("decompiler part off (no decompiler)" if how == "hx_ok" else "decompiler part not installed (error)")
p.term()
w["udc_ok"], w["install_raises"], w["hx_ok"] = True, False, True
m, p = load_plugin()
assert snap(m) == on

# ---- 4. rebase: the records are offsets from the image base ----
delta = 0x40000000
rebase(delta)
replan(traps)
assert w["flow"] == {a + delta for a in on["flow"]}, "the hook still knows the sites after a rebase"
assert m.STATE["wf_filter"].match(cdg(s0 + delta)) and not m.STATE["wf_filter"].match(cdg(s0))
p.term()
close_database()
m, p = load_plugin()
assert msgs("processor hook installed for %d WARN sites, decompiler part on; all of them have flow" % len(EXP_WARN))
assert m.WarnFlowOffAction().activate(None) == 1, "Remove after a rebase"
assert snap(m) == shifted(pre, delta), "Remove after a rebase restores the moved pre-state"
rebase(-delta)
assert snap(m) == pre
assert m.WarnFlowAction().activate(None) == 1 and snap(m) == on

# ---- 5. Remove restores what was there before: flow, function tails, record, filter, hook ----
assert m.WarnFlowOffAction().activate(None) == 1
off = m.STATE["wf_last"]
assert snap(m) == pre and m.STATE["wf"] is None and m.STATE["wf_filter"] is None
assert off["sites"] == len(EXP_WARN) and off["tails"] == len(exp_tails) and off["flow_left"] == 0 and off["tails_left"] == 0
assert msgs("WARN fall-through removed: %d sites reanalysed, flow still after 0; function tails removed: %d"
            % (len(EXP_WARN), len(exp_tails)))
replan(traps)
assert w["flow"] == pre["flow"]
assert m.WarnFlowOffAction().activate(None) == 0 and msgs("not on in this database")
assert annotate_remove() == ar_off
p.term()
m, p = load_plugin()
assert not w["listeners"] and not w["filters"], "no record: the next load installs nothing"
p.term()
assert hx_log["hooked"] == 0
print("OK warnflow %s: %d WARN ud2 sites, %d BUG ud2 sites; flow after %d WARN sites and 0 BUG sites; tails %d; "
      "other_func %d; site in no function %d; %d functions reanalysed; idempotent; term unhooks, the next load hooks "
      "from the record and reports lost flow; rebase; Remove restores flow, tails, record, filter; Annotate/Remove "
      "unchanged; filter matches only WARN sites; decompiler part fails soft"
      % (name, len(EXP_WARN), len(EXP_BUG), res["flow"], res["tails"], res["other_func"], res["no_func"], res["functions"]))
