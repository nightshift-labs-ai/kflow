"""Runs kflow's IDA layer on fake ida_* modules backed by a real kernel ELF.
Usage: python3 tests/test_ida_stub.py <kernel.elf> [<stripped vmlinux>]   (SKIPs without a path)"""
import bisect
import collections
import importlib
import os
import re
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from kflow.cli import Elf, load  # noqa: E402

BAD = 2 ** 64 - 1


class Seg:
    def __init__(self, s, e, perm, name):
        self.start_ea, self.end_ea, self.perm, self.type, self.name = s, e, perm, 0, name


class PackedElf(Elf):
    """A module as IDA's ELF loader lays it out: the imports one after another in an extern segment (8 bytes each
    here; the exact item size in real IDA is not verified), so after relocation "import + offset" (a tracepoint's
    key is __tracepoint_X + 8) lands on ANOTHER import. The command line's Elf gives each import a 64 KB slot."""
    EXTERN_SLOT = 8
    BASE = 0x400000  # and not at the command line's base: only offsets inside a section may be compared


SEG_XTRN = 1
FF_CODE, MS_CLS = 0x600, 0x600  # ida_bytes.pyi values
FF_FLOW = 0x10000  # bytes.hpp: "Exec flow from prev instruction"
X86_LEN = [(b"\xe9", 5), (b"\xeb", 2), (b"\x0f\x1f\x44\x00\x00", 5), (b"\x66\x90", 2), (b"\x0f\x0b", 2), (b"\xe8", 5)]
# ida_ua.decode_insn: the instructions the fake decodes (ida_allins.pyi codes) and which of them the fake processor
# modules mark CF_STOP (ida_idp.has_insn_feature). arm64 B and B.cond share ARM_b, as in IDA's ARM module; brk is not
# marked (IDA's answer is not known: kflow/warnflow.py only logs it); w["arm_b_stop"] False: B is not marked either;
# w["arm_ret_stop"] False: ret is not marked either. br, eret, retaa... decode as ARM_NOP here: never marked
NN_CALL, NN_INT3, NN_JMP, NN_MOV, NN_NOP, NN_RETN, NN_UD2 = 16, 48, 86, 122, 129, 159, 632
ARM_RET, ARM_NOP, ARM_B, ARM_BL, ARM_BRK = 1, 2, 3, 4, 542
CF_STOP = 1
X86_INSNS = [(b"\x0f\x0b", 2, NN_UD2), (b"\x0f\x1f\x44\x00\x00", 5, NN_NOP), (b"\x66\x90", 2, NN_NOP), (b"\x90", 1, NN_NOP),
             (b"\xe8", 5, NN_CALL), (b"\xe9", 5, NN_JMP), (b"\xeb", 2, NN_JMP), (b"\xc3", 1, NN_RETN), (b"\xcc", 1, NN_INT3)]


def world_from(elf):
    segs = []
    for name, (a, e) in elf.sections.items():
        exe = any(a <= ta < e for ta, te in elf.text)
        segs.append(Seg(a, e, 1 if exe else 4, name))
    if not segs:  # ELF without section names: one segment per loaded range
        segs = [Seg(a, e, 1 if any(a <= ta < e for ta, te in elf.text) else 4, "seg%d" % i)
                for i, (a, e, o) in enumerate(elf.loaded)]
    if elf.externs:  # a module's imports: IDA's extern segment
        x = Seg(min(elf.externs.values()), max(elf.externs.values()) + elf.EXTERN_SLOT, 4, "extern")
        x.type = SEG_XTRN
        segs.append(x)
    segs.sort(key=lambda s: s.start_ea)
    return {"segs": segs, "starts": [s.start_ea for s in segs], "cmts": {}, "xrefs": {}, "by_from": {}, "elf": elf,
            "path": elf.path}


def install(w, names=True):
    elf = w["elf"]
    m = {n: types.ModuleType(n) for n in "ida_bytes ida_ida ida_idaapi ida_name ida_segment ida_xref ida_funcs".split()}
    # functions as the plugin's IDA layer sees them: none, unless a test sets w["func_of"] (ea -> (start, end) or None);
    # none at all while auto-analysis runs (w["auto_ok"] False: IDA has not made them yet)
    m["ida_funcs"].get_func = lambda ea: (lambda r: types.SimpleNamespace(start_ea=r[0], end_ea=r[1]) if r else None)(
        w["func_of"](ea) if "func_of" in w and w.get("auto_ok", True) else None)
    m["ida_funcs"].func_contains = lambda f, ea: f.start_ea <= ea < f.end_ea or ea in w.get("shared", {}).get(f.start_ea, ())
    # every fragment (SDK: 'takes into account all fragments'); w["tail_bytes"] adds tail chunks (re-review s175 MINOR 3)
    m["ida_funcs"].calc_func_size = lambda f: (f.end_ea - f.start_ea) + w.get("tail_bytes", {}).get(f.start_ea, 0)
    m["ida_funcs"].get_func_name = lambda ea: w.get("func_names", {}).get(ea, "")
    m["ida_idaapi"].BADADDR = BAD

    def getseg(ea):
        i = bisect.bisect_right(w["starts"], ea) - 1
        return w["segs"][i] if i >= 0 and ea < w["segs"][i].end_ea else None
    m["ida_segment"].getseg = getseg
    m["ida_segment"].get_segm_by_name = lambda n: next((s for s in w["segs"] if s.name == n), None)
    m["ida_segment"].SEGPERM_EXEC, m["ida_segment"].SEG_CODE, m["ida_segment"].SEG_XTRN = 1, 2, SEG_XTRN
    m["ida_segment"].get_segm_qty = lambda: len(w["segs"])
    m["ida_segment"].getnseg = lambda n: w["segs"][n] if 0 <= n < len(w["segs"]) else None
    m["ida_bytes"].get_bytes = lambda ea, n: elf.read(ea, n)
    m["ida_bytes"].is_loaded = lambda ea: elf.read(ea, 1) is not None
    m["ida_bytes"].get_cmt = lambda ea, rep: w["cmts"].get(ea)
    # instruction heads: w["code"], the set IDA has made so far, while a test models auto-analysis; without it (a
    # finished analysis) every address of an executable segment counts as one. Unexplored bytes have flags 0.
    def is_head(ea):
        if "code" in w:
            return ea in w["code"]
        seg = getseg(ea)
        return seg is not None and bool(seg.perm & 1)
    # w["flow"]: instructions that IDA's ordinary flow reaches from the previous one (FF_FLOW), only where a test sets it
    m["ida_bytes"].get_flags = lambda ea: (FF_CODE | (FF_FLOW if ea in w.get("flow", ()) else 0)) if is_head(ea) else 0
    m["ida_bytes"].is_code = lambda F: F & MS_CLS == FF_CODE
    m["ida_bytes"].is_flow = lambda F: bool(F & FF_FLOW)

    def get_item_end(ea):
        """Like IDA: unexplored bytes are 1-byte items; an instruction ends where it ends. Instruction ends come from
        w["item_end"], else arm64's 4 bytes, else the x86 encodings at static-key sites (jmp, 2/5-byte NOP) and of
        ud2/call. An x86 instruction the fake cannot size (it has no decoder) ends 1 byte on: its next instruction is
        never taken for a fixup there, so the fake adds references real IDA would not (never fewer)."""
        if not is_head(ea):
            return ea + 1
        if ea in w.get("item_end", {}):
            return w["item_end"][ea]
        if elf.arch == "aarch64":
            return ea + 4
        b = elf.read(ea, 5) or b""
        for raw, n in X86_LEN:
            if b.startswith(raw) and len(b) >= n:
                return ea + n
        return ea + 1
    m["ida_bytes"].get_item_end = get_item_end

    def set_cmt(ea, text, rep):
        if text:
            w["cmts"][ea] = text
        else:
            w["cmts"].pop(ea, None)
        return True
    m["ida_bytes"].set_cmt = set_cmt
    # IDA keeps ONE name per address: a symbol sharing its address with an earlier one is not in the database
    def get_name_ea(base, n):  # a module's imports are named items of the extern segment
        a = elf.symbols.get(n, elf.externs.get(n)) if names else None
        return a if a is not None and elf.by_addr.get(a) == n else BAD
    m["ida_name"].get_name_ea = get_name_ea
    m["ida_nalt"] = types.ModuleType("ida_nalt")
    m["ida_nalt"].get_input_file_path = lambda: w.get("path")
    m["ida_nalt"].get_imagebase = lambda: w.get("imagebase", 0)
    nn = m["ida_netnode"] = types.ModuleType("ida_netnode")
    nn.BADNODE = BAD
    store = w.setdefault("netnodes", {})

    class netnode:  # alt values only, default tag; a name that does not exist has index BADNODE unless created
        def __init__(self, name, namlen=0, do_create=False):
            self.name = name
            if do_create:
                store.setdefault(name, {})

        def index(self):
            return 1000 + sorted(store).index(self.name) if self.name in store else BAD

        def altset(self, i, v):
            store[self.name][i] = v
            return True

        def altdel(self, i):
            return store.get(self.name, {}).pop(i, None) is not None

        def altval(self, i):
            return store.get(self.name, {}).get(i, 0)

        def _after(self, cur):  # sorted key list cached per netnode; bisect keeps Remove linear on 75k records
            d = store.get(self.name, {})
            if getattr(self, "_n", -1) != len(d):
                self._keys, self._n = sorted(d), len(d)
            i = 0 if cur is None else bisect.bisect_right(self._keys, cur)
            return self._keys[i] if i < len(self._keys) else BAD

        def altfirst(self):
            return self._after(None)

        def altnext(self, cur):
            return self._after(cur)

        def kill(self):
            store.pop(self.name, None)
    nn.netnode = netnode
    # like IDA: get_name() also returns placeholder names (unk_...) for unnamed (referenced) addresses; only
    # get_ea_name(ea, GN_NOT_DUMMY) leaves them out
    m["ida_name"].get_name = lambda ea: (elf.by_addr.get(ea, "") if names else "") or "unk_%X" % ea
    m["ida_name"].GN_NOT_DUMMY = 512
    m["ida_name"].get_ea_name = lambda ea, flags=0: ((elf.by_addr.get(ea, "") if names else "") if flags & 512
                                                     else m["ida_name"].get_name(ea))
    nlist = sorted(elf.by_addr) if names else []
    m["ida_name"].get_nlist_size = lambda: len(nlist)
    m["ida_name"].get_nlist_idx = lambda ea: bisect.bisect_left(nlist, ea)  # "closest match": may be the next name
    m["ida_name"].get_nlist_ea = lambda i: nlist[i]
    m["ida_name"].get_nlist_name = lambda i: elf.by_addr[nlist[i]]
    m["ida_name"].is_public_name = lambda ea: ea in getattr(elf, "public", ())  # IDA: the ELF's global symbols
    m["ida_name"].is_weak_name = lambda ea: ea in getattr(elf, "weak", ())  # and its weak ones
    m["ida_ida"].inf_is_64bit = lambda: True
    m["ida_ida"].inf_get_procname = lambda: "metapc" if elf.arch == "x86_64" else "ARM"
    x = m["ida_xref"]
    x.fl_JN, x.XREF_USER, x.XREF_FAR, x.XREF_DATA, x.dr_O = 19, 32, 1, 2, 1
    x.fl_F = 21
    w.setdefault("drefs", {})
    m["ida_bytes"].is_mapped = lambda ea: any(s.start_ea <= ea < s.end_ea for s in w["segs"])

    def add_dref(f, t, k):
        w["drefs"][(f, t)] = bool(k & 32)
        w.setdefault("dref_keys", {}).setdefault(f, set()).add((f, t))
        return True
    x.add_dref = add_dref
    x.del_dref = lambda f, t: w["drefs"].pop((f, t), None) and None

    def add_cref(f, t, k):
        if k == 21:  # fl_F: ordinary flow, which xrefblk_t with XREF_FAR does not list
            w.setdefault("flow", set()).add(t)
            return True
        w["xrefs"][(f, t)] = bool(k & 32)
        w["by_from"].setdefault(f, set()).add(t)
        return True
    x.add_cref = add_cref

    def del_cref(f, t, expand):
        if w.get("del_clears_flow") and t == m["ida_bytes"].get_item_end(f):  # worst case: real IDA unknown (s159)
            w.get("flow", set()).discard(t)
        w["by_from"].get(f, set()).discard(t)
        return w["xrefs"].pop((f, t), None) is not None
    x.del_cref = del_cref

    class xrefblk_t:
        def first_from(self, ea, flags):
            if flags == 2:  # XREF_DATA (one key per site here, so look up the few candidates directly)
                self._it = iter(sorted((t, u) for (f, t), u in w["drefs"].items() if f == ea)) if len(w["drefs"]) < 64 \
                    else iter(sorted((k[1], w["drefs"][k]) for k in w["dref_keys"].get(ea, ()) if k in w["drefs"]))
            else:
                self._it = iter(sorted((t, w["xrefs"][(ea, t)]) for t in w["by_from"].get(ea, ())))
            return self.next_from()

        def next_from(self):
            try:
                self.to, self.user = next(self._it)
            except StopIteration:
                return False
            self.iscode = True
            return True

        def first_to(self, ea, flags=0):
            """References TO ea (ida_xref.pyi: first_to(_to, flags=0), then next_to(); fields frm, to, iscode, user).
            XREF_FAR leaves out ordinary flow (which the fake keeps apart in w["flow"] anyway); data references come
            too, with iscode False, unless XREF_DATA asks for those only."""
            code = [] if flags == 2 else [(f, u, True) for (f, t), u in w["xrefs"].items() if t == ea]
            self._it_to = iter(sorted(code + [(f, u, False) for (f, t), u in w["drefs"].items() if t == ea]))
            self.to = ea
            return self.next_to()

        def next_to(self):
            try:
                self.frm, self.user, self.iscode = next(self._it_to)
            except StopIteration:
                return False
            return True
    x.xrefblk_t = xrefblk_t
    ua = m["ida_ua"] = types.ModuleType("ida_ua")
    idp = m["ida_idp"] = types.ModuleType("ida_idp")

    class insn_t:  # the members kflow reads
        def __init__(self):
            self.ea, self.size, self.itype = BAD, 0, 0

    def decode_insn(insn, ea):
        """Like IDA: the length of the instruction at ea (0 if the bytes are none), without changing the database;
        w["decoded"] counts the calls. w["insns"]: address -> (size, itype) laid out by a test, size 0 = undecodable.
        Else the bytes: arm64 any 4-byte word; x86 only X86_INSNS and 'mov r64, r64' (48 89 /r), nothing else."""
        w["decoded"] = w.get("decoded", 0) + 1
        b = m["ida_bytes"].get_bytes(ea, 5) or b""
        if ea in w.get("insns", {}):
            size, itype = w["insns"][ea]
        elif elf.arch == "aarch64" and len(b) >= 4:
            word = int.from_bytes(b[:4], "little")
            size = 4
            itype = (ARM_B if word >> 26 == 0b000101 or word >> 24 == 0x54 else ARM_BL if word >> 26 == 0b100101
                     else ARM_RET if word & 0xFFFFFC1F == 0xD65F0000 else ARM_BRK if word & 0xFFE0001F == 0xD4200000
                     else ARM_NOP)
        else:
            size, itype = next(((n, c) for raw, n, c in X86_INSNS if b.startswith(raw) and len(b) >= n), (0, 0))
            if not size and b[:2] == b"\x48\x89" and len(b) >= 3 and b[2] >= 0xC0:
                size, itype = 3, NN_MOV
        if size:
            insn.ea, insn.size, insn.itype = ea, size, itype
        return size
    ua.insn_t, ua.decode_insn = insn_t, decode_insn
    idp.CF_STOP = CF_STOP
    idp.has_insn_feature = lambda icode, bit: bool(bit & CF_STOP) and (w.get("stop_everything") or icode in (NN_JMP, NN_RETN, NN_UD2) or (
        icode == ARM_B and w.get("arm_b_stop", True)) or (icode == ARM_RET and w.get("arm_ret_stop", True)))
    sys.modules.update(m)
    sys.modules.pop("kflow.idalayer", None)
    return importlib.import_module("kflow.idalayer")


def install_ui(w, log):
    """Fake ida_kernwin, ida_funcs (get_func from the ELF's function symbols), ida_lines and ida_idaapi.plugin_t, to
    load kflow_entry.py (the IDA plugin). Messages, warnings, info boxes, wait boxes, jumps, registered actions,
    text dialogs and choosers shown go to log; ask_text answers w["ask_text"] (None: cancelled). Returns the modules
    and get_func."""
    elf = w["elf"]
    kw = types.ModuleType("ida_kernwin")
    kw.msg = lambda text: log.append(("msg", text))
    kw.warning = lambda text: log.append(("warning", text))
    kw.info = lambda text: log.append(("info", text)) or 0
    kw.show_wait_box = lambda text: log.append(("wait", text))
    kw.hide_wait_box = lambda: log.append(("hide", None))
    kw.replace_wait_box = lambda text: log.append(("wait_replace", text))
    kw.jumpto = lambda ea: log.append(("jump", ea)) or True
    kw.ask_text = lambda max_size, defval, prompt: log.append(("ask", max_size, defval, prompt)) or w.get("ask_text")
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
            w["shown"] = self  # the last chooser, for tests that check its rows
            return 0

    class UI_Hooks:  # the test fires the events itself on the hooks logged as ("ui_hook", hooks)
        def hook(self):
            log.append(("ui_hook", self))
            return True

        def unhook(self):
            log.append(("ui_unhook", self))
            return True

    kw.action_handler_t, kw.action_desc_t, kw.Choose, kw.UI_Hooks = action_handler_t, action_desc_t, Choose, UI_Hooks
    fn = types.ModuleType("ida_funcs")
    fn.get_func_name = lambda ea: elf.func(ea) or ""
    fstarts = [f[0] for f in elf.funcs]

    def get_func(ea):  # the function's entry chunk, from the ELF's function symbols; none while auto-analysis runs
        if not w.get("auto_ok", True):
            return None
        i = bisect.bisect_right(fstarts, ea) - 1
        if i >= 0 and elf.funcs[i][0] <= ea < elf.funcs[i][1]:
            return types.SimpleNamespace(start_ea=elf.funcs[i][0], end_ea=elf.funcs[i][1])
        return None

    def get_next_fchunk(ea):  # the first chunk that starts after ea: here every function is one chunk
        i = bisect.bisect_right(fstarts, ea)
        if not w.get("auto_ok", True) or i >= len(fstarts):
            return None
        return types.SimpleNamespace(start_ea=elf.funcs[i][0], end_ea=elf.funcs[i][1])

    fn.get_func, fn.get_next_fchunk = get_func, get_next_fchunk
    # every fragment of the function (SDK: 'takes into account all fragments'); w["tail_bytes"] adds tail chunks
    fn.calc_func_size = lambda f: (f.end_ea - f.start_ea) + w.get("tail_bytes", {}).get(f.start_ea, 0)
    fn.func_contains = lambda f, ea: f.start_ea <= ea < f.end_ea
    lines_mod = types.ModuleType("ida_lines")
    lines_mod.SCOLOR_AUTOCMT = "\x04"
    lines_mod.COLSTR = lambda text, tag: "\x01" + tag + text + "\x02" + tag  # SCOLOR_ON tag text SCOLOR_OFF tag
    api = sys.modules["ida_idaapi"]

    class plugin_t:
        pass

    api.plugin_t, api.PLUGIN_KEEP = plugin_t, 1
    sys.modules.update({"ida_kernwin": kw, "ida_funcs": fn, "ida_lines": lines_mod})
    if "ida_auto" not in sys.modules:  # Annotate asks whether auto-analysis has finished
        auto = types.ModuleType("ida_auto")
        auto.auto_is_ok = lambda: w.get("auto_ok", True)
        sys.modules["ida_auto"] = auto
    if not hasattr(sys.modules["ida_auto"], "auto_wait"):  # s174: the decompile check waits for IDA before its AFTER pass
        sys.modules["ida_auto"].auto_wait = lambda: AUTO_WAITS.append(len(DC_STATE["s"]["calls"]) if "s" in DC_STATE else -1)
    return types.SimpleNamespace(kw=kw, fn=fn, lines=lines_mod, get_func=get_func)


AUTO_WAITS = []  # s174: one entry per fake ida_auto.auto_wait() call: how many decompile() calls had happened by then
DC_STATE = {}


def add_decompiler(hx, annotated):
    """Give a fake ida_hexrays module a decompiler for kflow's decompile check: decompile(ea) fails (raises
    DecompilationFailure) for functions in state["always"], and for functions in state["after"] while annotated() is
    true; state["crash"] makes it raise RuntimeError. Results are cached per function like Hex-Rays' cache, so a
    second decompile() returns the first result unless mark_cfunc_dirty(ea) or clear_cached_cfuncs() erased it."""
    state = {"always": set(), "after": set(), "crash": None, "calls": [], "cache": {}, "dirty": 0, "none": False,
             "reason": ""}
    DC_STATE["s"] = state

    class DecompilationFailure(Exception):
        pass

    def decompile(ea, hf=None, flags=0):
        state["calls"].append(ea)
        state.setdefault("flags", []).append(flags)
        if state["crash"] and (not state.get("crash_after_only") or annotated()):
            raise RuntimeError(state["crash"])
        if ea not in state["cache"]:
            state["cache"][ea] = not (ea in state["always"] or (ea in state["after"] and annotated()))
        if not state["cache"][ea]:
            if hf is not None and state["reason"]:  # Hex-Rays fills the caller's hexrays_failure_t on failure
                hf.code, hf.errea, hf.str = -1, ea, state["reason"]
            if state["none"]:  # current IDAPython returns None on failure (SDK hexrays.i decompile_function pythonappend)
                return None
            raise DecompilationFailure("fake failure at 0x%X" % ea)
        return ("cfunc", ea)

    def mark_cfunc_dirty(ea, close_views=False):
        state["dirty"] += 1
        return state["cache"].pop(ea, None) is not None
    flush = getattr(hx, "clear_cached_cfuncs", None)

    def clear_cached_cfuncs():
        state["cache"].clear()
        if flush is not None:
            flush()
    class hexrays_failure_t(object):
        """SDK: fields code, errea, str; desc() gives the text (py_hexrays.py: repr is 'errea: desc')."""
        def __init__(self):
            self.code, self.errea, self.str = 0, 0xFFFFFFFFFFFFFFFF, ""

        def desc(self):
            return self.str
    hx.hexrays_failure_t = hexrays_failure_t
    hx.DecompilationFailure = DecompilationFailure
    hx.DECOMP_NO_WAIT = 1  # as in the 9.1 and 9.5 stubs
    hx.decompile = decompile
    hx.mark_cfunc_dirty = mark_cfunc_dirty
    hx.clear_cached_cfuncs = clear_cached_cfuncs
    return state


def run(path):
    cli_elf = Elf(path)
    ref = load(cli_elf)
    elf = PackedElf(path) if cli_elf.relocatable else cli_elf  # the database: imports packed like IDA's
    w = world_from(elf)
    il = install(w)
    t = il.scan()
    lost = [n for k in ("bug", "jump", "ex") for n in il.core.TABLES[k] if n in elf.symbols and elf.by_addr.get(elf.symbols[n]) != n]
    if lost:
        assert all(v in ("input file symbols", "names") for v in t["found_by"].values()), t["found_by"]
        print("  names IDA would not keep (found through the input file): %s" % ", ".join(lost))
    for k in ("bug", "jump", "ex"):
        assert len(t[k]) == len(ref.get(k, [])), (k, len(t[k]), len(ref.get(k, [])))
    # IDA's own references at enabled x86 jmp sites, and one user comment, exist before we start
    own = 0
    for j in t["jump"]:
        b = elf.read(j.code, 4)
        enabled = b and ((elf.arch == "x86_64" and b[0] in (0xE9, 0xEB))
                         or (elf.arch == "aarch64" and len(b) == 4 and int.from_bytes(b, "little") >> 26 == 0b000101))
        if not j.init and enabled:
            w["xrefs"][(j.code, j.target)] = False
            w["by_from"].setdefault(j.code, set()).add(j.target)
            own += 1
    # a reference the user added before kflow ran, at one of kflow's own sites: Remove must keep it
    mine = next(((j.code, j.target) for j in t["jump"] if il.in_text(j.code) and il.in_text(j.target)
                 and (j.code, j.target) not in w["xrefs"]), None)
    if mine is not None:
        w["xrefs"][mine] = True
        w["by_from"].setdefault(mine[0], set()).add(mine[1])
    # a fixup that is the very next instruction: ordinary flow, so kflow adds no reference there
    nxt = next(((x.insn, x.fixup) for x in t["ex"] if il.in_text(x.insn) and il.in_text(x.fixup)
                and (x.insn, x.fixup) not in w["xrefs"]), None)
    if nxt is not None:
        w.setdefault("item_end", {})[nxt[0]] = nxt[1]
    note = next((b.addr for b in t["bug"] if il.in_text(b.addr)), None)
    if note is not None:
        w["cmts"][note] = "my note"
    other = next((b.addr for b in t["bug"] if il.in_text(b.addr) and b.addr != note), None)
    if other is not None:
        w["cmts"][other] = "kflow-like note by the user"  # starts with "kflow" but is not ours
    pre = next(((j.code, j.key) for j in t["jump"] if il.in_text(j.code)), None)
    if pre:
        w["drefs"][pre] = True  # the user's own reference site -> key: kept, not recorded
        w.setdefault("dref_keys", {}).setdefault(pre[0], set()).add(pre)
    res = il.annotate(t, il.current_arch())
    if not elf.relocatable:  # IDA's name list gives every key the same name as the command line
        bad = [hex(j.key) for j in t["jump"] if il.key_name(j.key) != (elf.key_name(j.key) or "0x%X" % j.key)]
        assert not bad, bad[:5]
    else:  # a module: keys in imports keep their own import's name, although IDA packs the imports
        want = [cli_elf.key_name(c.key) or "0x%X" % c.key for c in ref.get("jump", [])]
        bad = [(hex(j.entry), il.site_key_name(j), x) for j, x in zip(t["jump"], want) if il.site_key_name(j) != x]
        assert not bad, bad[:5]
        offs = sum(1 for c in ref.get("jump", []) if (cli_elf.extern_of(c.key) or (0, 0))[1])
        print("  module keys in imports: %d at import + offset, %d labels from the command line"
              % (offs, len(il.SITE_KEY)))
        lab = [j for j in t["jump"] if j.entry in il.SITE_KEY and il.in_text(j.code)
               and il.key_name(j.key) != il.SITE_KEY[j.entry][0]]  # sites where IDA's own name would be wrong
        assert all(il.key_name(j.key) not in w["cmts"].get(j.code, "") for j in lab), "comment shows the neighbour"
        assert not lab or any(il.SITE_KEY[j.entry][0] in w["cmts"].get(j.code, "") for j in lab)
        if t["jump"]:  # a segment that starts elsewhere than its section: the decodes do not line up, no labels
            seg = il.ida_segment.getseg(t["jump"][0].code)
            seg.start_ea -= 0x40
            try:
                assert il.module_key_labels(t["jump"]) == {}
            finally:
                seg.start_ea += 0x40
            assert il.module_key_labels(t["jump"][:-1]) == {}  # entry counts differ: no labels
        for j in t["jump"]:  # each site's key reference goes to its own import, never a neighbour
            hit = il.SITE_KEY.get(j.entry)
            if hit and il.in_text(j.code):
                assert (j.code, elf.externs[hit[1]]) in w["drefs"], (hex(j.code), hit)
    for a in filter(None, os.environ.get("KFLOW_SHOW", "").split(",")):  # print the comments at these addresses
        print("%s:  %s" % (a, w["cmts"].get(int(a, 16), "(none)")))
    if nxt is not None:
        assert nxt not in w["xrefs"], "no reference to the next instruction"
    if other is not None:
        assert w["cmts"][other] == "kflow-like note by the user"
    assert res["kept_user_comments"] == (1 if note is not None else 0) + (1 if other is not None else 0), res
    if note is not None:
        assert w["cmts"][note] == "my note"
    ours = [c for c in w["cmts"].values() if c.startswith("kflow: ")]
    assert len(ours) <= res["comments"] and ours, (len(ours), res)  # sites sharing an address keep the last comment
    dummy = [c for c in ours if re.search(r"\bunk_[0-9A-F]+\b", c)]  # IDA-style placeholders (the fake get_name() returns them), not "chunk_"
    assert not dummy, dummy[:3]
    users = sum(1 for u in w["xrefs"].values() if u)
    assert users == res["xrefs"] + (mine is not None), (users, res)
    assert len(w["netnodes"].get(il.NODE, {})) == res["xrefs"] and (res["xrefs"] > 0 or not (t["jump"] or t["ex"]))
    assert len(w["netnodes"].get(il.KEY_NODE, {})) == res["key_refs"] == len(w["drefs"]) - (pre is not None)
    assert res["key_refs"] > 0 or not t["jump"] or pre and len(t["jump"]) == 1, res
    rres = {}
    n_drefs = len(w["drefs"])  # Annotate twice: nothing is stale, nothing is added (sites with several entries too)
    again0 = il.annotate(t, il.current_arch())
    assert again0["stale_key_refs"] == 0 and again0["key_refs"] == 0 and len(w["drefs"]) == n_drefs, again0
    if elf.relocatable and il.SITE_KEY:  # Annotate again as if the .ko had moved (no labels): the key references
        saved = dict(il.SITE_KEY)          # point elsewhere now; the earlier ones must not be left behind
        il.SITE_KEY.clear()
        again = il.annotate(t, il.current_arch())
        il.SITE_KEY.update(saved)
        moved = sum(1 for j in t["jump"] if j.entry in saved and il.in_text(j.code)
                    and il.ida_name.get_name_ea(BAD, saved[j.entry][1]) != j.key)  # offset-0 keys do not move
        assert (again["stale_key_refs"] > 0) == (moved > 0), (again, moved)
    removed = il.remove_annotations(t, rres)
    assert removed == res["xrefs"], (removed, res)
    assert rres["key_refs"] == res["key_refs"], (rres, res)  # every key reference kflow added is counted as removed
    assert list(w["drefs"]) == ([pre] if pre else []) and il.KEY_NODE not in w["netnodes"]  # only the user's own stays
    assert sum(1 for u in w["xrefs"].values() if not u) == own  # IDA's own references stay
    assert [k for k, u in w["xrefs"].items() if u] == ([mine] if mine else []), "only the user's own reference stays"
    assert il.NODE not in w["netnodes"]
    assert not any(c.startswith("kflow: ") for c in w["cmts"].values())
    if other is not None:
        assert w["cmts"][other] == "kflow-like note by the user"
    assert il.remove_annotations(t) == 0
    # rebase after annotating: the recorded offsets follow the image base, so Remove still finds every reference
    res2 = il.annotate(t, il.current_arch())
    delta = 0x200000
    w["xrefs"] = {(f + delta, to + delta): u for (f, to), u in w["xrefs"].items()}
    w["by_from"] = {}
    for f, to in w["xrefs"]:
        w["by_from"].setdefault(f, set()).add(to)
    w["drefs"] = {(f + delta, to + delta): u for (f, to), u in w["drefs"].items()}
    w["dref_keys"] = {}
    for k in w["drefs"]:
        w["dref_keys"].setdefault(k[0], set()).add(k)
    w["imagebase"] = w.get("imagebase", 0) + delta
    assert il.remove_annotations({"bug": [], "jump": [], "ex": []}) == res2["xrefs"] == res["xrefs"]
    assert list(w["drefs"]) == ([(pre[0] + delta, pre[1] + delta)] if pre else []), "key refs follow a rebase"
    assert [k for k, u in w["xrefs"].items() if u] == ([(mine[0] + delta, mine[1] + delta)] if mine else [])
    # rebase with the __start_/__stop_ names gone from the database: the shift comes from an anchor name it kept
    fs = il.file_symbols()
    anchor = next((n for n in il.ANCHORS if n in fs), None)
    if anchor is not None:
        assert il._shift(fs) == 0
        keep = il.ida_name.get_name_ea
        il.ida_name.get_name_ea = lambda base, n: fs[n] + 0x200000 if n == anchor else BAD
        try:
            assert il._shift(fs) == 0x200000
        finally:
            il.ida_name.get_name_ea = keep
    print("OK %s: found by %s; %d comments, %d user xrefs added and removed, %d IDA xrefs + %d earlier user xref kept, "
          "%d user comments kept" % (os.path.basename(path), t["found_by"], res["comments"], res["xrefs"], own,
                                     mine is not None, res["kept_user_comments"]))
    return t, w


def other_function(path):
    """A static-key target or fixup inside ANOTHER function (not at its start) gets a data reference, recorded and
    removed like the rest; at another function's start, in the same function or in no function: a jump reference."""
    cli_elf = Elf(path)
    elf = PackedElf(path) if cli_elf.relocatable else cli_elf
    w = world_from(elf)
    il = install(w)
    t = il.scan()
    arch = il.current_arch()
    pairs = [(x.insn, x.fixup) for x in t["ex"]] + [(j.code, j.target) for j in t["jump"]]
    srcs = collections.Counter(s for s, _ in pairs)
    dsts = collections.Counter(d for _, d in pairs)  # fixups often share a landing pad: use targets of one site only
    pts = sorted({a for p in pairs for a in p})

    def free(lo, hi):  # no other site or target inside [lo, hi)
        i = bisect.bisect_left(pts, lo)
        return [a for a in pts[i:bisect.bisect_left(pts, hi)]]
    chosen, ranges = [], []
    for s, d in pairs:
        if (srcs[s] != 1 or dsts[d] != 1 or not il.in_text(s) or not il.in_text(d) or il.branches_to(s, d, arch) or d == s + 1
                or abs(d - s) < 8 or abs(d - s) > 0x100):
            continue
        case = len(chosen)
        want = ([(s, s + 2), (d - 2, d + 2)] if case == 0 else [(s, s + 2), (d, d + 2)] if case == 1
                else [(min(s, d), max(s, d) + 2)])
        if any(sorted(set(free(lo, hi)) - {s, d}) for lo, hi in want) or any(
                lo < h2 and l2 < hi for lo, hi in want for l2, h2 in ranges):
            continue
        chosen.append((s, d))
        ranges += want
        if len(chosen) == 3:
            break
    if len(chosen) < 3:
        print("  other-function check skipped: no three separate sites in %s" % os.path.basename(path))
        return
    first = il.annotate(t, arch)  # before IDA has made the functions: jump references everywhere
    assert first["other_refs"] == 0 and w["xrefs"].get(chosen[0]) is True
    w["func_of"] = lambda ea: next(((lo, hi) for lo, hi in ranges if lo <= ea < hi), None)
    assert [p for p in pairs if il.in_other_function(*p)] == [chosen[0]], "only the first pair is in another function"
    s0, d0 = chosen[0]
    # re-Annotate after analysis: kflow's own jump reference becomes a data reference; and back when that changes
    conv = il.annotate(t, arch)
    assert conv["changed_refs"] == 1 and conv["other_refs"] == 1 and chosen[0] not in w["xrefs"], conv
    assert w["drefs"].get(chosen[0]) is True and il.NODE in w["netnodes"]
    keep = w["func_of"]
    w["func_of"] = lambda ea: None if ea == d0 else keep(ea)
    back = il.annotate(t, arch)
    assert back["changed_refs"] == 1 and back["xrefs"] == 1 and chosen[0] not in w["drefs"] and w["xrefs"].get(chosen[0]) is True
    assert not w["netnodes"].get(il.OTHER_NODE)
    w["func_of"] = keep
    assert il.annotate(t, arch)["changed_refs"] == 1  # other function again
    assert il.remove_annotations(t) >= 0 and chosen[0] not in w["drefs"] and not any(w["xrefs"].values())
    # source in no function: still another function's middle -> data reference; a tail the source function shares,
    # and the source function's own .cold part -> jump reference
    w["func_of"] = lambda ea: None if s0 <= ea < s0 + 2 else keep(ea)
    assert il.in_other_function(s0, d0)
    w["func_of"] = keep
    w["shared"] = {s0: {d0}}
    assert not il.in_other_function(s0, d0)
    w.pop("shared")
    w["func_names"] = {s0: "foo.isra.0", d0 - 2: "foo.isra.0.cold"}
    assert not il.in_other_function(s0, d0)
    w["func_names"] = {s0: "foo", d0 - 2: "foobar.cold"}
    assert il.in_other_function(s0, d0)
    w.pop("func_names")
    # a data reference that is there already (IDA's own, not a user one): nothing added, Remove leaves it
    w["drefs"][chosen[0]] = False
    w.setdefault("dref_keys", {}).setdefault(s0, set()).add(chosen[0])
    r0 = il.annotate(t, arch)
    assert r0["other_refs"] == 0 and not w["netnodes"].get(il.OTHER_NODE) and chosen[0] not in w["xrefs"], r0
    il.remove_annotations(t)
    assert w["drefs"].get(chosen[0]) is False
    w["drefs"].pop(chosen[0])
    w["dref_keys"][s0].discard(chosen[0])
    # IDA's own jump reference at the pair (e.g. analysis found it): no data reference is added next to it
    w["xrefs"][chosen[0]] = False
    w["by_from"].setdefault(s0, set()).add(d0)
    r1 = il.annotate(t, arch)
    assert r1["other_refs"] == 0 and chosen[0] not in w["drefs"] and w["xrefs"][chosen[0]] is False, r1
    il.remove_annotations(t)
    assert w["xrefs"].pop(chosen[0]) is False
    w["by_from"][s0].discard(d0)
    w.setdefault("item_end", {})[s0] = d0  # the target is the next instruction: ordinary flow, no reference at all
    r2 = il.annotate(t, arch)
    assert r2["other_refs"] == 0 and chosen[0] not in w["drefs"] and chosen[0] not in w["xrefs"], r2
    il.remove_annotations(t)
    w["item_end"].pop(s0)
    # a static-key site that is a jmp to its target now (IDA makes that reference itself): nothing added either
    en = next(((s, d) for s, d in pairs if srcs[s] == 1 and dsts[d] == 1 and il.in_text(s) and il.in_text(d)
               and il.branches_to(s, d, arch) and abs(d - s) >= 8
               and not sorted(set(free(s, s + 2)) - {s, d}) and not sorted(set(free(d - 2, d + 2)) - {s, d})
               and not any(lo < h2 and l2 < hi for lo, hi in ((s, s + 2), (d - 2, d + 2)) for l2, h2 in ranges)), None)
    if en is not None:
        ranges += [(en[0], en[0] + 2), (en[1] - 2, en[1] + 2)]
        assert il.in_other_function(*en)
        r3 = il.annotate(t, arch)
        assert en not in w["drefs"] and en not in w["xrefs"], r3
        il.remove_annotations(t)
        del ranges[-2:]
    w["imagebase"] = 0x10000  # a non-zero image base, so the rebase below checks the recorded offsets
    res = il.annotate(t, arch)
    assert res["other_refs"] == 1 and w["drefs"].get(chosen[0]) is True and chosen[0] not in w["xrefs"], res
    assert w["xrefs"].get(chosen[1]) is True and w["xrefs"].get(chosen[2]) is True  # function start; same function
    assert len(w["netnodes"].get(il.OTHER_NODE, {})) == 1
    assert "inside another function: 1" in il.annotate_text(res)
    again = il.annotate(t, arch)
    assert again["other_refs"] == 0 and again["xrefs"] == 0, again
    w["drefs"][chosen[0]] = False  # no longer a user reference (IDA's own now): Remove leaves it
    assert il.remove_annotations(t, {}) == res["xrefs"] and w["drefs"].get(chosen[0]) is False
    w["drefs"].pop(chosen[0])
    res = il.annotate(t, arch)
    assert res["other_refs"] == 1 and w["drefs"].get(chosen[0]) is True
    rres = {}
    delta = 0x200000  # rebase between Annotate and Remove: the data reference is still found
    w["xrefs"] = {(f + delta, to + delta): u for (f, to), u in w["xrefs"].items()}
    w["by_from"] = {}
    for f, to in w["xrefs"]:
        w["by_from"].setdefault(f, set()).add(to)
    w["drefs"] = {(f + delta, to + delta): u for (f, to), u in w["drefs"].items()}
    w["dref_keys"] = {}
    for k in w["drefs"]:
        w["dref_keys"].setdefault(k[0], set()).add(k)
    w["imagebase"] = w.get("imagebase", 0) + delta
    removed = il.remove_annotations({"bug": [], "jump": [], "ex": []}, rres)
    assert removed == res["xrefs"] and rres["other_refs"] == 1, (removed, rres)
    assert not any(w["drefs"].values()) and il.OTHER_NODE not in w["netnodes"] and not any(w["xrefs"].values())
    print("OK other function: data reference into another function (also from a source in no function) added, changed"
          " back and forth when IDA's functions change, removed after a rebase; jump references at a function start,"
          " inside the same function, a shared tail, the function's .cold part and outside functions; IDA's own data"
          " reference kept (%s)" % os.path.basename(path))


def _db(path):
    cli_elf = Elf(path)
    elf = PackedElf(path) if cli_elf.relocatable else cli_elf
    w = world_from(elf)
    il = install(w)
    return elf, w, il, il.scan()


def _funcs(elf):
    starts = [f[0] for f in elf.funcs]

    def func_of(ea):  # IDA's functions once analysis has made them: the ELF's function symbols
        i = bisect.bisect_right(starts, ea) - 1
        return elf.funcs[i][:2] if i >= 0 and ea < elf.funcs[i][1] else None
    return func_of


def analysis_running(path):
    """Annotate right after loading, while IDA's auto-analysis still runs (review s158 F1): no site is an instruction
    yet and IDA has made no functions. An xref's source must be an item head (ida_xref.pyi) and get_item_end() counts
    unexplored bytes as 1-byte items, so a fixup that is the next instruction would get a user jump reference that a
    later Annotate keeps. kflow adds no reference from such a site and counts it; once analysis has finished, a second
    Annotate adds exactly what Annotate on the analysed database adds."""
    elf, w, il, t = _db(path)
    arch = il.current_arch()
    w["code"], w["auto_ok"], w["func_of"] = set(), False, _funcs(elf)
    res = il.annotate(t, arch)
    assert not w["xrefs"] and not w["drefs"], "%d jump and %d data references from addresses that are not " \
        "instructions yet" % (len(w["xrefs"]), len(w["drefs"]))
    sites = sum(1 for j in t["jump"] if il.in_text(j.code)) + sum(1 for x in t["ex"] if il.in_text(x.insn))
    assert res.get("not_code") == sites and res["xrefs"] == res["key_refs"] == res["other_refs"] == 0, (res, sites)
    assert not any(w["netnodes"].get(n) for n in (il.NODE, il.KEY_NODE, il.OTHER_NODE)) and il.annotated()
    assert res["comments"] > 0 and "%d static-key / exception-table sites are not instructions yet" % sites in \
        il.annotate_text(res) or not sites, il.annotate_text(res)
    # review s159 NIT: once analysis has finished, waiting changes nothing: the text says what to do instead
    done_text = il.annotate_text(res, analysis_done=True)
    assert not sites or ("%d static-key / exception-table sites are not code in IDA" % sites in done_text
                         and "press C" in done_text and "not instructions yet" not in done_text), done_text
    # auto-analysis finished: every site an instruction, the functions made
    w.pop("code")
    w["auto_ok"] = True
    res2 = il.annotate(t, arch)
    _, w2, il2, t2 = _db(path)  # the same database annotated only after analysis
    w2["func_of"] = _funcs(elf)
    ref = il2.annotate(t2, arch)
    assert res2["not_code"] == 0 and (res2["xrefs"], res2["key_refs"], res2["other_refs"]) == (
        ref["xrefs"], ref["key_refs"], ref["other_refs"]), (res2, ref)
    assert w["xrefs"] == w2["xrefs"] and w["drefs"] == w2["drefs"] and w["netnodes"] == w2["netnodes"]
    print("OK analysis running: %d sites not instructions yet, no reference added from them; after analysis %d jump, "
          "%d key and %d other-function references as on the analysed database (%s)"
          % (sites, res2["xrefs"], res2["key_refs"], res2["other_refs"], os.path.basename(path)))


def stale_next_insn(path):
    """An earlier Annotate (kflow 0.0.4 and older, run while the sites were unexplored bytes) recorded a user
    reference to the next instruction, a jump reference and, from a run that saw the target in another function, a
    data reference (review s158 F1). Annotate after analysis deletes both and their records, and adds every other
    reference exactly as on a database annotated only after analysis; Remove then leaves no user reference."""
    elf, w, il, t = _db(path)
    arch = il.current_arch()
    srcs = collections.Counter([j.code for j in t["jump"]] + [x.insn for x in t["ex"]])
    nxt = [x for x in t["ex"] if srcs[x.insn] == 1 and il.in_text(x.insn) and il.in_text(x.fixup)
           and 0 < x.fixup - x.insn <= 15 and not il.branches_to(x.insn, x.fixup, arch)][:2]
    if len(nxt) < 2:
        print("  stale next-instruction check skipped: no two exception sites in %s" % os.path.basename(path))
        return
    base = w["imagebase"] = 0x10000
    ends = {x.insn: x.fixup for x in nxt}  # both fixups are the next instruction
    _, w2, il2, t2 = _db(path)
    w2["imagebase"], w2["item_end"] = base, dict(ends)
    ref = il2.annotate(t2, arch)
    (a, fa), (b, fb) = [(x.insn, x.fixup) for x in nxt]
    w["xrefs"][(a, fa)] = True
    w["by_from"].setdefault(a, set()).add(fa)
    w["drefs"][(b, fb)] = True
    w.setdefault("dref_keys", {}).setdefault(b, set()).add((b, fb))
    w["netnodes"][il.NODE] = {(a - base) & il.MASK: (fa - base) & il.MASK}
    w["netnodes"][il.OTHER_NODE] = {(b - base) & il.MASK: (fb - base) & il.MASK}
    w["item_end"] = dict(ends)
    w["flow"], w["del_clears_flow"] = {fa, fb}, True  # review s159 MINOR 2: if del_cref also cleared the flow
    res = il.annotate(t, arch)
    assert {fa, fb} <= w["flow"], "deleting the stale reference lost IDA's ordinary flow to the next instruction"
    assert (a, fa) not in w["xrefs"] and (b, fb) not in w["drefs"], "the earlier next-instruction reference is still there"
    assert res.get("next_insn_refs") == 2 and res["not_code"] == 0, res
    assert w["xrefs"] == w2["xrefs"] and w["drefs"] == w2["drefs"] and w["netnodes"] == w2["netnodes"], "other references"
    assert (res["xrefs"], res["key_refs"], res["other_refs"]) == (ref["xrefs"], ref["key_refs"], ref["other_refs"]), (res, ref)
    assert "references to the next instruction removed (added by an earlier Annotate" in il.annotate_text(res)
    again = il.annotate(t, arch)
    assert again["next_insn_refs"] == again["xrefs"] == again["key_refs"] == 0, again
    il.remove_annotations(t)
    assert not any(w["xrefs"].values()) and not any(w["drefs"].values()), "Remove left a user reference"
    for flow in ({fa}, set()):  # review s159 MINOR 1: Remove puts back only flow that was there, and never invents it
        w["xrefs"][(a, fa)] = True
        w["by_from"].setdefault(a, set()).add(fa)
        w["netnodes"].setdefault(il.NODE, {})[(a - base) & il.MASK] = (fa - base) & il.MASK
        w["flow"], w["del_clears_flow"] = set(flow), True
        il.remove_annotations(t)
        assert (a, fa) not in w["xrefs"] and (fa in w["flow"]) == bool(flow), (flow, w["flow"])
    # Annotate path, no flow there before: none afterwards either
    w["xrefs"][(a, fa)] = True
    w["by_from"].setdefault(a, set()).add(fa)
    w["netnodes"].setdefault(il.NODE, {})[(a - base) & il.MASK] = (fa - base) & il.MASK
    w["flow"], w["del_clears_flow"] = set(), True
    il.annotate(t, arch)
    assert (a, fa) not in w["xrefs"] and fa not in w["flow"], "Annotate invented ordinary flow"
    il.remove_annotations(t)
    print("OK stale next instruction: a jump and a data reference an earlier Annotate recorded to the next instruction "
          "deleted with their records, the other %d references as on a database annotated after analysis (%s)"
          % (res["xrefs"] + res["key_refs"] + res["other_refs"], os.path.basename(path)))


HIDDEN_NOP = "; nothing else in the database jumps or falls through to 0x%X, so this pseudocode probably does not show that code"
HIDDEN_JMP = ("; the site is a jump here and nothing else in the database jumps or falls through to the next instruction "
              "0x%X (run when the key is %s), so this pseudocode probably does not show that code")


def hidden_path(path):
    """Judge item 4 (s160): the pseudocode text says the site's other path is hidden only when nothing but kflow leads
    there: no ordinary flow into it (FF_FLOW), no jump/call reference from anywhere but the site itself and the
    references kflow recorded (another static-key site or a faulting instruction that points at the same address).
    NOP-state sites: the target; jmp-state sites: the instruction after the jmp."""
    elf, w, il, t = _db(path)
    arch = il.current_arch()
    srcs = collections.Counter([j.code for j in t["jump"]] + [x.insn for x in t["ex"]])
    dsts = collections.Counter([j.target for j in t["jump"]] + [x.fixup for x in t["ex"]])
    for j in t["jump"]:  # IDA's own references at the enabled jmp sites, as in run()
        if il.branches_to(j.code, j.target, arch):
            w["xrefs"][(j.code, j.target)] = False
            w["by_from"].setdefault(j.code, set()).add(j.target)
    w["imagebase"] = base = 0x10000  # the recorded offsets are relative to the image base
    il.annotate(t, arch)
    to_srcs = collections.defaultdict(list)
    for (s, d) in w["xrefs"]:
        to_srcs[d].append(s)

    def lone(j):
        return srcs[j.code] == 1 and il.in_text(j.code) and il.in_text(j.target) and dsts[j.target] == 1
    nop = next((j for j in t["jump"] if lone(j) and not il.branches_to(j.code, j.target, arch)
                and j.target != il.ida_bytes.get_item_end(j.code) and w["xrefs"].get((j.code, j.target)) is True
                and to_srcs.get(j.target) == [j.code]), None)
    jmp = next((j for j in t["jump"] if lone(j) and il.branches_to(j.code, j.target, arch)
                and il.in_text(il.ida_bytes.get_item_end(j.code)) and il.ida_bytes.get_item_end(j.code) not in to_srcs
                and il.ida_bytes.get_item_end(j.code) not in dsts), None)
    if nop is None and jmp is None:
        print("  hidden-path check skipped: no lone static-key site in %s" % os.path.basename(path))
        return
    other = next(a for a in sorted(srcs) if il.in_text(a) and all(a != j.code for j in (nop, jmp) if j))
    cases = []
    if nop is not None:
        d, want = nop.target, HIDDEN_NOP % nop.target
        assert il.hidden_path_text(nop, arch) == want, il.hidden_path_text(nop, arch)
        # another kflow site's recorded reference to the same target is not flow either
        w["xrefs"][(other, d)] = True
        w["netnodes"][il.NODE][(other - base) & il.MASK] = (d - base) & il.MASK
        assert il.hidden_path_text(nop, arch) == want, "kflow's own reference from another site counted as flow"
        # review s177 m1: the user then patched that other site to a jump there: its old record does not make it kflow's
        get = il.ida_bytes.get_bytes
        jb = (b"\xe9" + ((d - other - 5) & 0xFFFFFFFF).to_bytes(4, "little")) if arch == "x86_64" else \
            (0x14000000 | (((d - other) >> 2) & 0x3FFFFFF)).to_bytes(4, "little")
        il.ida_bytes.get_bytes = lambda ea, n: jb[:n] if ea == other else get(ea, n)
        assert il.branches_to(other, d, arch)
        assert il.hidden_path_text(nop, arch) == "", "a recorded site patched to jump there counted as kflow's"
        il.ida_bytes.get_bytes = get
        del w["netnodes"][il.NODE][(other - base) & il.MASK]  # the same reference, not recorded: the user's own
        assert il.hidden_path_text(nop, arch) == "", "a user reference kflow did not add is another path"
        # review s177 m2 (b): other has a kflow record, but for another address: its reference to d is still a path
        w["netnodes"][il.NODE][(other - base) & il.MASK] = (d + 1 - base) & il.MASK
        assert il.hidden_path_text(nop, arch) == "", "a source kflow recorded for another target counted as kflow's"
        del w["netnodes"][il.NODE][(other - base) & il.MASK]
        w["xrefs"][(other, d)] = False  # IDA's own branch from elsewhere
        assert il.hidden_path_text(nop, arch) == "", "IDA branches there from elsewhere"
        del w["xrefs"][(other, d)]
        w["drefs"][(other, d)] = True  # a data reference (an address taken) is not flow
        assert il.hidden_path_text(nop, arch) == want
        del w["drefs"][(other, d)]
        w["flow"] = {d}  # the previous instruction falls into the target
        assert il.hidden_path_text(nop, arch) == "", "ordinary flow reaches the target"
        w["flow"] = set()
        w["code"] = {nop.code}  # the target is not an instruction (yet): nothing is known, nothing said
        assert il.hidden_path_text(nop, arch) == ""
        w["code"] = {d}  # the site is not an instruction: kflow added no reference from it, nothing said
        assert il.hidden_path_text(nop, arch) == ""
        del w["code"]
        assert il.hidden_path_text(nop, arch) == want
        # review s177 m2 (c): the site's own reference to its target that kflow did not record (the user's, or one a
        # Remove left) is the pair kflow would add, not a path from elsewhere: the NOP still never jumps there
        rec = w["netnodes"][il.NODE].pop((nop.code - base) & il.MASK)
        assert w["xrefs"].get((nop.code, d)) is True
        assert il.hidden_path_text(nop, arch) == want, "the site's own unrecorded reference counted as another path"
        w["netnodes"][il.NODE][(nop.code - base) & il.MASK] = rec
        cases.append("NOP site 0x%X" % nop.code)
    if jmp is not None:
        f = il.ida_bytes.get_item_end(jmp.code)
        want = HIDDEN_JMP % (f, "on" if jmp.branch else "off")  # it jumps when (key XOR branch bit): falls through otherwise
        assert il.hidden_path_text(jmp, arch) == want, il.hidden_path_text(jmp, arch)
        w["xrefs"][(other, f)] = False  # some branch reaches the fall-through: the decompiler can show it
        assert il.hidden_path_text(jmp, arch) == "", "the key-off/on fall-through is reached by another branch"
        del w["xrefs"][(other, f)]
        w["flow"] = {f}
        assert il.hidden_path_text(jmp, arch) == ""
        w["flow"] = set()
        cases.append("jmp site 0x%X" % jmp.code)
    # review s177 B1: a site that jumps to the very next instruction (x86 'eb 00', arm64 'b .+4'; 13 on the demo
    # kernel) runs it in both key states, and IDA's own jump reference from the site is that path: no sentence.
    # Where the ELF has none, one is made at a site (its bytes, item end and IDA's reference).
    nxt = [j for j in t["jump"] if il.in_text(j.code) and il.is_insn(j.code)
           and j.target == il.ida_bytes.get_item_end(j.code) and il.branches_to(j.code, j.target, arch)]
    get, made = il.ida_bytes.get_bytes, None
    if not nxt:
        s = (jmp or nop).code
        raw = b"\xeb\x00" if arch == "x86_64" else (0x14000001).to_bytes(4, "little")
        il.ida_bytes.get_bytes = lambda ea, n: raw[:n] if ea == s else get(ea, n)
        w.setdefault("item_end", {})[s] = s + len(raw)
        w["xrefs"][(s, s + len(raw))] = False
        w["by_from"].setdefault(s, set()).add(s + len(raw))
        made = types.SimpleNamespace(code=s, target=s + len(raw), branch=0)
        nxt = [made]
    for j in nxt:
        got = il.hidden_path_text(j, arch)
        assert got == "", "site 0x%X jumps to the next instruction itself: %s" % (j.code, got)
    j = nxt[0]
    w["xrefs"].pop((j.code, j.target))  # even without IDA's own jump reference: the site itself runs the next insn
    got = il.hidden_path_text(j, arch)
    assert got == "", "site 0x%X jumps to the next instruction, no IDA reference: %s" % (j.code, got)
    w["xrefs"][(j.code, j.target)] = False
    if made is not None:
        il.ida_bytes.get_bytes = get
        del w["item_end"][made.code], w["xrefs"][(made.code, made.target)]
        w["by_from"][made.code].discard(made.target)
    cases.append("%d jump%s to the next instruction%s" % (len(nxt), "" if len(nxt) == 1 else "s",
                                                          " (made)" if made else ""))
    print("OK hidden path: the sentence only where nothing but kflow leads to the other path (%s; IDA branch, user "
          "reference, ordinary flow, not code: no sentence) (%s)" % (", ".join(cases), os.path.basename(path)))


def target_blocks(path):
    """Spec step 3 (judge item 4): the static-key chooser's 'bytes / insns' of the out-of-line block at a target,
    decoded forward with ida_ua.decode_insn by the block rule of tools/reach.py: up to and including the first
    instruction that does not pass execution to the next one; ending earlier before a join (a jump or call reference
    from elsewhere that kflow did not record), before an x86 int3 and where executable code ends; at most 4096
    instructions ('+' then); '?' when an instruction cannot be decoded. Each case lays its own bytes at one target."""
    elf, w, il, t = _db(path)
    arch = il.current_arch()
    a = next((j.target for j in t["jump"] if il.in_text(j.target) and il.in_text(j.target + 64)), None)
    if a is None:
        print("  target-block check skipped: no static-key target in code in %s" % os.path.basename(path))
        return
    other = next(j.code for j in t["jump"] if il.in_text(j.code) and not a - 64 <= j.code < a + 64)
    get = il.ida_bytes.get_bytes
    w["imagebase"] = base = 0x10000

    def block(code):  # target_block and its chooser text with these bytes at a (the database's own bytes elsewhere)
        il.ida_bytes.get_bytes = lambda ea, n: (code[ea - a:] + (get(a + len(code), n) or b""))[:n] \
            if a <= ea < a + len(code) else get(ea, n)
        try:
            return il.target_block(a, arch), il.target_block_text(a, arch)
        finally:
            il.ida_bytes.get_bytes = get
    if arch == "x86_64":
        mov, call, jmp = b"\x48\x89\xc7", b"\xe8" + bytes(4), b"\xe9" + bytes(4)
        seq, starts = mov + call + jmp, [a, a + 3, a + 8]
        assert block(seq) == ((13, 3, False), "13 / 3"), block(seq)  # up to and including the jmp
        assert block(mov + b"\xc3")[0] == (4, 2, False)  # ret
        assert block(call + b"\x0f\x0b" + mov)[0] == (7, 2, False)  # ud2, a BUG/WARN trap
        assert block(mov + call + b"\xcc\xcc")[0] == (8, 2, False), "int3 padding after a call that does not return"
        assert block(b"\xcc" + mov)[0] == (0, 0, False)
        assert block(mov + b"\x0f\x05" + jmp) == (None, "?"), "an instruction the fake cannot decode (syscall)"
        assert block(b"\x0f\x05")[1] == "?"
        w["insns"] = {a: (4, NN_MOV)}  # the bytes of an arm64 ret decide nothing on x86_64 (s179 NIT 4)
        assert block(b"\xc0\x03\x5f\xd6" + mov + jmp)[0] == (12, 3, False)
        del w["insns"]
        kinds = "jmp, ret, ud2 end it (an int3 just before it)"
    else:
        nop, bcond, b, brk, ret = (x.to_bytes(4, "little") for x in (0xD503201F, 0x54000040, 0x14000002, 0xD4210000,
                                                                      0xD65F03C0))
        seq, starts = nop + bcond + b, [a, a + 4, a + 8]
        assert block(seq) == ((12, 3, False), "12 / 3"), block(seq)  # B.cond falls through, B does not
        w["arm_b_stop"] = False  # if IDA's ARM module did not mark B as CF_STOP: the bytes still end the block there
        assert block(seq)[0] == (12, 3, False)
        w["arm_b_stop"] = True
        assert block(nop + brk + nop)[0] == (8, 2, False)  # brk #0x800, a BUG/WARN trap
        assert block(nop + ret + nop)[0] == (8, 2, False)
        w["arm_ret_stop"] = False  # if IDA's ARM module did not mark ret as CF_STOP: the bytes still end the block
        assert block(nop + ret + nop)[0] == (8, 2, False), "ret ended the block only because the fake marks it CF_STOP"
        w["arm_ret_stop"] = True
        # ret x1, br x16, br x10, eret, retaa, retab, eretaa, eretab, braa x16, x17, brab x3, sp, braaz x16, brabz x9:
        # decided by their bytes, whatever IDA marks (review s178 MINOR 2, s179 NITs 1-2; words from clang)
        for word in (0xD65F0020, 0xD61F0200, 0xD61F0140, 0xD69F03E0, 0xD65F0BFF, 0xD65F0FFF, 0xD69F0BFF, 0xD69F0FFF,
                     0xD71F0A11, 0xD71F0C7F, 0xD61F0A1F, 0xD61F0D3F):
            assert block(nop + word.to_bytes(4, "little") + nop)[0] == (8, 2, False), "%08x did not end the block" % word
        # blr x16, blr x3, blraa x16, x17, blrab x1, x2, blraaz x16, blrabz x9 return to the next instruction: never an
        # end, even if IDA marked them CF_STOP (the fake marks everything here)
        w["stop_everything"] = True
        for word in (0xD63F0200, 0xD63F0060, 0xD73F0A11, 0xD73F0C22, 0xD63F0A1F, 0xD63F0D3F):
            assert block(word.to_bytes(4, "little") + ret)[0] == (8, 2, False), "%08x ended the block" % word
        del w["stop_everything"]
        assert block(nop + (0xD63F0200).to_bytes(4, "little") + ret)[0] == (12, 3, False)
        w["insns"] = {a + 4: (0, 0)}
        assert block(nop + nop + ret) == (None, "?")
        del w["insns"]
        kinds = "B, brk, ret, br, eret (also their pointer-authentication forms) end it (B.cond, blr do not)"
    full = (len(seq), 3, False)
    # a join: IDA's jump reference from elsewhere to the second instruction ends the block before it
    w["xrefs"][(other, starts[1])] = False
    assert block(seq)[0] == (starts[1] - a, 1, False), block(seq)
    w["xrefs"][(other, starts[1])] = True  # kflow's own recorded reference there is not a join
    w["netnodes"].setdefault(il.NODE, {})[(other - base) & il.MASK] = (starts[1] - base) & il.MASK
    assert block(seq)[0] == full, "a reference kflow recorded counted as a join"
    del w["netnodes"][il.NODE][(other - base) & il.MASK]  # the same reference unrecorded: the user's, a join
    assert block(seq)[0] == (starts[1] - a, 1, False)
    del w["xrefs"][(other, starts[1])]
    w["drefs"][(other, starts[1])] = True  # a data reference is not flow
    assert block(seq)[0] == full
    del w["drefs"][(other, starts[1])]
    w["xrefs"][(other, a)] = False  # a reference to the target itself: where the block starts anyway
    assert block(seq)[0] == full
    del w["xrefs"][(other, a)]
    # the cap (4096 instructions, as in tools/reach.py): both numbers get '+'
    assert il.BLOCK_CAP == 4096
    il.BLOCK_CAP = 2
    try:
        assert block(seq) == ((starts[2] - a, 2, True), "%d+ / 2+" % (starts[2] - a)), block(seq)
    finally:
        il.BLOCK_CAP = 4096
    # executable code ends after the second instruction (the segment made shorter): the block ends there
    seg = il.ida_segment.getseg(a)
    end, seg.end_ea = seg.end_ea, starts[2]
    try:
        assert block(seq)[0] == (starts[2] - a, 2, False), block(seq)
        assert il.target_block(starts[2], arch) is None and il.target_block_text(starts[2], arch) == "?"
    finally:
        seg.end_ea = end
    assert block(seq)[0] == full
    print("OK target block: %s, a join / the end of code ends it before, kflow's recorded reference and data "
          "references do not, cap 4096 gives '+', undecodable gives '?' (%s)" % (kinds, os.path.basename(path)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("SKIP: pass a kernel ELF path")
        sys.exit(0)
    for p in sys.argv[1:]:
        run(p)
        other_function(p)
        analysis_running(p)
        stale_next_insn(p)
        hidden_path(p)
        target_blocks(p)
