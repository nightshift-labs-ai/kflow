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
X86_LEN = [(b"\xe9", 5), (b"\xeb", 2), (b"\x0f\x1f\x44\x00\x00", 5), (b"\x66\x90", 2), (b"\x0f\x0b", 2), (b"\xe8", 5)]


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
    m["ida_bytes"].get_flags = lambda ea: FF_CODE if is_head(ea) else 0
    m["ida_bytes"].is_code = lambda F: F & MS_CLS == FF_CODE

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
    m["ida_ida"].inf_is_64bit = lambda: True
    m["ida_ida"].inf_get_procname = lambda: "metapc" if elf.arch == "x86_64" else "ARM"
    x = m["ida_xref"]
    x.fl_JN, x.XREF_USER, x.XREF_FAR, x.XREF_DATA, x.dr_O = 19, 32, 1, 2, 1
    w.setdefault("drefs", {})
    m["ida_bytes"].is_mapped = lambda ea: any(s.start_ea <= ea < s.end_ea for s in w["segs"])

    def add_dref(f, t, k):
        w["drefs"][(f, t)] = bool(k & 32)
        w.setdefault("dref_keys", {}).setdefault(f, set()).add((f, t))
        return True
    x.add_dref = add_dref
    x.del_dref = lambda f, t: w["drefs"].pop((f, t), None) and None

    def add_cref(f, t, k):
        w["xrefs"][(f, t)] = bool(k & 32)
        w["by_from"].setdefault(f, set()).add(t)
        return True
    x.add_cref = add_cref

    def del_cref(f, t, expand):
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
    x.xrefblk_t = xrefblk_t
    sys.modules.update(m)
    sys.modules.pop("kflow.idalayer", None)
    return importlib.import_module("kflow.idalayer")


def install_ui(w, log):
    """Fake ida_kernwin, ida_funcs (get_func from the ELF's function symbols), ida_lines and ida_idaapi.plugin_t, to
    load kflow_entry.py (the IDA plugin). Messages, warnings, info boxes, wait boxes, jumps, registered actions and
    choosers shown go to log. Returns the modules and get_func."""
    elf = w["elf"]
    kw = types.ModuleType("ida_kernwin")
    kw.msg = lambda text: log.append(("msg", text))
    kw.warning = lambda text: log.append(("warning", text))
    kw.info = lambda text: log.append(("info", text)) or 0
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

    fn.get_func = get_func
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
    return types.SimpleNamespace(kw=kw, fn=fn, lines=lines_mod, get_func=get_func)


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
    res = il.annotate(t, arch)
    assert (a, fa) not in w["xrefs"] and (b, fb) not in w["drefs"], "the earlier next-instruction reference is still there"
    assert res.get("next_insn_refs") == 2 and res["not_code"] == 0, res
    assert w["xrefs"] == w2["xrefs"] and w["drefs"] == w2["drefs"] and w["netnodes"] == w2["netnodes"], "other references"
    assert (res["xrefs"], res["key_refs"], res["other_refs"]) == (ref["xrefs"], ref["key_refs"], ref["other_refs"]), (res, ref)
    assert "references to the next instruction removed (added by an earlier Annotate" in il.annotate_text(res)
    again = il.annotate(t, arch)
    assert again["next_insn_refs"] == again["xrefs"] == again["key_refs"] == 0, again
    il.remove_annotations(t)
    assert not any(w["xrefs"].values()) and not any(w["drefs"].values()), "Remove left a user reference"
    print("OK stale next instruction: a jump and a data reference an earlier Annotate recorded to the next instruction "
          "deleted with their records, the other %d references as on a database annotated after analysis (%s)"
          % (res["xrefs"] + res["key_refs"] + res["other_refs"], os.path.basename(path)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("SKIP: pass a kernel ELF path")
        sys.exit(0)
    for p in sys.argv[1:]:
        run(p)
        other_function(p)
        analysis_running(p)
        stale_next_insn(p)
