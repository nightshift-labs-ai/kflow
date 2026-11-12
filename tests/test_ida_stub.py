"""Runs kflow's IDA layer on fake ida_* modules backed by a real kernel ELF.
Usage: python3 tests/test_ida_stub.py <kernel.elf> [<stripped vmlinux>]   (SKIPs without a path)"""
import bisect
import importlib
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from kflow.cli import Elf, load  # noqa: E402

BAD = 2 ** 64 - 1


class Seg:
    def __init__(self, s, e, perm, name):
        self.start_ea, self.end_ea, self.perm, self.type, self.name = s, e, perm, 0, name


def world_from(elf):
    segs = []
    for name, (a, e) in elf.sections.items():
        exe = any(a <= ta < e for ta, te in elf.text)
        segs.append(Seg(a, e, 1 if exe else 4, name))
    if not segs:  # ELF without section names: one segment per loaded range
        segs = [Seg(a, e, 1 if any(a <= ta < e for ta, te in elf.text) else 4, "seg%d" % i)
                for i, (a, e, o) in enumerate(elf.loaded)]
    segs.sort(key=lambda s: s.start_ea)
    return {"segs": segs, "starts": [s.start_ea for s in segs], "cmts": {}, "xrefs": {}, "by_from": {}, "elf": elf,
            "path": elf.path}


def install(w, names=True):
    elf = w["elf"]
    m = {n: types.ModuleType(n) for n in "ida_bytes ida_ida ida_idaapi ida_name ida_segment ida_xref".split()}
    m["ida_idaapi"].BADADDR = BAD

    def getseg(ea):
        i = bisect.bisect_right(w["starts"], ea) - 1
        return w["segs"][i] if i >= 0 and ea < w["segs"][i].end_ea else None
    m["ida_segment"].getseg = getseg
    m["ida_segment"].get_segm_by_name = lambda n: next((s for s in w["segs"] if s.name == n), None)
    m["ida_segment"].SEGPERM_EXEC, m["ida_segment"].SEG_CODE = 1, 2
    m["ida_segment"].get_segm_qty = lambda: len(w["segs"])
    m["ida_segment"].getnseg = lambda n: w["segs"][n] if 0 <= n < len(w["segs"]) else None
    m["ida_bytes"].get_bytes = lambda ea, n: elf.read(ea, n)
    m["ida_bytes"].is_loaded = lambda ea: elf.read(ea, 1) is not None
    m["ida_bytes"].get_cmt = lambda ea, rep: w["cmts"].get(ea)
    m["ida_bytes"].get_item_end = lambda ea: w.get("item_end", {}).get(ea, ea + 1)

    def set_cmt(ea, text, rep):
        if text:
            w["cmts"][ea] = text
        else:
            w["cmts"].pop(ea, None)
        return True
    m["ida_bytes"].set_cmt = set_cmt
    # IDA keeps ONE name per address: a symbol sharing its address with an earlier one is not in the database
    m["ida_name"].get_name_ea = lambda base, n: (elf.symbols[n] if names and n in elf.symbols
                                                 and elf.by_addr.get(elf.symbols[n]) == n else BAD)
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


def run(path):
    elf = Elf(path)
    ref = load(elf)
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
    dummy = [c for c in ours if "unk_" in c]  # the fake get_name() returns IDA-style placeholder names: never show them
    assert not dummy, dummy[:3]
    users = sum(1 for u in w["xrefs"].values() if u)
    assert users == res["xrefs"] + (mine is not None), (users, res)
    assert len(w["netnodes"].get(il.NODE, {})) == res["xrefs"] and (res["xrefs"] > 0 or not (t["jump"] or t["ex"]))
    assert len(w["netnodes"].get(il.KEY_NODE, {})) == res["key_refs"] == len(w["drefs"]) - (pre is not None)
    assert res["key_refs"] > 0 or not t["jump"] or pre and len(t["jump"]) == 1, res
    removed = il.remove_annotations(t)
    assert removed == res["xrefs"], (removed, res)
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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("SKIP: pass a kernel ELF path")
        sys.exit(0)
    for p in sys.argv[1:]:
        run(p)
