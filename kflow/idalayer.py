"""IDA side of kflow: find the kernel's site tables in the database, comment the sites, add references."""
import bisect
import os

import ida_bytes
import ida_ida
import ida_idaapi
import ida_nalt
import ida_name
import ida_netnode
import ida_segment
import ida_xref

from . import core

TAG = "kflow"
BADADDR = ida_idaapi.BADADDR
TRAP_LEN = {"x86_64": 2, "aarch64": 4}
NODE = "$ kflow created xrefs"  # site -> target of every reference kflow itself added (offsets from the image base)
KEY_NODE = "$ kflow created key refs"  # static-key site -> key, the data references kflow added
MASK = (1 << 64) - 1


def current_arch():
    if not ida_ida.inf_is_64bit():
        return None
    proc = ida_ida.inf_get_procname().lower()
    if proc in ("metapc", "pc"):
        return "x86_64"
    if proc.startswith("arm"):
        return "aarch64"
    return None


def read(ea, size):
    """Bytes at ea, clipped to the end of its segment; None outside any segment."""
    seg = ida_segment.getseg(ea)
    if seg is None:
        return None
    size = min(size, seg.end_ea - ea)
    if size <= 0 or not ida_bytes.is_loaded(ea):
        return None
    return ida_bytes.get_bytes(ea, size)


def in_text(ea):
    seg = ida_segment.getseg(ea)
    return seg is not None and bool(seg.perm & ida_segment.SEGPERM_EXEC or seg.type == ida_segment.SEG_CODE)


_FILE_SYMBOLS = {}


def file_symbols():
    """The input file's own ELF symbol table, read once per path ({} if it cannot be read).

    IDA keeps one name per address, and __stop_ names usually share theirs with another symbol
    (__stop___bug_table with __start_orc_header, for example), so the database may not have them."""
    path = ida_nalt.get_input_file_path() or ""
    try:
        st = os.stat(path)
        key = (path, st.st_size, st.st_mtime)
    except OSError:
        return {}
    if key not in _FILE_SYMBOLS:
        _FILE_SYMBOLS.clear()  # one input file at a time; a new kernel at the same path gets read again
        try:
            with open(path, "rb") as fh:
                head = fh.read(18)
            if head[:4] == b"\x7fELF" and head[16:18] == b"\x01\x00":  # ET_REL: a module never has __start_ names
                _FILE_SYMBOLS[key] = {}
            else:
                from .cli import Elf
                _FILE_SYMBOLS[key] = Elf(path).symbols
        except Exception:  # noqa: BLE001  (missing, moved or not an ELF: just no fallback)
            _FILE_SYMBOLS[key] = {}
    return _FILE_SYMBOLS[key]


_MODULE = {}


def module_sites():
    """For a kernel module (ET_REL) still on disk at the input path: one (offset of the site in its section, imported
    name or None, key label or None) per jump-table entry as the command line decodes it; else None. Only these
    tuples are kept (not the parsed file), once per path, size and mtime."""
    path = ida_nalt.get_input_file_path() or ""
    try:
        st = os.stat(path)
        key = (path, st.st_size, st.st_mtime)
    except OSError:
        return None
    if key not in _MODULE:
        _MODULE.clear()
        _MODULE[key] = None
        try:
            with open(path, "rb") as fh:
                head = fh.read(18)
            if head[:4] == b"\x7fELF" and head[16:18] == b"\x01\x00":
                from .cli import Elf, load
                elf = Elf(path)
                secs = sorted(elf.sections.values())
                starts = [x[0] for x in secs]

                def place(ea):
                    i = bisect.bisect_right(starts, ea) - 1
                    return ea - secs[i][0] if i >= 0 and ea < secs[i][1] else None
                sites = []
                for c in load(elf).get("jump", []):
                    ext = elf.extern_of(c.key)
                    sites.append((place(c.code), ext[0] if ext else None, elf.key_name(c.key) if ext else None))
                _MODULE[key] = sites
        except Exception:  # noqa: BLE001  (unreadable or a layout the command line rejects: no module labels)
            _MODULE[key] = None
    return _MODULE[key]


def _outside_or_extern(ea):
    seg = ida_segment.getseg(ea)
    return seg is None or seg.type == ida_segment.SEG_XTRN


def module_key_labels(jumps):
    """{jump entry address: (key label, imported name)} for a kernel module's static keys that live in an imported
    symbol at an offset IDA cannot name. IDA's ELF loader puts the imports in an extern segment, probably one after
    another, so after relocation "import + offset" (a tracepoint's key is __tracepoint_X + 8; arrays like
    nf_hooks_needed) can land on ANOTHER import and get its name. The command line gives each import a 64 KB slot and
    names these keys exactly; its label is used for every site whose key IDA put in an extern segment or outside all
    segments, but only when both decodes have the same entries: same count and each site at the same offset in its
    section."""
    if not jumps:
        return {}
    sites = module_sites()
    if sites is None or len(sites) != len(jumps):
        return {}
    out = {}
    for j, (where, name, label) in zip(jumps, sites):
        seg = ida_segment.getseg(j.code)
        if seg is None or where is None or j.code - seg.start_ea != where:
            return {}  # the two decodes do not line up: keep IDA's own names
        if name is not None and _outside_or_extern(j.key):
            out[j.entry] = (label, name)
    return out


SITE_KEY = {}  # jump entry address -> (label, imported name), from the last scan() of a module


def site_key_name(j, cache=None):
    """The static key's name for this site: the module label when there is one, else IDA's names (cached by key)."""
    hit = SITE_KEY.get(j.entry)
    if hit:
        return hit[0]
    if cache is None:
        return key_name(j.key)
    if j.key not in cache:
        cache[j.key] = key_name(j.key)
    return cache[j.key]


ANCHORS = ("_text", "_stext", "stext", "startup_64", "_etext", "_sdata", "linux_banner")


def _shift(fs):
    """database address - file address, from the first anchor symbol both have (0 if none: not rebased)."""
    for n in ANCHORS:
        if n in fs:
            ea = ida_name.get_name_ea(BADADDR, n)
            if ea != BADADDR:
                return ea - fs[n]
    return 0


def table_range(kind):
    """[start, stop) of a table from its __start_/__stop_ names in the database, else from the input file's
    symbol table (shifted like the database if __start_ is known there), else from a segment of the same name."""
    s, e = core.TABLES[kind]
    a, b = ida_name.get_name_ea(BADADDR, s), ida_name.get_name_ea(BADADDR, e)
    if a != BADADDR and b != BADADDR and b > a:
        return a, b, "names"
    fs = file_symbols()
    if s in fs and e in fs and fs[e] > fs[s]:
        # the database may have been rebased: measure the shift on a name it still has
        delta = a - fs[s] if a != BADADDR else b - fs[e] if b != BADADDR else _shift(fs)
        start, stop = fs[s] + delta, fs[e] + delta
        if ida_segment.getseg(start) is not None:
            return start, stop, "input file symbols"
    seg = ida_segment.get_segm_by_name(s[len("__start_"):])
    if seg is not None:
        return seg.start_ea, seg.end_ea, "segment"
    return None


def scan():
    """Decode every table found. Returns dict: bug/jump/ex lists, layouts, missing kinds, where each was found."""
    out = {"missing": [], "found_by": {}, "errors": {}, "bug": [], "jump": [], "ex": []}
    for kind in core.TABLES:
        r = table_range(kind)
        if r is None:
            out["missing"].append(kind)
            continue
        start, stop, how = r
        out["found_by"][kind] = how
        try:  # one table in a layout kflow does not know must not hide the others
            if kind == "bug":
                out["bug_layout"], out["bug"] = core.decode_bug_table(read, start, stop, in_text=in_text)
            elif kind == "jump":
                out["jump"] = core.decode_jump_table(read, start, stop, in_text=in_text)
            else:
                out["ex_layout"], out["ex"] = core.decode_ex_table(read, start, stop, in_text=in_text)
        except ValueError as error:
            out["errors"][kind] = str(error)
    SITE_KEY.clear()
    try:
        SITE_KEY.update(module_key_labels(out["jump"]))
    except Exception:  # noqa: BLE001  (labels are a refinement: never let them break a scan)
        SITE_KEY.clear()
    return out


def not_decoded(t):
    """'; not decoded: jump (reason)' for the tables whose layout kflow could not read, else ''."""
    return "".join("; not decoded: %s (%s)" % (k, e) for k, e in t.get("errors", {}).items())


def real_name(ea):
    """The name at ea, but never one of IDA's placeholder names (unk_..., byte_..., loc_...): IDA puts those on
    referenced addresses, keys included once Annotate adds its key references, and get_name() returns them."""
    return ida_name.get_ea_name(ea, ida_name.GN_NOT_DUMMY)


def name_or_hex(ea):
    return real_name(ea) or "0x%X" % ea


def bug_comment(b):
    where = " at %s" % b.where() if b.file else ""
    if b.warn and b.args:
        return "%s: WARN%s (WARN with a message, Linux 6.19+: reported through this call, then continues)" % (TAG, where)
    if b.warn:
        return "%s: WARN%s (the kernel reports and continues after this trap)" % (TAG, where)
    return "%s: BUG%s (does not return)" % (TAG, where)


def nearest_name(ea):
    """(name, address) of the closest name at or before ea from IDA's name list, or None. get_nlist_idx returns "the
    closest match", which may be the next name after ea, so its neighbour before it is checked too."""
    size = ida_name.get_nlist_size()
    idx = ida_name.get_nlist_idx(ea)
    best = None
    for i in (idx, idx - 1):
        if 0 <= i < size:
            a = ida_name.get_nlist_ea(i)
            if a <= ea and (best is None or a > best[1]):
                best = (ida_name.get_nlist_name(i), a)
    return best


def key_name(ea):
    return core.key_label(real_name, ea, read, nearest_name) or "0x%X" % ea


def jump_when(j):
    # the kernel makes the site a jump when (key enabled) XOR (branch bit): jump_label_type() in kernel/jump_label.c
    return "jumps to 0x%X when the key is %s" % (j.target, "off" if j.branch else "on")


def jump_comment(j):
    kind = "static_branch_likely" if j.branch else "static_branch_unlikely"
    return "%s: static key %s (%s): runtime-patched NOP/branch; %s" % (TAG, site_key_name(j), kind, jump_when(j))


def jump_pseudo_text(j, name=None, before=False):
    """The pseudocode version of jump_comment: key, likely/unlikely, when the site jumps. before: the site has no
    statement of its own, so the text sits on the line of the next address that has one."""
    at = " at 0x%X, just before this line" % j.code if before else ""
    return "%s: static key %s (%s)%s: %s" % (TAG, name or site_key_name(j), "likely" if j.branch else "unlikely", at,
                                             jump_when(j))


def ex_comment(x, arch):
    if x.handler is not None:
        t = " (handler %s)" % name_or_hex(x.handler)
    else:
        t = "" if x.data is None else " (%s)" % x.type_name(arch or "x86_64")
    return "%s: may fault -> fixup at 0x%X%s" % (TAG, x.fixup, t)


def _set(ea, text, res):
    old = ida_bytes.get_cmt(ea, False)
    if old and not old.startswith(TAG + ": "):
        res["kept_user_comments"] += 1
        return
    ida_bytes.set_cmt(ea, text, False)
    res["comments"] += 1


def _created(name=NODE):
    return ida_netnode.netnode(name, 0, True)


def branches_to(src, dst, arch):
    """True if the instruction at src is a direct jmp/b to dst: IDA makes that reference itself (perhaps only once
    auto-analysis reaches it), so kflow must not add or record one there."""
    b = read(src, 5)
    if not b:
        return False
    if arch == "x86_64":
        if b[0] == 0xE9 and len(b) >= 5:
            return src + 5 + int.from_bytes(b[1:5], "little", signed=True) == dst
        if b[0] == 0xEB and len(b) >= 2:
            return src + 2 + int.from_bytes(b[1:2], "little", signed=True) == dst
    elif arch == "aarch64" and len(b) >= 4:
        w = int.from_bytes(b[:4], "little")
        if w >> 26 == 0b000101:
            imm = w & 0x3FFFFFF
            imm -= (1 << 26) if imm & (1 << 25) else 0
            return src + 4 * imm == dst
    return False


def _add(src, dst, node, arch=None):
    """Add a user jump reference unless one (IDA's own, e.g. an enabled jmp, or the user's) already exists or the
    instruction itself branches there. Every reference added is recorded in the database, so Remove deletes only these."""
    if not in_text(dst) or dst in code_refs_from(src) or branches_to(src, dst, arch):
        return 0
    if dst == ida_bytes.get_item_end(src):  # the fixup/target is the next instruction: ordinary flow already goes there
        return 0
    if not ida_xref.add_cref(src, dst, ida_xref.fl_JN | ida_xref.XREF_USER):
        return 0
    base = ida_nalt.get_imagebase()
    node.altset((src - base) & MASK, (dst - base) & MASK)
    return 1


def data_refs_from(ea):
    """{target: is_user} for the data references from ea."""
    out = {}
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(ea, ida_xref.XREF_DATA)
    while ok:
        out[xb.to] = bool(xb.user)
        ok = xb.next_from()
    return out


def _add_key_ref(site, key, node):
    """A user data reference static-key site -> key, so the key's cross references list its sites; recorded like
    the jump references, so Remove deletes only these."""
    if not ida_bytes.is_mapped(key) or key in data_refs_from(site):
        return 0
    if not ida_xref.add_dref(site, key, ida_xref.dr_O | ida_xref.XREF_USER):
        return 0
    base = ida_nalt.get_imagebase()
    node.altset((site - base) & MASK, (key - base) & MASK)
    return 1


def _drop_stale_key_refs(wanted, node):
    """Delete the key reference an earlier Annotate recorded at a site when this Annotate points the site elsewhere
    (a module annotated while its .ko was on disk and again after it moved, or by an older kflow): its record is
    about to be overwritten, so Remove could no longer find it. Only a reference that is still a user reference."""
    base = ida_nalt.get_imagebase()
    dropped = 0
    for site, keys in wanted.items():
        prev = node.altval((site - base) & MASK)
        if not prev:
            continue
        prev = (prev + base) & MASK
        if prev not in keys and data_refs_from(site).get(prev):
            ida_xref.del_dref(site, prev)
            dropped += 1
    return dropped


def key_ref_target(j):
    """Where the site -> key reference points: the key, or for a module label the imported symbol itself (IDA's
    address for "import + offset" may be another import); BADADDR (no reference) if IDA has no such name."""
    hit = SITE_KEY.get(j.entry)
    if not hit:
        return j.key
    return ida_name.get_name_ea(BADADDR, hit[1])


def annotate(t, arch=None):
    """Comment every site; add jump references site -> static-key target and faulting insn -> fixup, and data
    references site -> key."""
    res = {"comments": 0, "xrefs": 0, "key_refs": 0, "kept_user_comments": 0}
    node = _created()
    knode = _created(KEY_NODE)
    arch = arch or current_arch()
    for b in t["bug"]:
        if in_text(b.addr):
            _set(b.addr, bug_comment(b), res)
    wanted = {}  # site -> the key references this Annotate wants there (a site can carry several entries)
    for j in t["jump"]:
        if in_text(j.code):
            wanted.setdefault(j.code, set()).add(key_ref_target(j))
    res["stale_key_refs"] = _drop_stale_key_refs(wanted, knode)
    for j in t["jump"]:
        if in_text(j.code):
            _set(j.code, jump_comment(j), res)
            res["xrefs"] += _add(j.code, j.target, node, arch)
            res["key_refs"] += _add_key_ref(j.code, key_ref_target(j), knode)
    for x in t["ex"]:
        if in_text(x.insn):
            _set(x.insn, ex_comment(x, arch), res)
            res["xrefs"] += _add(x.insn, x.fixup, node, arch)
    return res


def annotate_text(res):
    """One readable line for the counts annotate() returns (menu action and headless runner)."""
    text = ("comments: %d, jump references added: %d, static-key site -> key references: %d, user comments kept: %d"
            % (res["comments"], res["xrefs"], res["key_refs"], res["kept_user_comments"]))
    if res.get("stale_key_refs"):
        text += ", outdated key references removed: %d" % res["stale_key_refs"]
    return text


def annotated():
    """True when the database carries kflow's annotations: Annotate creates the record of added references (even
    if it adds none), Remove deletes it."""
    return ida_netnode.netnode(NODE, 0, False).index() != ida_netnode.BADNODE


def layout():
    """Segment bounds; they change when the database is rebased (Edit > Segments > Rebase program)."""
    segs = (ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty()))
    return tuple((s.start_ea, s.end_ea) for s in segs if s is not None)


def code_refs_from(ea):
    """{target: is_user} for the jump/call references from ea (ordinary flow excluded)."""
    out = {}
    xb = ida_xref.xrefblk_t()
    ok = xb.first_from(ea, ida_xref.XREF_FAR)
    while ok:
        if xb.iscode:
            out[xb.to] = bool(xb.user)
        ok = xb.next_from()
    return out


def remove_annotations(t, res=None):
    """Remove our comments and the references kflow added (as recorded by annotate; references that existed
    before, IDA's own or the user's, stay). Returns how many jump references were removed; if res is a dict,
    res["key_refs"] is set to how many site -> key data references were removed."""
    for ea in [b.addr for b in t["bug"]] + [j.code for j in t["jump"]] + [x.insn for x in t["ex"]]:
        old = ida_bytes.get_cmt(ea, False)
        if old and old.startswith(TAG + ": "):
            ida_bytes.set_cmt(ea, "", False)
    base = ida_nalt.get_imagebase()  # offsets survive a rebase of the database
    key_refs = 0
    knode = ida_netnode.netnode(KEY_NODE, 0, False)
    if knode.index() != ida_netnode.BADNODE:
        off = knode.altfirst()
        while off != ida_netnode.BADNODE:
            f, to = (off + base) & MASK, (knode.altval(off) + base) & MASK
            if data_refs_from(f).get(to):  # still there and still a user reference
                ida_xref.del_dref(f, to)
                key_refs += 1
            off = knode.altnext(off)
        knode.kill()
    if res is not None:
        res["key_refs"] = key_refs
    node = ida_netnode.netnode(NODE, 0, False)
    if node.index() == ida_netnode.BADNODE:  # never annotated
        return 0
    removed = 0
    off = node.altfirst()
    while off != ida_netnode.BADNODE:
        f, to = (off + base) & MASK, (node.altval(off) + base) & MASK
        if code_refs_from(f).get(to):  # still there and still a user reference
            ida_xref.del_cref(f, to, False)
            removed += 1
        off = node.altnext(off)
    node.kill()
    return removed
