"""IDA side of kflow: find the kernel's site tables in the database, comment the sites, add references."""
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
    if path not in _FILE_SYMBOLS:
        try:
            from .cli import Elf
            _FILE_SYMBOLS[path] = Elf(path).symbols
        except Exception:  # noqa: BLE001  (missing, moved or not an ELF: just no fallback)
            _FILE_SYMBOLS[path] = {}
    return _FILE_SYMBOLS[path]


def table_range(kind):
    """[start, stop) of a table from its __start_/__stop_ names in the database, else from the input file's
    symbol table (shifted like the database if __start_ is known there), else from a segment of the same name."""
    s, e = core.TABLES[kind]
    a, b = ida_name.get_name_ea(BADADDR, s), ida_name.get_name_ea(BADADDR, e)
    if a != BADADDR and b != BADADDR and b > a:
        return a, b, "names"
    fs = file_symbols()
    if s in fs and e in fs and fs[e] > fs[s]:
        delta = a - fs[s] if a != BADADDR else 0  # the database may have been rebased
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
    return out


def not_decoded(t):
    """'; not decoded: jump (reason)' for the tables whose layout kflow could not read, else ''."""
    return "".join("; not decoded: %s (%s)" % (k, e) for k, e in t.get("errors", {}).items())


def name_or_hex(ea):
    return ida_name.get_name(ea) or "0x%X" % ea


def bug_comment(b):
    where = " at %s" % b.where() if b.file else ""
    if b.warn:
        return "%s: WARN%s (the kernel reports and continues after this trap)" % (TAG, where)
    return "%s: BUG%s (does not return)" % (TAG, where)


def key_name(ea):
    return core.key_label(ida_name.get_name, ea, read) or "0x%X" % ea


def jump_comment(j):
    kind = "static_branch_likely" if j.branch else "static_branch_unlikely"
    return ("%s: static key %s (%s): runtime-patched NOP/branch; branch target 0x%X"
            % (TAG, key_name(j.key), kind, j.target))


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


def _created():
    return ida_netnode.netnode(NODE, 0, True)


def _add(src, dst, node):
    """Add a user jump reference unless one (IDA's own, e.g. an enabled jmp, or the user's) already exists.
    Every reference added is recorded in the database, so Remove deletes only these."""
    if not in_text(dst) or dst in code_refs_from(src):
        return 0
    if not ida_xref.add_cref(src, dst, ida_xref.fl_JN | ida_xref.XREF_USER):
        return 0
    base = ida_nalt.get_imagebase()
    node.altset((src - base) & MASK, (dst - base) & MASK)
    return 1


def annotate(t, arch=None):
    """Comment every site; add jump references site -> static-key target and faulting insn -> fixup."""
    res = {"comments": 0, "xrefs": 0, "kept_user_comments": 0}
    node = _created()
    for b in t["bug"]:
        if in_text(b.addr):
            _set(b.addr, bug_comment(b), res)
    for j in t["jump"]:
        if in_text(j.code):
            _set(j.code, jump_comment(j), res)
            res["xrefs"] += _add(j.code, j.target, node)
    for x in t["ex"]:
        if in_text(x.insn):
            _set(x.insn, ex_comment(x, arch), res)
            res["xrefs"] += _add(x.insn, x.fixup, node)
    return res


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


def remove_annotations(t):
    """Remove our comments and the references kflow added (as recorded by annotate; references that existed
    before, IDA's own or the user's, stay). Returns how many references were removed."""
    for ea in [b.addr for b in t["bug"]] + [j.code for j in t["jump"]] + [x.insn for x in t["ex"]]:
        old = ida_bytes.get_cmt(ea, False)
        if old and old.startswith(TAG + ": "):
            ida_bytes.set_cmt(ea, "", False)
    node = ida_netnode.netnode(NODE, 0, False)
    if node.index() == ida_netnode.BADNODE:  # never annotated
        return 0
    base = ida_nalt.get_imagebase()  # offsets survive a rebase of the database
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
