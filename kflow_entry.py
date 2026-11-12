"""kflow: Linux kernel BUG/WARN sites, static-key branches and exception fixups in IDA.

Edit > Plugins > kflow actions:
  * Annotate kernel sites: reads the kernel's own __bug_table, __jump_table and __ex_table, comments every
    site (BUG/WARN with source file:line, static key + branch target, faulting instruction -> fixup) and adds
    jump references to static-key targets and fixups where IDA has none.
  * List BUG/WARN sites: a list with function and source file:line; Enter jumps to the site.
  * Remove annotations.
With the Hex-Rays decompiler, annotated sites also get a comment in pseudocode (display only, nothing saved).
"""
import bisect
import os
import sys
import traceback

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from kflow import __version__, idalayer  # noqa: E402

ISSUES_URL = "https://github.com/nightshift-labs-ai/kflow/issues"
# pseudo: the sites by address for the pseudocode hook (built by Annotate, rebuilt after a rebase); hx: the hook.
STATE = {"tables": None, "pseudo": None, "hx": None, "hx_error": False}
NOP_WINDOW = 16  # bytes: how far a static-key site without a statement of its own may be from the next one that has one


def report(text):
    ida_kernwin.msg("[kflow] %s\n" % text)


def guarded(activate):
    def wrapper(self, ctx):
        try:
            return activate(self, ctx)
        except Exception:  # noqa: BLE001  (last line of defence inside IDA)
            ida_kernwin.msg("[kflow] unexpected error:\n%s\n" % traceback.format_exc())
            ida_kernwin.warning("kflow: unexpected error, details are in the Output window.\nPlease report it: %s" % ISSUES_URL)
            return 0
    return wrapper


def scan_or_warn():
    if idalayer.current_arch() is None:
        ida_kernwin.warning("kflow: this database is not a 64-bit x86_64 or aarch64 kernel.")
        return None
    ida_kernwin.show_wait_box("HIDECANCEL\nkflow: reading the kernel's site tables")
    try:
        t = idalayer.scan()
    except ValueError as e:
        t = None
        problem = str(e)
    finally:
        ida_kernwin.hide_wait_box()
    if t is None:
        ida_kernwin.warning("kflow: %s" % problem)
        return None
    if len(t["missing"]) == 3:
        ida_kernwin.warning("kflow: no __start___bug_table / __start___jump_table / __start___ex_table names and no "
                            "segments of those names: load a vmlinux with symbols or a kernel ELF with kallsyms names (a raw Image or "
                            "vmlinuz loaded as a binary file has neither: turn it into an ELF with vmlinux-to-elf "
                            "first, see the README).")
        return None
    STATE["tables"] = t
    report("found %d BUG/WARN sites (%s), %d static-key sites, %d exception-table sites; not found: %s%s"
           % (len(t["bug"]), t.get("bug_layout") or "-", len(t["jump"]), len(t["ex"]), ", ".join(t["missing"]) or "none",
              idalayer.not_decoded(t)))
    return t


def pseudo_index(t, arch, layout):
    """The decoded sites by address, for the pseudocode hook; texts are made when a function is printed."""
    sites = {}
    for kind, items, ea in (("bug", t["bug"], "addr"), ("jump", t["jump"], "code"), ("ex", t["ex"], "insn")):
        for site in items:
            sites.setdefault(getattr(site, ea), []).append((kind, site))
    return {"layout": layout, "arch": arch, "sites": sites, "eas": sorted(sites), "names": {}}


def pseudo_map():
    """The map for the hook, or None if the database has no kflow annotations (never annotated, or removed). Built
    again from the kernel's tables when the segments moved since it was made (rebase), so no stale address shows;
    also on the first function printed in a database annotated in an earlier session."""
    if not idalayer.annotated():
        STATE["pseudo"] = None
        return None
    now = idalayer.layout()
    p = STATE["pseudo"]
    if p is not None and p["layout"] == now:
        return p
    arch = idalayer.current_arch()
    if arch is None:
        STATE["pseudo"] = None
        return None
    report("reading the site tables again for pseudocode comments (%s)"
           % ("segments changed since they were read: rebase?" if p is not None else "database annotated earlier"))
    STATE["pseudo"] = pseudo_index({"bug": [], "jump": [], "ex": []}, arch, now)  # a failing scan is not retried per function
    STATE["pseudo"] = pseudo_index(idalayer.scan(), arch, now)
    return STATE["pseudo"]


def pseudo_text(p, kind, site, before=False):
    if kind == "bug":
        return idalayer.bug_comment(site)
    if kind == "ex":
        return idalayer.ex_comment(site, p["arch"])
    return idalayer.jump_pseudo_text(site, idalayer.site_key_name(site, p["names"]), before)


def pseudocode_lines(cfunc):
    """{line index: [comment, ...]} for the kflow sites in this decompiled function. A site whose address has a
    statement gets its comment on that statement's line. A static-key site without one (a NOP usually leaves no
    statement) gets it on the line of the next address that has one, if that is at most NOP_WINDOW bytes on, no
    other kflow site lies in between and the site is in this function; otherwise it gets none."""
    p = pseudo_map()
    if not p or not p["eas"]:
        return {}
    eamap = cfunc.get_eamap()
    keys = sorted(eamap)
    eas, sites = p["eas"], p["sites"]
    at = {}  # address with statements -> texts
    prev = None
    for ea in keys:
        for kind, site in sites.get(ea, ()):
            at.setdefault(ea, []).append(pseudo_text(p, kind, site))
        i = bisect.bisect_left(eas, ea) - 1  # the closest site before ea: no other site between them
        if i >= 0 and ea - eas[i] <= NOP_WINDOW and (prev is None or eas[i] > prev):
            near = [s for kind, s in sites[eas[i]] if kind == "jump"]
            f = ida_funcs.get_func(eas[i]) if near else None
            if f is not None and f.start_ea == cfunc.entry_ea:
                at.setdefault(ea, []).extend(pseudo_text(p, "jump", s, before=True) for s in near)
        prev = ea
    lines = {}
    for ea, texts in at.items():
        for insn in eamap[ea]:
            coords = cfunc.find_item_coords(insn)  # (x, y), or (None, None) if the item is not in the text
            if isinstance(coords, (tuple, list)) and len(coords) == 2 and isinstance(coords[1], int):
                have = lines.setdefault(coords[1], [])
                have.extend(text for text in texts if text not in have)
    return lines


def add_pseudocode_comments(cfunc):
    """Display-only text appended to the printed lines; nothing is stored in the database."""
    lines = pseudocode_lines(cfunc)
    if not lines:
        return 0
    sv = cfunc.get_pseudocode()
    done = 0
    for y, texts in sorted(lines.items()):
        if 0 <= y < len(sv):
            sv[y].line += ida_lines.COLSTR("  // " + "; ".join(texts), ida_lines.SCOLOR_AUTOCMT)
            done += 1
    return done


def hook_pseudocode():
    """Install the decompiler hook once, if Hex-Rays is there. Without it kflow works as before."""
    if STATE["hx"] is not None:
        return True
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return False

        class PseudocodeHooks(ida_hexrays.Hexrays_Hooks):
            def func_printed(self, cfunc):
                try:
                    add_pseudocode_comments(cfunc)
                except Exception:  # noqa: BLE001  a hook must never break the decompiler
                    try:
                        if not STATE["hx_error"]:
                            STATE["hx_error"] = True
                            report("pseudocode comment failed (shown once):\n%s" % traceback.format_exc())
                    except Exception:  # noqa: BLE001
                        pass
                return 0

        hooks = PseudocodeHooks()
        if hooks.hook():
            STATE["hx"] = hooks
    except Exception:  # noqa: BLE001  no decompiler, or an unexpected one: carry on without the hook
        STATE["hx"] = None
    return STATE["hx"] is not None


def unhook_pseudocode():
    hooks, STATE["hx"] = STATE["hx"], None
    STATE["pseudo"] = None
    STATE["hx_error"] = False  # a later session reports its own first error
    if hooks is not None:
        try:
            hooks.unhook()
        except Exception:  # noqa: BLE001
            traceback.print_exc()


def flush_pseudocode():
    """Drop cached decompilations so the next decompile prints (or stops printing) our comments."""
    if STATE["hx"] is None:
        return
    try:
        import ida_hexrays
        ida_hexrays.clear_cached_cfuncs()
    except Exception:  # noqa: BLE001
        pass


class AnnotateAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        t = scan_or_warn()
        if t is None:
            return 0
        ida_kernwin.show_wait_box("HIDECANCEL\nkflow: writing comments and references")
        try:
            res = idalayer.annotate(t, idalayer.current_arch())
        finally:
            ida_kernwin.hide_wait_box()
        report(idalayer.annotate_text(res))
        if hook_pseudocode():
            STATE["pseudo"] = pseudo_index(t, idalayer.current_arch(), idalayer.layout())
            flush_pseudocode()
            report("pseudocode comments on: functions decompiled from now on show the sites (display only)")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


BUG_COLUMNS = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Kind", 6], ["Function", 30], ["Source", 40]]
KEY_COLUMNS = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Key", 34], ["Kind", 8], ["Now", 7],
               ["Target", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Function", 30]]


class SitesChooser(ida_kernwin.Choose):
    def __init__(self, rows, title="kflow: BUG/WARN sites", columns=None):
        ida_kernwin.Choose.__init__(self, title, columns or BUG_COLUMNS)
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.rows[n][1:]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.rows[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )


class ListAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        t = scan_or_warn()  # rescan: cheap, and right after a rebase or a database switch
        if t is None:
            return 0
        rows = [(b.addr, "0x%X" % b.addr, "WARN" if b.warn else "BUG",
                 ida_funcs.get_func_name(b.addr) or "", b.where() or "") for b in t["bug"]]
        SitesChooser(rows).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def key_site_rows(t):
    """One row per static-key site: key, likely/unlikely, whether the bytes here are a jump to the target now
    (the site jumps when the key's state XOR the entry's branch bit is set), target, function."""
    arch = idalayer.current_arch()
    names = {}
    rows = []
    for j in t["jump"]:
        name = idalayer.site_key_name(j, names)
        now = "jump" if idalayer.branches_to(j.code, j.target, arch) else "no jump"
        rows.append((j.code, "0x%X" % j.code, name, "likely" if j.branch else "unlikely", now,
                     "0x%X" % j.target, ida_funcs.get_func_name(j.code) or ""))
    return rows


class KeySitesAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        t = scan_or_warn()
        if t is None:
            return 0
        if not t["jump"]:
            ida_kernwin.warning("kflow: no static-key sites in this database (%s)." % (
                "no __jump_table found" if "jump" in t["missing"] else
                "the __jump_table could not be decoded: %s" % t["errors"]["jump"] if "jump" in t.get("errors", {}) else
                "the table is empty"))
            return 0
        SitesChooser(key_site_rows(t), "kflow: static-key sites", KEY_COLUMNS).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class RemoveAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        t = scan_or_warn()  # rescan: cheap, and right after a rebase or a database switch
        if t is None:
            return 0
        ida_kernwin.show_wait_box("HIDECANCEL\nkflow: removing comments and references")
        try:
            res = {}
            removed = idalayer.remove_annotations(t, res)
        finally:
            ida_kernwin.hide_wait_box()
        report("references removed: %d jump references, %d static-key site -> key references" % (removed, res.get("key_refs", 0)))
        STATE["pseudo"] = None
        flush_pseudocode()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("kflow:annotate", "kflow: Annotate kernel sites", AnnotateAction),
    ("kflow:list", "kflow: List BUG/WARN sites", ListAction),
    ("kflow:keys", "kflow: List static-key sites", KeySitesAction),
    ("kflow:remove", "kflow: Remove annotations", RemoveAction),
]


class KflowPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Linux kernel BUG/WARN sites, static-key branches and exception fixups"
    help = comment
    wanted_name = "kflow"
    wanted_hotkey = ""

    def init(self):
        for name, label, handler in ACTIONS:
            ida_kernwin.register_action(ida_kernwin.action_desc_t(name, label, handler()))
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", name, ida_kernwin.SETMENU_APP)
        hook_pseudocode()
        report("%s loaded" % __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.process_ui_action("kflow:annotate")

    def term(self):
        unhook_pseudocode()
        for name, _, _ in ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return KflowPlugin()
