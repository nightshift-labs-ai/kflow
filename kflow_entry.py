"""kflow: Linux kernel BUG/WARN sites, static-key branches and exception fixups in IDA.

Edit > Plugins > kflow actions:
  * Annotate kernel sites: reads the kernel's own __bug_table, __jump_table and __ex_table, comments every
    site (BUG/WARN with source file:line, static key + branch target, faulting instruction -> fixup) and adds
    jump references to static-key targets and fixups where IDA has none.
  * List BUG/WARN sites: a list with function and source file:line; Enter jumps to the site.
  * Remove annotations.
"""
import os
import sys
import traceback

import ida_funcs
import ida_idaapi
import ida_kernwin

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from kflow import __version__, idalayer  # noqa: E402

ISSUES_URL = "https://github.com/nightshift-labs-ai/kflow/issues"
STATE = {"tables": None}


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
    ida_kernwin.show_wait_box("kflow: reading the kernel's site tables")
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
                            "segments of those names: load a vmlinux with symbols or a kernel ELF with kallsyms names.")
        return None
    STATE["tables"] = t
    report("found %d BUG/WARN sites (%s), %d static-key sites, %d exception-table sites; not found: %s"
           % (len(t["bug"]), t.get("bug_layout") or "-", len(t["jump"]), len(t["ex"]), ", ".join(t["missing"]) or "none"))
    return t


class AnnotateAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        t = scan_or_warn()
        if t is None:
            return 0
        ida_kernwin.show_wait_box("kflow: writing comments and references")
        try:
            res = idalayer.annotate(t, idalayer.current_arch())
        finally:
            ida_kernwin.hide_wait_box()
        report("comments: %d, references added: %d, user comments kept: %d"
               % (res["comments"], res["xrefs"], res["kept_user_comments"]))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class SitesChooser(ida_kernwin.Choose):
    def __init__(self, rows):
        ida_kernwin.Choose.__init__(self, "kflow: BUG/WARN sites",
                                    [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Kind", 6],
                                     ["Function", 30], ["Source", 40]])
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


class RemoveAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        t = scan_or_warn()  # rescan: cheap, and right after a rebase or a database switch
        if t is None:
            return 0
        ida_kernwin.show_wait_box("kflow: removing comments and references")
        try:
            removed = idalayer.remove_annotations(t)
        finally:
            ida_kernwin.hide_wait_box()
        report("references removed: %d" % removed)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("kflow:annotate", "kflow: Annotate kernel sites", AnnotateAction),
    ("kflow:list", "kflow: List BUG/WARN sites", ListAction),
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
        report("%s loaded" % __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.process_ui_action("kflow:annotate")

    def term(self):
        for name, _, _ in ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return KflowPlugin()
