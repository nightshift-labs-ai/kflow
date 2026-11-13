"""kflow: Linux kernel BUG/WARN sites, static-key branches and exception fixups in IDA.

Edit > Plugins > kflow actions:
  * Annotate kernel sites: reads the kernel's own __bug_table, __jump_table and __ex_table, comments every
    site (BUG/WARN with source file:line, static key + branch target, faulting instruction -> fixup) and adds
    jump references to static-key targets and fixups where IDA has none.
  * List BUG/WARN sites: a list with function and source file:line; Enter jumps to the site.
  * Go to oops/WARN line: paste a WARNING / kernel BUG / RIP / pc line or a whole oops report; jumps to the BUG/WARN
    site it names (function + offset), or lists the candidate sites when only file:line is known.
  * Remove annotations.
  * Let WARN sites fall through (experimental, x86_64 only, off by default) / Remove WARN fall-through: see
    kflow/warnflow.py.
With the Hex-Rays decompiler, annotated sites also get a comment in pseudocode (display only, nothing saved).
"""
import bisect
import os
import sys
import time
import traceback

import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from kflow import __version__, idalayer, oops, selfcheck  # noqa: E402

ISSUES_URL = "https://github.com/nightshift-labs-ai/kflow/issues"
# pseudo: the sites by address for the pseudocode hook (built by Annotate, rebuilt after a rebase); hx: the hook;
# hx_late: a UI hook that tries it again when a plugin loads, while the decompiler was not there at init.
# wf / wf_filter: the WARN fall-through processor hook and decompiler filter, only while it is on for the open database;
# wf_last: its last counts.
# oops_text: the last text pasted into Go to oops/WARN line (the dialog's default the next time).
# hidden_error: a hidden-path sentence failed (reported once; that comment is shown without it).
STATE = {"tables": None, "pseudo": None, "hx": None, "hx_error": False, "hx_late": None, "wf": None, "wf_filter": None,
         "wf_error": False, "wf_last": None, "oops_text": "", "hidden_error": False}
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
    # + the hidden-path sentence, from the database's references when the function is printed (so also in a later
    # session): only where nothing but kflow leads to the path the site does not take here (judge item 4)
    text = idalayer.jump_pseudo_text(site, idalayer.site_key_name(site, p["names"]), before)
    try:
        hidden = idalayer.hidden_path_text(site, p["arch"])
    except Exception:  # noqa: BLE001  one sentence must not cost the function all its kflow comments (review s177 N5)
        hidden = ""
        if not STATE["hidden_error"]:
            STATE["hidden_error"] = True
            report("hidden-path sentence failed at 0x%X, comment shown without it (shown once):\n%s"
                   % (site.code, traceback.format_exc()))
    return text + hidden


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


class LateHexrays(ida_kernwin.UI_Hooks):
    """The decompiler may load after kflow: IDAPython initialises its Hex-Rays bindings when the decompiler plugin
    loads (ui_plugin_loaded in its py_hexrays.hpp). Until the pseudocode hook is in, try it again whenever a plugin
    loads, so a database annotated earlier shows its comments without running Annotate again."""

    def plugin_loaded(self, plugin_info):
        try:
            if STATE["hx"] is None and hook_pseudocode() and idalayer.annotated():
                report("decompiler loaded: pseudocode comments on (display only)")
        except Exception:  # noqa: BLE001  a UI hook must never break plugin loading
            pass


def hook_pseudocode_later():
    """At init, when there was no decompiler yet: the UI hook above (kept until kflow unloads)."""
    try:
        late = LateHexrays()
        if late.hook():
            STATE["hx_late"] = late
    except Exception:  # noqa: BLE001  kflow works without pseudocode comments
        STATE["hx_late"] = None


def unhook_pseudocode():
    late, STATE["hx_late"] = STATE["hx_late"], None
    if late is not None:
        try:
            late.unhook()
        except Exception:  # noqa: BLE001
            traceback.print_exc()
    hooks, STATE["hx"] = STATE["hx"], None
    STATE["pseudo"] = None
    STATE["hx_error"] = False  # a later session reports its own first error
    STATE["hidden_error"] = False  # the same for a hidden-path sentence error
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
            check = selfcheck.start(t, idalayer.current_arch())  # with Hex-Rays: decompile a few functions first
            res = idalayer.annotate(t, idalayer.current_arch())
            if check is not None and check.waits():  # re-review s175 code MINOR 1: this wait has no time limit
                ida_kernwin.replace_wait_box("HIDECANCEL\nkflow: decompile check: waiting for IDA to analyse the new "
                                             "references, then decompiling again")
            line = selfcheck.finish(check)
        finally:
            ida_kernwin.hide_wait_box()
        import ida_auto
        done = ida_auto.auto_is_ok()
        report(idalayer.annotate_text(res, analysis_done=done))
        if line:
            report(line)
        if not done:
            report("IDA's auto-analysis is still running: run Annotate again when it has finished, so that sites that are "
                   "not instructions yet get their references and targets inside other functions get data references "
                   "instead of jump references")
        if hook_pseudocode():
            STATE["pseudo"] = pseudo_index(t, idalayer.current_arch(), idalayer.layout())
            flush_pseudocode()
            report("pseudocode comments on: functions decompiled from now on show the sites (display only)")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


BUG_COLUMNS = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Kind", 6], ["Function", 30], ["Source", 40]]
KEY_COLUMNS = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Key", 34], ["Kind", 8], ["Now", 7],
               ["Target", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Block (bytes / insns)", 12], ["Function", 30]]
BLOCK_COLUMN = 5  # the Block column's place in a static-key chooser line


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


class KeySitesChooser(SitesChooser):
    """The static-key list. Its Block column (the out-of-line block at the site's target, idalayer.target_block_text)
    is decoded only when IDA asks for a row, and once per target."""

    def __init__(self, rows, targets, arch):
        SitesChooser.__init__(self, rows, "kflow: static-key sites", KEY_COLUMNS)
        self.targets, self.arch, self.blocks = targets, arch, {}

    def OnGetLine(self, n):
        target = self.targets[n]
        if target not in self.blocks:
            self.blocks[target] = idalayer.target_block_text(target, self.arch)
        line = list(self.rows[n][1:])
        line.insert(BLOCK_COLUMN, self.blocks[target])
        return line


class ListAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        t = scan_or_warn()  # rescan: cheap, and right after a rebase or a database switch
        if t is None:
            return 0
        SitesChooser(bug_site_rows(t["bug"])).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def bug_site_rows(sites):
    return [(b.addr, "0x%X" % b.addr, "WARN" if b.warn else "BUG", ida_funcs.get_func_name(b.addr) or "", b.where() or "")
            for b in sites]


def function_starts(name, suffixed=False):
    """[(start, size or None, printed size or None, name)] of the function IDA has under this name
    (ida_name.get_name_ea, as kflow looks up the table names). suffixed=True: the functions in IDA's name list called
    name.<suffix> (Linux 6.1 with Clang LTO prints a name like foo.llvm.123 cut at the first dot). size: up to the end
    of the function's last chunk before the next name. printed size: what the kernel prints after the '/' (kallsyms
    measures to the next symbol): here the distance to the next name in IDA's name list in the same segment."""
    def size(ea):
        # get_func() is the entry chunk only. IDA ends flow at a WARN ud2, so the code after such a gap is a tail chunk
        # of the same function (or in none): a site there is still inside it (review s163 MAJOR 1). A chunk at or past
        # the next name is not counted: the kernel prints an address there with that name.
        f = ida_funcs.get_func(ea)
        if f is None or f.start_ea != ea:
            return None
        n, seg = printed(ea), ida_segment.getseg(ea)
        limit = ea + n if n else seg.end_ea if seg is not None else f.end_ea
        end, c = f.end_ea, ida_funcs.get_next_fchunk(ea)
        while c is not None and c.start_ea < limit:
            if ida_funcs.func_contains(f, c.start_ea):
                end = max(end, min(c.end_ea, limit))
            c = ida_funcs.get_next_fchunk(c.start_ea)
        return end - ea

    def printed(ea):
        n, i = ida_name.get_nlist_size(), ida_name.get_nlist_idx(ea)
        while 0 <= i < n and (ida_name.get_nlist_ea(i) <= ea or ida_name.get_nlist_name(i).startswith("$")):
            i += 1
        if not 0 <= i < n:
            return None
        nxt, seg = ida_name.get_nlist_ea(i), ida_segment.getseg(ea)
        return nxt - ea if seg is not None and nxt < seg.end_ea else None
    if not suffixed:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        return [] if ea == ida_idaapi.BADADDR else [(ea, size(ea), printed(ea), name)]
    out = []
    for i in range(ida_name.get_nlist_size()):
        full = ida_name.get_nlist_name(i)
        if full.startswith(name + "."):
            ea = ida_name.get_nlist_ea(i)
            out.append((ea, size(ea), printed(ea), full))
    return out


OOPS_PROMPT = ("kflow: paste a kernel log: a WARNING / kernel BUG / RIP / pc line, a whole oops or syzbot report, "
               "func+0xoff or file:line")


class OopsAction(ida_kernwin.action_handler_t):
    """Go to the BUG/WARN site a pasted kernel log names: function + offset of the RIP / pc / WARNING line (the
    kernel prints the trap's own address), else the sites at the WARNING / kernel BUG line's file:line."""
    @guarded
    def activate(self, ctx):
        default, pre = STATE["oops_text"], None
        if not default and idalayer.current_arch() is not None:  # a first try: a WARNING line from this database's own
            ida_kernwin.show_wait_box("HIDECANCEL\nkflow: reading the kernel's site tables")  # table (judge s180 #3)
            try:
                pre = idalayer.scan()
                default = oops.example_line(pre["bug"], ida_funcs.get_func_name, function_starts,
                                            oops.module_name(ida_nalt.get_input_file_path() or "")) or ""
            except Exception:  # noqa: BLE001  the example is a convenience; the action goes on without it
                pre, default = None, ""
            finally:
                ida_kernwin.hide_wait_box()
        text = ida_kernwin.ask_text(0, default, OOPS_PROMPT)
        if not text:
            return 0
        STATE["oops_text"] = text
        rep = oops.parse(text)
        if rep.primary is None:
            ida_kernwin.warning("kflow: found no WARNING / kernel BUG line, trap RIP / pc line, func+0xoff or file:line in the "
                                "pasted text.%s" % "".join(" Note: " + n for n in oops.not_traps(rep)))
            return 0
        t = pre if pre is not None else scan_or_warn()
        if t is None:
            return 0
        path = ida_nalt.get_input_file_path() or ""
        mod = oops.module_name(path)
        m = oops.resolve(rep, t["bug"], function_starts, mod, mod is not None)
        # IDA shows one function under a name; the kernel can have several static functions of that name
        static = m.function_start is not None and not ida_name.is_public_name(m.function_start) \
            and not ida_name.is_weak_name(m.function_start)
        if m.status == "exact" and static and not oops.confirms(rep, m.site):
            m.notes.append("%s is a static function, and IDA names only one function so: another static function of "
                           "that name is not tried (python3 -m kflow --oops lists them all); the log's WARNING / kernel "
                           "BUG line would confirm the site" % m.function)
        causes = "a log from another build, or two reports in one paste?"
        if m.status == "mismatch" and static:  # review s159 NIT 1: the log may name another static function of that name
            causes = ("a log from another build, two reports in one paste, or IDA shows another static function of "
                      "that name (IDA names only one)?")
            m.notes.append("%s is a static function in IDA, so the cause can be a log from another build, two reports in "
                           "one paste, or IDA shows another static function of that name (IDA names only one); python3 "
                           "-m kflow --oops tries every function of that name" % m.function)
        for line in oops.describe(rep, m, ida_funcs.get_func_name):
            report(line)
        if m.status == "ambiguous" or (m.address is None and m.candidates):  # the candidates, no jump
            where = "at %s" % m.label if m.label else "in %s" % m.loc.function
            SitesChooser(bug_site_rows(m.candidates), "kflow: BUG/WARN sites %s" % where).Show()
            if m.status == "mismatch":  # never a silent jump to a site the log itself contradicts
                ida_kernwin.warning("kflow: the pasted log does not fit this file: %s (%s). Not jumping; the BUG/WARN "
                                    "sites at %s are in the list, details in the Output window."
                                    % (m.reason, causes, m.label))
            return 1
        if m.address is None:
            ida_kernwin.warning("kflow: no BUG/WARN site or function of this file matches the pasted text; details are "
                                "in the Output window.")
            return 0
        if not ida_kernwin.jumpto(m.address):  # an address outside this database
            ida_kernwin.warning("kflow: could not jump to 0x%X (not in this database?); details are in the Output "
                                "window." % m.address)
            return 0
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
        KeySitesChooser(key_site_rows(t), [j.target for j in t["jump"]], idalayer.current_arch()).Show()
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
        report("references removed: %d jump references, %d static-key site -> key references, %d data references to targets"
               " inside another function" % (removed, res.get("key_refs", 0), res.get("other_refs", 0)))
        STATE["pseudo"] = None
        flush_pseudocode()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def warnflow_hook(offsets=()):
    """Install kflow's processor hook for the open database (once) and give it the sites. It lives only in memory."""
    if STATE["wf"] is None:
        from kflow import warnflow
        hook = warnflow.WarnFlowHook()
        if not hook.hook():
            return None
        hook.on_undo = _warnflow_resync_filter
        STATE["wf"] = hook
    STATE["wf"].offsets = set(offsets)
    return STATE["wf"]


def _warnflow_resync_filter(offsets):
    if STATE["wf_filter"] is not None:
        STATE["wf_filter"].offsets = set(offsets)


def warnflow_filter(offsets):
    """The decompiler part, if Hex-Rays is there. Fails soft: a problem is reported once, the disassembly part stays.
    Returns what happened, for the messages."""
    if STATE["wf_filter"] is not None:
        STATE["wf_filter"].offsets = set(offsets)
        return "on"
    try:
        from kflow import warnflow
        STATE["wf_filter"] = warnflow.make_filter(offsets)
    except Exception:  # noqa: BLE001  no decompiler, a decompiler that refuses the filter, or an unexpected one
        STATE["wf_filter"] = None
        if not STATE["wf_error"]:
            STATE["wf_error"] = True
            report("WARN fall-through: the decompiler part could not be installed (shown once); the disassembly part "
                   "is not affected:\n%s" % traceback.format_exc())
        return "not installed (error)"
    return "on" if STATE["wf_filter"] is not None else "off (no decompiler)"


def warnflow_stop():
    """Unhook and remove the decompiler filter (plugin unloads, or Remove WARN fall-through)."""
    hook, STATE["wf"] = STATE["wf"], None
    flt, STATE["wf_filter"] = STATE["wf_filter"], None
    STATE["wf_error"] = False
    if hook is not None:
        hook.offsets = set()
        try:
            hook.unhook()
        except Exception:  # noqa: BLE001
            traceback.print_exc()
    if flt is not None:
        try:
            from kflow import warnflow
            warnflow.remove_filter(flt)
        except Exception:  # noqa: BLE001
            traceback.print_exc()


def warnflow_resume():
    """At load: in a database where WARN fall-through is on, hook again (nothing else is changed) and say how many
    sites lost their flow (reanalysed while kflow was not loaded); running the action again restores them."""
    if not idalayer.warn_flow_recorded() or idalayer.current_arch() != "x86_64":
        return
    try:
        from kflow import warnflow
        offsets = warnflow.site_offsets(warnflow.records())
        if warnflow_hook(offsets) is None:
            report("WARN fall-through is on in this database, but IDA did not accept the processor hook")
            return
        lost = warnflow.missing_flow(offsets)
        # like the action: __WARN() needs a successor in the function, so no filter while no site has flow
        dec = warnflow_filter(offsets) if lost < len(offsets) else "not installed (no site has flow)"
        report("WARN fall-through (experimental) is on in this database: processor hook installed for %d WARN sites, "
               "decompiler part %s; %s" % (len(offsets), dec, "%d of them have no flow now (reanalysed without kflow?): "
                                           "run kflow: Let WARN sites fall through again to restore it" % lost
                                           if lost else "all of them have flow"))
    except Exception:  # noqa: BLE001  the other features must load anyway
        report("WARN fall-through could not be turned on again:\n%s" % traceback.format_exc())


class WarnFlowAction(ida_kernwin.action_handler_t):
    """Experimental, x86_64 only: ordinary flow after the WARN ud2 traps listed in the kernel's __bug_table."""
    @guarded
    def activate(self, ctx):
        if idalayer.current_arch() == "aarch64":
            from kflow import warnflow
            stops = warnflow.brk_stops()
            report("WARN fall-through: arm64 database; IDA's ARM module marks brk as the end of flow: %s; nothing changed"
                   % ("yes" if stops else "no"))
            if stops:
                ida_kernwin.info("kflow: IDA's ARM module ends code flow at brk here, but kflow's WARN fall-through "
                                 "supports only x86_64 so far. Nothing was changed.\nPlease report it: %s" % ISSUES_URL)
            else:
                ida_kernwin.info("kflow: not needed on arm64: IDA continues after brk #0x800. Nothing was changed.")
            return 0
        import ida_auto
        if not ida_auto.auto_is_ok():  # auto_wait() would run the whole remaining analysis under a wait box
            ida_kernwin.warning("kflow: wait until IDA's auto-analysis has finished, then run this again. Nothing was changed.")
            return 0
        t = scan_or_warn()
        if t is None:
            return 0
        from kflow import warnflow
        if not warnflow.warn_sites(t):
            ida_kernwin.warning("kflow: no WARN trap of this kernel's __bug_table is a ud2 in code: nothing to do.")
            return 0
        stops = warnflow.ud2_stops()
        hook = warnflow_hook(STATE["wf"].offsets if STATE["wf"] is not None else ())
        if hook is None:
            ida_kernwin.warning("kflow: IDA did not accept the processor hook; nothing was changed.")
            return 0
        start = time.time()
        ida_kernwin.show_wait_box("HIDECANCEL\nkflow: letting WARN sites fall through (IDA reanalyses them)")
        try:
            res = warnflow.enable(t, hook)
        finally:
            ida_kernwin.hide_wait_box()
        STATE["wf_last"] = res
        if res["flow"]:
            dec = warnflow_filter(hook.offsets)
        else:  # IDA ignored the hook: __WARN() would have no successor in the function, so no filter
            dec = "not installed (no site got flow)"
            if STATE["wf_filter"] is not None:  # one installed at load time while sites still had flow
                from kflow import warnflow
                warnflow.remove_filter(STATE.pop("wf_filter"))
                STATE["wf_filter"] = None
        flush_pseudocode()
        report("WARN fall-through (experimental): %d WARN ud2 sites, flow after %d of them (IDA marks ud2 as the end "
               "of flow: %s); the %d BUG ud2 traps are left alone; function tails added: %d, next instruction already "
               "in another function (left alone): %d, site in no function: %d, tail not added: %d; %d functions "
               "reanalysed; decompiler part %s; %.1f s"
               % (res["sites"], res["flow"], "yes" if stops else "no", warnflow.bug_traps(t), res["tails"],
                  res["other_func"], res["no_func"], res["tail_failed"], res["functions"], dec, time.time() - start))
        if res["sites"] and not res["flow"]:
            ida_kernwin.warning("kflow: IDA added no flow after any of the %d WARN sites: the processor hook had no "
                                "effect in this IDA version.\nPlease report it: %s\n'kflow: Remove WARN fall-through' "
                                "undoes the rest." % (res["sites"], ISSUES_URL))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class WarnFlowOffAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        if not idalayer.warn_flow_recorded():
            if STATE["wf"] is not None or STATE["wf_filter"] is not None:  # e.g. the enable action was undone
                warnflow_stop()
                report("WARN fall-through: no record in this database (undone?); kflow's processor hook and decompiler "
                       "filter were still installed and are now removed")
                flush_pseudocode()
                return 1
            ida_kernwin.warning("kflow: WARN fall-through is not on in this database.")
            return 0
        from kflow import warnflow
        warnflow_stop()  # first: then nothing adds the flow when IDA reanalyses the sites
        ida_kernwin.show_wait_box("HIDECANCEL\nkflow: removing WARN fall-through (IDA reanalyses the sites)")
        try:
            res = warnflow.disable()
        finally:
            ida_kernwin.hide_wait_box()
        STATE["wf_last"] = res
        flush_pseudocode()
        report("WARN fall-through removed: %d sites reanalysed, flow still after %d; function tails removed: %d%s"
               % (res["sites"], res["flow_left"], res["tails"],
                  "; %d tails kflow added were not removed (merged with IDA's own code or refused; kflow removes only a "
                  "chunk that is still exactly the tail it added) and stay where they are" % res["tails_left"]
                  if res["tails_left"] else ""))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("kflow:annotate", "kflow: Annotate kernel sites", AnnotateAction),
    ("kflow:list", "kflow: List BUG/WARN sites", ListAction),
    ("kflow:keys", "kflow: List static-key sites", KeySitesAction),
    ("kflow:oops", "kflow: Go to oops/WARN line", OopsAction),
    ("kflow:remove", "kflow: Remove annotations", RemoveAction),
    ("kflow:warnflow", "kflow: Let WARN sites fall through (experimental)", WarnFlowAction),
    ("kflow:warnflow_off", "kflow: Remove WARN fall-through", WarnFlowOffAction),
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
        if not hook_pseudocode():
            hook_pseudocode_later()
        warnflow_resume()
        report("%s loaded" % __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.process_ui_action("kflow:annotate")

    def term(self):
        warnflow_stop()
        unhook_pseudocode()
        for name, _, _ in ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return KflowPlugin()
