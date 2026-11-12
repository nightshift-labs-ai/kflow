"""Experimental, opt-in, x86_64 only: let the WARN traps listed in the kernel's __bug_table fall through in IDA.

IDA ends code flow at x86_64 `ud2`, so the code after a WARN trap (where the kernel carries on) is unreachable in IDA
and missing from the function, and Hex-Rays prints the trap as BUG(), which never returns. Ordinary flow is kept in
the database flags and IDA drops it whenever it reanalyses the ud2 (SDK xref.hpp: all non-user xrefs of an item are
deleted on reanalysis; fl_F cannot be a user xref), so a processor hook is the only durable way to add it:
WarnFlowHook adds ordinary flow after exactly the recorded WARN ud2 sites and leaves every other instruction, BUG
traps included, to IDA. The sites are recorded in the database (offsets from the image base, like kflow's other
records); kflow_entry.py hooks again whenever it loads a database that has the record, and only then.

Written from the IDA SDK documentation and the official samples (ana_emu_out.py for the hook, vds8.py for the
microcode filter); tested only on fake ida_* modules (tests/test_warnflow_stub.py), not yet in real IDA.
"""
import ida_allins
import ida_auto
import ida_bytes
import ida_funcs
import ida_idp
import ida_nalt
import ida_netnode
import ida_xref

from .idalayer import BADADDR, MASK, WARN_NODE, _created, in_text, read

UD2 = b"\x0f\x0b"
UD2_LEN = len(UD2)
NN_UD2 = ida_allins.NN_ud2
SITE, TAIL = 1, 2  # record bits: a WARN ud2 that falls through; the start of a function tail kflow appended
LEN_SHIFT = 8  # a TAIL record also holds the tail's length (its end) from this bit; 0 = end not known: never removed
DECL = "void __spoils<> __WARN(void);"  # returns and changes no register; __WARN() is the kernel's own name for the trap


def warn_sites(t):
    """Addresses of the WARN traps that are a ud2 here, in code, with code after them. Not BUG traps; not a Linux
    6.19+ WARN with a message (a call, no trap); not freed init code of a memory image (other bytes now)."""
    return {b.addr for b in t["bug"] if b.warn and not b.args and in_text(b.addr) and in_text(b.addr + UD2_LEN)
            and read(b.addr, UD2_LEN) == UD2}


def bug_traps(t):
    """How many BUG traps are a ud2 here: kflow leaves them the end of flow."""
    return len({b.addr for b in t["bug"] if not b.warn and in_text(b.addr) and read(b.addr, UD2_LEN) == UD2})


def ud2_stops():
    """IDA's own answer (x86 database): does its processor module mark ud2 as the end of flow? Logged only."""
    return bool(ida_idp.has_insn_feature(NN_UD2, ida_idp.CF_STOP))


def brk_stops():
    """The same for arm64 brk (ARM database)."""
    return bool(ida_idp.has_insn_feature(ida_allins.ARM_brk, ida_idp.CF_STOP))


def _offset(ea, base):
    return (ea - base) & MASK


def _ea(off, base):
    return (off + base) & MASK


class WarnFlowHook(ida_idp.IDP_Hooks):
    """Emulates the recorded WARN ud2 traps as an instruction that does not stop: ordinary flow to the next one, as a
    processor module's emulator adds for every non-stop instruction. Everything else gets IDA's own emulation.
    Sites are offsets from the image base, so the hook stays right after a rebase."""

    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self, 0, 0)  # not HKCB_GLOBAL: never outlives the database (SDK idp.hpp)
        self.offsets = set()
        self.on_undo = None  # set by the plugin: also resync the decompiler filter

    def ev_emu_insn(self, insn):
        try:
            if insn.itype != NN_UD2:  # nearly every instruction: one compare
                return 0
            if ((insn.ea - ida_nalt.get_imagebase()) & MASK) not in self.offsets:
                return 0  # a BUG trap or any other ud2: IDA's own emulation (end of flow)
            insn.add_cref(insn.ea + insn.size, 0, ida_xref.fl_F)  # ordinary flow
            return 1  # handled (ud2 has no operands); 0 would run IDA's own emulation too (ana_emu_out.py)
        except Exception:  # noqa: BLE001  a processor hook must never break IDA's analysis
            return 0

    def ev_ending_undo(self, action_name, is_undo):
        """Undo/redo changed the database (the record included): take the sites from it again, as the official
        sample py_mex1.py advises, so the hook never adds flow the database no longer records."""
        try:
            self.offsets = site_offsets(records())
            if self.on_undo is not None:
                self.on_undo(self.offsets)
        except Exception:  # noqa: BLE001
            pass
        return 0


def records():
    """{offset: bits} recorded in the database, or None when WARN fall-through is off there."""
    node = ida_netnode.netnode(WARN_NODE, 0, False)
    if node.index() == ida_netnode.BADNODE:
        return None
    out = {}
    off = node.altfirst()
    while off != ida_netnode.BADNODE:
        out[off] = node.altval(off)
        off = node.altnext(off)
    return out


def site_offsets(rec):
    return {off for off, bits in (rec or {}).items() if bits & SITE}


def missing_flow(offsets):
    """How many recorded sites have no flow to the next instruction now (e.g. reanalysed while kflow was not loaded)."""
    base = ida_nalt.get_imagebase()
    return sum(1 for off in offsets if not ida_bytes.is_flow(ida_bytes.get_flags(_ea(off, base) + UD2_LEN)))


def _tail_length(nxt, limit):
    """Length of the tail kflow just appended at nxt, or 0 when IDA merged it with a chunk it already had (the chunk
    at nxt starts before nxt, or reaches past limit, where the next chunk started before the append)."""
    c = ida_funcs.get_fchunk(nxt)
    if c is None or c.start_ea != nxt or c.end_ea > limit or c.end_ea <= nxt:
        return 0
    return c.end_ea - nxt


def _own_tail(rec, off, base):
    """The site's function if the chunk at a recorded tail is still exactly the tail kflow appended to it: a tail chunk
    that starts at the recorded start, ends at the recorded end and is owned by that function; else None."""
    n, site = rec[off] >> LEN_SHIFT, (off - UD2_LEN) & MASK  # the tail starts right after its WARN site
    if not n or not rec.get(site, 0) & SITE:
        return None  # end not recorded (a record from before kflow recorded it, or IDA merged the tail on append)
    ea = _ea(off, base)
    f = ida_funcs.get_func(_ea(site, base))
    c = ida_funcs.get_fchunk(ea)  # the chunk around ea; remove_func_tail would remove all of it
    if (f is None or c is None or not ida_funcs.is_func_tail(c) or c.start_ea != ea or c.end_ea != _ea(off + n, base)
            or c.owner != f.start_ea):
        return None
    return f


def _reanalyze(funcs):
    for fea in sorted(funcs):
        pfn = ida_funcs.get_func(fea)
        if pfn is not None:
            ida_funcs.reanalyze_function(pfn)


def enable(t, hook):
    """Record the WARN ud2 sites, let IDA reanalyse them with the hook in place, add the newly reachable code that is
    in no function to the site's function as a tail (code of another function is never taken: counted), then
    reanalyse those functions. hook: the plugin's WarnFlowHook, already hooked. Running it again changes nothing.
    Returns counts; "flow" is the self-check (0 means IDA ignored the hook)."""
    sites = sorted(warn_sites(t))
    base = ida_nalt.get_imagebase()
    res = {"sites": len(sites), "flow": 0, "tails": 0, "other_func": 0, "no_func": 0, "tail_failed": 0, "functions": 0}
    if not sites:
        return res
    node = _created(WARN_NODE)
    for ea in sites:
        off = _offset(ea, base)
        node.altset(off, node.altval(off) | SITE)
    hook.offsets = site_offsets(records())
    for ea in sites:
        ida_auto.plan_ea(ea)
    ida_auto.auto_wait()  # IDA re-emulates each site; the hook adds the flow, IDA disassembles what follows
    funcs = set()
    for ea in sites:
        f = ida_funcs.get_func(ea)
        if f is None:
            res["no_func"] += 1
            continue
        funcs.add(f.start_ea)
        nxt = ea + UD2_LEN
        g = ida_funcs.get_func(nxt)
        if g is None:
            c = ida_funcs.get_next_fchunk(nxt)
            limit = c.start_ea if c is not None else BADADDR
            if ida_bytes.is_code(ida_bytes.get_flags(nxt)) and ida_funcs.append_func_tail(f, nxt, BADADDR):
                off = _offset(nxt, base)
                node.altset(off, (node.altval(off) & SITE) | TAIL | (_tail_length(nxt, limit) << LEN_SHIFT))
                res["tails"] += 1
            else:
                res["tail_failed"] += 1
        elif g.start_ea != f.start_ea:
            res["other_func"] += 1  # IDA made a function there: left alone
    _reanalyze(funcs)
    ida_auto.auto_wait()
    res["functions"] = len(funcs)
    res["flow"] = sum(1 for ea in sites if ida_bytes.is_flow(ida_bytes.get_flags(ea + UD2_LEN)))
    return res


def disable():
    """Undo enable(); the caller unhooks first, so nothing adds the flow any more. Removes each function tail kflow
    appended only where it is still exactly that chunk: a tail chunk that starts and ends where kflow's did and belongs
    to the site's function (remove_func_tail removes the whole chunk around the address, so a tail IDA merged with
    its own code, or one whose end was not recorded, stays and is counted in tails_left). Then lets IDA reanalyse
    the sites (IDA drops their flow), reanalyses the functions and deletes the record. The code after a site stays
    code, unreachable again. Returns counts, or None when WARN fall-through is off in this database."""
    rec = records()
    if rec is None:
        return None
    base = ida_nalt.get_imagebase()
    sites = sorted(_ea(off, base) for off, bits in rec.items() if bits & SITE)
    tails = sorted(off for off, bits in rec.items() if bits & TAIL)
    res = {"sites": len(sites), "tails": 0, "tails_left": 0, "flow_left": 0}
    funcs = set()
    for off in tails:
        ea = _ea(off, base)
        if ida_funcs.get_func(ea) is None:
            continue  # no function there any more: nothing to take back
        f = _own_tail(rec, off, base)
        fea = f.start_ea if f is not None else None  # read before the chunk list changes
        if f is not None and ida_funcs.remove_func_tail(f, ea):
            res["tails"] += 1
            funcs.add(fea)
        else:
            res["tails_left"] += 1  # merged with IDA's own code, end not recorded, moved to another function, or refused
    for ea in sites:
        ida_auto.plan_ea(ea)
        f = ida_funcs.get_func(ea)
        if f is not None:
            funcs.add(f.start_ea)
    ida_auto.auto_wait()
    _reanalyze(funcs)
    ida_auto.auto_wait()
    res["flow_left"] = sum(1 for ea in sites if ida_bytes.is_flow(ida_bytes.get_flags(ea + UD2_LEN)))
    ida_netnode.netnode(WARN_NODE, 0, False).kill()
    return res


def make_filter(offsets):
    """The Hex-Rays part: a microcode filter that decompiles each recorded WARN ud2 as a call to __WARN(), which
    returns and changes no register, instead of BUG(). Returns the installed filter, or None without the decompiler.
    Raises if Hex-Rays refuses the declaration or the filter (the plugin reports that and keeps the rest)."""
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        return None

    class WarnCall(ida_hexrays.udc_filter_t):
        def __init__(self):
            ida_hexrays.udc_filter_t.__init__(self)
            self.offsets = set()

        def match(self, cdg):
            try:
                insn = cdg.insn
                return (insn.itype == NN_UD2 and ((insn.ea - ida_nalt.get_imagebase()) & MASK) in self.offsets
                        and ida_bytes.is_flow(ida_bytes.get_flags(insn.ea + insn.size)))  # only where IDA has the flow
            except Exception:  # noqa: BLE001  never break the decompiler
                return False

    flt = WarnCall()
    if not flt.init(DECL):
        raise ValueError("Hex-Rays did not accept the declaration %r" % DECL)
    flt.offsets = set(offsets)
    if not ida_hexrays.install_microcode_filter(flt, True):
        raise ValueError("Hex-Rays did not install the microcode filter")
    return flt


def remove_filter(flt):
    import ida_hexrays
    return ida_hexrays.install_microcode_filter(flt, False)
