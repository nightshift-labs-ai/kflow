"""Decompile check around Annotate: with the Hex-Rays decompiler, decompile a few functions that get a new kflow jump
reference before Annotate adds anything and again afterwards, and say in one line whether any of them stopped
decompiling. Used by the Annotate menu action and by tools/kflow_headless.py.

It never stops Annotate: any error becomes one 'decompile check skipped: <reason>' line. Tested only with fake
ida_* modules; not yet run in IDA.
"""
import time

import ida_bytes
import ida_funcs

from . import idalayer

MAX_FUNCS = 20       # functions decompiled before and after Annotate
TIME_LIMIT = 10.0    # seconds of decompiling in all; half of it for the BEFORE pass
clock = time.monotonic


def hexrays():
    """True when the decompiler is there and ready (as kflow_entry.hook_pseudocode checks it)."""
    try:
        import ida_hexrays
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:  # noqa: BLE001  (no decompiler, or IDA without its Python bindings)
        return False


def is_nop(ea, arch):
    """True for an x86 NOP (90, 66 90, 0F 1F .., 66 0F 1F ..) or the aarch64 NOP at ea."""
    if arch == "aarch64":
        return idalayer.read(ea, 4) == b"\x1f\x20\x03\xd5"
    b = (idalayer.read(ea, 3) or b"").lstrip(b"\x66")
    return b[:1] == b"\x90" or b[:2] == b"\x0f\x1f"


def gets_jump_ref(j, arch):
    """True when Annotate will add a new jump reference at this static-key site (the tests _ref() and _add() make)."""
    src, dst = j.code, j.target
    return bool(idalayer.in_text(src) and idalayer.is_insn(src) and idalayer.in_text(dst)
                and dst != ida_bytes.get_item_end(src) and not idalayer.in_other_function(src, dst)
                and dst not in idalayer.code_refs_from(src) and not idalayer.branches_to(src, dst, arch))


def pick_functions(t, arch, limit=MAX_FUNCS):
    """Start addresses of up to `limit` functions with a static-key site that gets a new jump reference: functions
    with a NOP site first, then spread evenly over the table (same choice every run)."""
    nop, other = [], []
    seen = set()
    for j in t["jump"]:
        if not gets_jump_ref(j, arch):
            continue
        f = ida_funcs.get_func(j.code)
        if f is None or f.start_ea in seen:
            continue
        seen.add(f.start_ea)
        (nop if is_nop(j.code, arch) else other).append(f.start_ea)
    funcs = nop + other
    if len(funcs) > limit:
        funcs = [funcs[i * len(funcs) // limit] for i in range(limit)]
    return funcs


def decompiles(ea):
    """True when Hex-Rays decompiles the function at ea now. Its cache entry is erased first (mark_cfunc_dirty), so
    the answer is not an older result kept from before Annotate."""
    import ida_hexrays
    ida_hexrays.mark_cfunc_dirty(ea)
    try:
        return ida_hexrays.decompile(ea) is not None
    except ida_hexrays.DecompilationFailure:
        return False


def fname(ea):
    return ida_funcs.get_func_name(ea) or "0x%X" % ea


class DecompileCheck:
    """before() runs before Annotate, after() after it, text() gives the summary line (None without a decompiler)."""

    def __init__(self, seconds=TIME_LIMIT):
        self.seconds = seconds
        self.picked = []
        self.before_ok = {}
        self.after_ok = {}
        self.spent = 0.0
        self.stopped = False
        self.error = None

    def _run(self, funcs, out, limit):
        for ea in funcs:
            if self.spent >= limit:
                self.stopped = True
                return
            start = clock()
            out[ea] = decompiles(ea)
            self.spent += clock() - start

    def before(self, t, arch):
        try:
            self.picked = pick_functions(t, arch)
            self._run(self.picked, self.before_ok, self.seconds / 2)
        except Exception as e:  # noqa: BLE001  (the check must never stop Annotate)
            self.error = e

    def after(self):
        if self.error is not None:
            return
        try:
            self._run(list(self.before_ok), self.after_ok, self.seconds)
        except Exception as e:  # noqa: BLE001
            self.error = e

    def text(self):
        if self.error is not None:
            return "decompile check skipped: %s" % (str(self.error) or type(self.error).__name__)
        if not self.picked:
            return "decompile check: no function has a static-key site that gets a new jump reference"
        checked = list(self.after_ok)
        good = [ea for ea in checked if self.before_ok[ea]]
        blamed = [ea for ea in good if not self.after_ok[ea]]
        failed_before = [ea for ea in checked if not self.before_ok[ea]]
        if not good:
            text = "decompile check: none of %d functions with static-key sites decompiled before Annotate" % len(checked)
        elif blamed:
            text = ("decompile check: %d of %d functions decompiled before Annotate but fail after (%s): kflow's jump "
                    "references may confuse Hex-Rays there; kflow: Remove annotations takes them out"
                    % (len(blamed), len(good), ", ".join(fname(ea) for ea in blamed)))
        else:
            text = "decompile check: %d functions with static-key sites decompile before and after Annotate" % len(good)
        if failed_before and good:
            text += "; %d more failed already before Annotate (not counted against kflow)" % len(failed_before)
        if self.stopped:
            text += "; stopped after %.0f s of decompiling: %d of %d picked functions checked" % (
                self.spent, len(checked), len(self.picked))
        return text


def start(t, arch):
    """A DecompileCheck that has done its BEFORE pass, or None without the decompiler. Call before annotate()."""
    if not hexrays():
        return None
    check = DecompileCheck()
    check.before(t, arch)
    return check


def finish(check):
    """The summary line after annotate() (None without the decompiler); never raises."""
    if check is None:
        return None
    try:
        check.after()
        return check.text()
    except Exception as e:  # noqa: BLE001
        return "decompile check skipped: %s" % (str(e) or type(e).__name__)
