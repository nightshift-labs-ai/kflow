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
TIME_LIMIT = 10.0    # BEFORE starts no decompile after TIME_LIMIT/2 s; AFTER gets TIME_LIMIT/2 s more of its own
MAX_FUNC_BYTES = 0x4000  # review s174 api MINOR 4: larger functions are not picked (one decompile could take tens of s)
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
    spread evenly over the table (same choice every run; the list is ordered NOP-site functions first before spreading,
    so NOP sites are not preferred once there are more than `limit`)."""
    nop, other = [], []
    seen = set()
    for j in t["jump"]:
        if not gets_jump_ref(j, arch):
            continue
        f = ida_funcs.get_func(j.code)
        if f is None or f.start_ea in seen or f.end_ea - f.start_ea > MAX_FUNC_BYTES:
            continue
        seen.add(f.start_ea)
        (nop if is_nop(j.code, arch) else other).append(f.start_ea)
    funcs = nop + other
    if len(funcs) > limit:
        funcs = [funcs[i * len(funcs) // limit] for i in range(limit)]
    return funcs


REASON_CHARS = 80  # Hex-Rays' failure text is cut to this many characters in the summary line


def try_decompile(ea):
    """(True, None) when Hex-Rays decompiles the function at ea now, else (False, Hex-Rays' own reason or None). Its
    cache entry is erased first (mark_cfunc_dirty), so the answer is not an older result kept from before Annotate."""
    import ida_hexrays
    ida_hexrays.mark_cfunc_dirty(ea)
    hf = None
    try:  # review s174 api MINOR 5: Hex-Rays writes why it failed into a hexrays_failure_t the caller passes
        hf = ida_hexrays.hexrays_failure_t()
    except Exception:  # noqa: BLE001  (without it: the same check, no reason)
        hf = None
    try:
        # review s174 api MINOR 5: DECOMP_NO_WAIT = no Hex-Rays wait box of its own, so no user Cancel there that would be
        # read as a kflow failure. Failure = None (current IDAPython) or DecompilationFailure (older ones)
        if ida_hexrays.decompile(ea, hf, ida_hexrays.DECOMP_NO_WAIT) is not None:
            return True, None
    except ida_hexrays.DecompilationFailure:
        pass
    return False, failure_reason(hf)


def failure_reason(hf):
    """Hex-Rays' text in hf on one line, cut to REASON_CHARS; None when there is none."""
    if hf is None:
        return None
    try:
        text = " ".join(str(hf.desc()).split())
    except Exception:  # noqa: BLE001
        return None
    if len(text) > REASON_CHARS:
        text = text[:REASON_CHARS] + "..."
    return text or None


def decompiles(ea):
    """True when Hex-Rays decompiles the function at ea now (try_decompile without the reason)."""
    return try_decompile(ea)[0]


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
        self.skip = None     # a reason to skip the whole check (auto-analysis still running)
        self.reasons = {}    # function -> Hex-Rays' reason for its last failed decompile

    def _run(self, funcs, out, limit):
        for ea in funcs:
            if self.spent >= limit:
                self.stopped = True
                return
            start = clock()
            out[ea], why = try_decompile(ea)
            self.spent += clock() - start
            if why:
                self.reasons[ea] = why

    def before(self, t, arch):
        try:
            self.picked = pick_functions(t, arch)
            self._run(self.picked, self.before_ok, self.seconds / 2)
        except Exception as e:  # noqa: BLE001  (the check must never stop Annotate)
            self.error = e

    def after(self):
        if self.error is not None or self.skip is not None:
            return
        try:
            # reviews s174 (api MINOR 3/NIT 7, claims F1): its own half of the budget, and only functions that decompiled
            # before (one slow BEFORE decompile must not leave AFTER nothing; failures before are never re-tried)
            self._run([ea for ea in self.before_ok if self.before_ok[ea]], self.after_ok, self.spent + self.seconds / 2)
        except Exception as e:  # noqa: BLE001
            self.error = e

    def text(self):
        if self.skip is not None:
            return "decompile check skipped: %s" % self.skip
        if self.error is not None:
            return "decompile check skipped: %s" % (str(self.error) or type(self.error).__name__)
        if not self.picked:
            return "decompile check: no function has a static-key site that gets a new jump reference"
        checked = list(self.after_ok)  # functions that decompiled before Annotate and were decompiled again after it
        good = [ea for ea in self.before_ok if self.before_ok[ea]]
        blamed = [ea for ea in checked if not self.after_ok[ea]]
        failed_before = [ea for ea in self.before_ok if not self.before_ok[ea]]

        def n(k):
            return "%d function%s" % (k, "" if k == 1 else "s")
        if not good:
            text = "decompile check: none of %s with static-key sites decompiled before Annotate" % n(len(self.before_ok))
        elif blamed:
            text = ("decompile check: %d of %s decompiled before Annotate but %s after (%s): kflow's jump "
                    "references may confuse Hex-Rays there; kflow: Remove annotations takes them out"
                    % (len(blamed), n(len(checked)), "fails" if len(blamed) == 1 else "fail",  # re-review s174 NIT 3
                       ", ".join(fname(ea) + (": " + self.reasons[ea] if ea in self.reasons else "") for ea in blamed)))
        else:
            text = "decompile check: %s with static-key sites %s before and after Annotate" % (
                n(len(checked)), "decompiles" if len(checked) == 1 else "decompile")
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
    try:
        import ida_auto
        if not ida_auto.auto_is_ok():  # BEFORE and AFTER would compare a database that is still changing
            check.skip = ("IDA's auto-analysis is still running; after it finishes, Remove annotations and Annotate "
                          "again to run the check")
            return check
    except Exception as e:  # noqa: BLE001  (the check must never stop Annotate)
        check.error = e
        return check
    check.before(t, arch)
    return check


def finish(check):
    """The summary line after annotate() (None without the decompiler); never raises."""
    if check is None:
        return None
    try:
        if check.skip is None and check.error is None and any(check.before_ok.values()):  # re-review s174 MINOR 2
            import ida_auto
            # review s174 api MAJOR 1: auto-analysis was idle before Annotate (start() checked it), so this only lets IDA
            # react to the references Annotate just added; the AFTER pass then sees what F5 will see
            ida_auto.auto_wait()
        check.after()
        return check.text()
    except Exception as e:  # noqa: BLE001
        return "decompile check skipped: %s" % (str(e) or type(e).__name__)
