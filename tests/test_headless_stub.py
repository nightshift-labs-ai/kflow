"""tools/kflow_headless.py on fake idapro + ida_* modules backed by a kernel ELF.
Usage: python3 tests/test_headless_stub.py <kernel.elf>   (SKIPs without a path)"""
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
if len(sys.argv) < 2:
    print("SKIP: pass a kernel ELF path")
    sys.exit(0)
import test_ida_stub as T  # noqa: E402
from kflow.cli import Elf  # noqa: E402

elf = Elf(sys.argv[1])
w = T.world_from(elf)
T.install(w)
calls = []
idapro = types.ModuleType("idapro")
idapro.open_database = lambda path, analyse: calls.append(("open", analyse)) or 0
idapro.close_database = lambda save: calls.append(("close", save))
sys.modules["idapro"] = idapro
auto_ok = [True]  # IDA's auto-analysis state after open_database (review s159 NIT 2: the runner asks IDA, not the flag)
sys.modules["ida_auto"] = types.ModuleType("ida_auto")
sys.modules["ida_auto"].auto_is_ok = lambda: auto_ok[0]
sys.modules["ida_auto"].auto_wait = lambda: calls.append(("auto_wait",))
dialogs = []  # tripwire only: kflow_headless never imports kflow_entry (the summary window lives there), so this stays empty unless that import is ever added
if "ida_kernwin" not in sys.modules:
    sys.modules["ida_kernwin"] = types.ModuleType("ida_kernwin")
sys.modules["ida_kernwin"].ask_buttons = lambda *a: dialogs.append(a) or -1
import kflow_headless as H  # noqa: E402
from kflow import idalayer as IL  # noqa: E402
seen_done, _annotate_text = [], IL.annotate_text
IL.annotate_text = lambda res, analysis_done=False: seen_done.append(analysis_done) or _annotate_text(res, analysis_done)
import json  # noqa: E402
import tempfile  # noqa: E402

if "ida_funcs" not in sys.modules:
    sys.modules["ida_funcs"] = types.ModuleType("ida_funcs")
sys.modules["ida_funcs"].get_func_name = lambda ea: elf.func(ea) or ""  # function names for --json, from the ELF

import contextlib, io  # noqa: E402
out = io.StringIO()
with contextlib.redirect_stdout(out):
    assert H.main([sys.argv[1]]) == 0
print(out.getvalue(), end="")
assert "jump references added: " in out.getvalue() and "static-key site -> key references: " in out.getvalue(), out.getvalue()
assert "decompile check" not in out.getvalue(), "no decompiler: no decompile check line"
assert any(c.startswith("kflow: ") for c in w["cmts"].values())
assert seen_done == [True], seen_done
auto_ok[0] = False  # e.g. --no-analysis on a fresh file: the text must not claim analysis has finished
with contextlib.redirect_stdout(io.StringIO()):
    assert H.main([sys.argv[1], "--no-analysis"]) == 0
assert seen_done == [True, False], seen_done
assert calls[-2:] == [("open", False), ("close", True)], calls
del calls[-2:]  # the open/close sequence below is checked as before
auto_ok[0] = True
assert H.main([sys.argv[1], "--remove", "--no-analysis"]) == 0
assert calls == [("open", True), ("close", True), ("open", False), ("close", True)], calls
assert not any(c.startswith("kflow") for c in w["cmts"].values())
assert not any(w["xrefs"].values())  # no user references left
# --json: every decoded site, with IDA's function names, written before anything changes
with tempfile.TemporaryDirectory() as d:
    out = os.path.join(d, "sites.json")
    with contextlib.redirect_stdout(io.StringIO()):
        assert H.main([sys.argv[1], "--json", out, "--remove", "--no-analysis"]) == 0
    js = json.load(open(out))
ref = T.load(elf)
assert [len(js[k]) for k in ("bug", "jump", "ex")] == [len(ref.get(k, [])) for k in ("bug", "jump", "ex")], js["missing"]
for k, key in (("bug", "addr"), ("jump", "addr"), ("ex", "addr")):
    assert all(r[key].startswith("0x") and int(r[key], 16) >= 0 for r in js[k])
b0 = next((b for b in ref.get("bug", []) if b.file), None)
if b0 is not None:
    r = next(r for r in js["bug"] if int(r["addr"], 16) == b0.addr)
    assert r["file"] == b0.file and r["line"] == b0.line and r["kind"] == ("WARN" if b0.warn else "BUG")
    assert r["function"] == (elf.func(b0.addr) or None), r
assert all(r["kind"] in ("likely", "unlikely") and r["now"] in ("jump", "no jump") and r["key"] for r in js["jump"])
print("OK headless --json: %d BUG/WARN, %d static-key, %d exception-table records" % (len(js["bug"]), len(js["jump"]), len(js["ex"])))
# with a (fake) Hex-Rays decompiler: one decompile check line after the counts, naming a function that stopped
# decompiling after Annotate
hx = types.ModuleType("ida_hexrays")
hx.init_hexrays_plugin = lambda flags=0: True
dc = T.add_decompiler(hx, IL.annotated)
sys.modules["ida_hexrays"] = hx
w["func_of"] = T._funcs(elf)  # IDA's functions: the ELF's function symbols
from kflow import selfcheck as SC  # noqa: E402
picked = SC.pick_functions(IL.scan(), IL.current_arch())
assert picked or not elf.funcs or not IL.scan()["jump"], "a kernel with functions and static keys has functions to check"
if picked:
    dc["after"] = {picked[0]}
out = io.StringIO()
with contextlib.redirect_stdout(out):
    assert H.main([sys.argv[1]]) == 0
lines = [x for x in out.getvalue().splitlines() if "decompile check" in x]
assert len(lines) == 1 and lines[0].startswith("[kflow] decompile check: "), out.getvalue()
if picked:
    assert ("1 of %d functions decompiled before Annotate but fails after" % len(picked)) in lines[0], lines
    assert "run with --remove to take them out" in lines[0] and "kflow: Remove annotations" not in lines[0], lines
with contextlib.redirect_stdout(io.StringIO()):
    assert H.main([sys.argv[1], "--remove"]) == 0
first_line = lines[0]


def headless_check_line(argv):
    o = io.StringIO()
    with contextlib.redirect_stdout(o):
        assert H.main(argv) == 0
    got = [x for x in o.getvalue().splitlines() if "decompile check" in x]
    assert len(got) == 1, o.getvalue()
    return got[0]


# re-review s175 code NIT 1 / claims NIT 5: headless skip lines give headless steps, not menu actions
auto_ok[0] = False  # --no-analysis on a fresh file: IDA's auto-analysis did not run
line = headless_check_line([sys.argv[1], "--no-analysis"])
auto_ok[0] = True
assert line.startswith("[kflow] decompile check skipped: ") and "--no-analysis" in line and "--remove" in line, line
assert "Remove annotations" not in line and "Annotate again" not in line and "still running" not in line, line
line = headless_check_line([sys.argv[1]])  # kflow's references from the previous run are still in the database
assert line.startswith("[kflow] decompile check skipped: ") and "--remove" in line, line
assert "Remove annotations" not in line and "Annotate again" not in line, line
with contextlib.redirect_stdout(io.StringIO()):
    assert H.main([sys.argv[1], "--remove"]) == 0
sys.modules["ida_hexrays"] = None
w.pop("func_of")
print("OK headless decompile check: %s" % first_line)
assert not dialogs, dialogs
print("OK headless: annotate + remove, database saved both times")
