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
print("OK headless: annotate + remove, database saved both times")
