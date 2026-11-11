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
import kflow_headless as H  # noqa: E402

assert H.main([sys.argv[1]]) == 0
assert any(c.startswith("kflow: ") for c in w["cmts"].values())
assert H.main([sys.argv[1], "--remove", "--no-analysis"]) == 0
assert calls == [("open", True), ("close", True), ("open", False), ("close", True)], calls
assert not any(c.startswith("kflow") for c in w["cmts"].values())
assert not any(w["xrefs"].values())  # no user references left
print("OK headless: annotate + remove, database saved both times")
