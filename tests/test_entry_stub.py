"""Loads kflow_entry.py (the IDA plugin) on fake ida_* modules backed by a kernel ELF and runs its three actions.
Usage: python3 tests/test_entry_stub.py <kernel.elf>   (SKIPs without a path)"""
import importlib
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
if len(sys.argv) < 2:
    print("SKIP: pass a kernel ELF path")
    sys.exit(0)
import test_ida_stub as T  # noqa: E402
from kflow.cli import Elf  # noqa: E402

elf = Elf(sys.argv[1])
w = T.world_from(elf)
T.install(w)
log = []
kw = types.ModuleType("ida_kernwin")
kw.msg = lambda text: log.append(("msg", text))
kw.warning = lambda text: log.append(("warning", text))
kw.show_wait_box = lambda text: log.append(("wait", text))
kw.hide_wait_box = lambda: log.append(("hide", None))
kw.jumpto = lambda ea: log.append(("jump", ea)) or True
kw.AST_ENABLE_ALWAYS, kw.SETMENU_APP = 1, 0
kw.register_action = lambda desc: log.append(("reg", desc.name)) or True
kw.unregister_action = lambda name: log.append(("unreg", name)) or True
kw.attach_action_to_menu = lambda path, name, flags: True
kw.process_ui_action = lambda name: log.append(("ui", name)) or True


class action_handler_t:
    pass


class action_desc_t:
    def __init__(self, name, label, handler, *rest):
        self.name, self.label, self.handler = name, label, handler


class Choose:
    CHCOL_HEX, NOTHING_CHANGED = 1, 0

    def __init__(self, title, cols, flags=0):
        self.title, self.cols = title, cols

    def Show(self):
        log.append(("show", self.title, self.OnGetSize()))
        return 0


kw.action_handler_t, kw.action_desc_t, kw.Choose = action_handler_t, action_desc_t, Choose
fn = types.ModuleType("ida_funcs")
fn.get_func_name = lambda ea: elf.func(ea) or ""
api = sys.modules["ida_idaapi"]


class plugin_t:
    pass


api.plugin_t, api.PLUGIN_KEEP = plugin_t, 1
sys.modules.update({"ida_kernwin": kw, "ida_funcs": fn})
sys.path.insert(0, os.path.join(HERE, ".."))
sys.modules.pop("kflow_entry", None)
m = importlib.import_module("kflow_entry")
p = m.PLUGIN_ENTRY()
assert p.init() == 1 and [x[1] for x in log if x[0] == "reg"] == ["kflow:annotate", "kflow:list", "kflow:keys", "kflow:remove"]
assert m.AnnotateAction().activate(None) == 1
assert any(c.startswith("kflow: ") for c in w["cmts"].values())
assert ("hide", None) in log and not [x for x in log if x[0] == "warning"], log[-3:]
assert m.ListAction().activate(None) == 1
shown = [x for x in log if x[0] == "show"]
assert shown and shown[0][2] == len(m.STATE["tables"]["bug"]), shown
ch = m.SitesChooser([(0x10, "0x10", "WARN", "f", "a.c:1")])
assert ch.OnGetLine(0) == ("0x10", "WARN", "f", "a.c:1") and ch.OnSelectLine(0) == (0,) and ("jump", 0x10) in log
keys = m.KeySitesAction().activate(None)
jumps = m.STATE["tables"]["jump"]
if jumps:
    assert keys == 1, keys
    kshown = [x for x in log if x[0] == "show"][-1]
    assert kshown[1] == "kflow: static-key sites" and kshown[2] == len(jumps), kshown
    rows = m.key_site_rows(m.STATE["tables"])
    j = jumps[0]
    assert rows[0][0] == j.code and rows[0][3] == ("likely" if j.branch else "unlikely") and rows[0][4] in ("jump", "no jump")
    nj = sum(r[4] == "jump" for r in rows)
    assert 0 < nj < len(rows) or len(rows) < 50, nj  # real kernels have both states
else:
    assert keys == 0
assert m.RemoveAction().activate(None) == 1
assert not any(c.startswith("kflow") for c in w["cmts"].values())
# a database that is not a supported kernel: one warning, nothing written
sys.modules["ida_ida"].inf_is_64bit = lambda: False
m.STATE["tables"] = None
assert m.AnnotateAction().activate(None) == 0 and "not a 64-bit" in [x for x in log if x[0] == "warning"][-1][1]
p.term()
assert [x[1] for x in log if x[0] == "unreg"] == ["kflow:annotate", "kflow:list", "kflow:keys", "kflow:remove"]
print("OK entry: plugin loads, Annotate / List (%d rows) / List static keys (%d rows) / Remove run, unsupported database warned" % (shown[0][2], len(jumps)))
