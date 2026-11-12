#!/usr/bin/env python3
"""Check every ida_* name kflow uses against the official IDAPython stubs, plus the object members and the
signatures/return shapes the Hex-Rays pseudocode hook relies on.

    python3 tests/check_ida_api.py <dir containing ida_*.pyi>

It proves the names exist, not that the calls behave as intended in IDA.
"""
import ast
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FILES = ["kflow/idalayer.py"] + [f for f in ("kflow_entry.py",) if os.path.exists(os.path.join(ROOT, f))]


def dotted(n):
    p = []
    while isinstance(n, ast.Attribute):
        p.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        p.append(n.id)
        return list(reversed(p))


if len(sys.argv) < 2:
    print("usage: check_ida_api.py <stub dir>")
    sys.exit(2)
missing = checked = 0
for f in FILES:
    tree = ast.parse(open(os.path.join(ROOT, f)).read())
    seen = {tuple(d[:3]) for d in (dotted(n) for n in ast.walk(tree) if isinstance(n, ast.Attribute)) if d and d[0].startswith("ida_")}
    for d in sorted(seen):
        if any(o != d and o[:len(d)] == d for o in seen):
            continue
        src = open(os.path.join(sys.argv[1], d[0] + ".pyi")).read()
        for name in d[1:]:
            checked += 1
            if not re.search(r"(?:def|class)\s+%s\b|^\s*%s\s*:" % (name, name), src, re.M):
                print("MISSING", ".".join(d))
                missing += 1
# members used on objects (xrefblk_t iteration, segment_t fields)
MEMBERS = [("ida_xref", "xrefblk_t", m) for m in ("first_from", "next_from", "to", "iscode", "user")] + \
    [("ida_segment", "segment_t", m) for m in ("start_ea", "end_ea", "perm", "type")] + \
    [("ida_netnode", "netnode", m) for m in ("altset", "altval", "altfirst", "altnext", "index", "kill")] + \
    [("ida_kernwin", "Choose", m) for m in ("Show", "CHCOL_HEX", "NOTHING_CHANGED")] + \
    [("ida_hexrays", "Hexrays_Hooks", m) for m in ("func_printed", "hook", "unhook")] + \
    [("ida_hexrays", "cfunc_t", m) for m in ("get_eamap", "get_pseudocode", "find_item_coords", "entry_ea")] + \
    [("ida_hexrays", "eamap_t", m) for m in ("__iter__", "__getitem__")] + [("ida_hexrays", "cinsnptrvec_t", "__iter__")] + \
    [("ida_pro", "strvec_t", m) for m in ("__getitem__", "__len__")] + [("ida_kernwin", "simpleline_t", "line")] + \
    [("ida_funcs", "func_t", "start_ea")]
for mod, cls, name in MEMBERS:
    checked += 1
    src = open(os.path.join(sys.argv[1], mod + ".pyi")).read()
    body = re.search(r"^class %s\b.*?(?=^class |\Z)" % cls, src, re.M | re.S)
    if not body or not re.search(r"(?:def\s+%s\b|^\s+%s\s*:)" % (name, name), body.group(0), re.M):
        print("MISSING", "%s.%s.%s" % (mod, cls, name))
        missing += 1
# signatures and return shapes the pseudocode hook relies on (the hook returns 0; coords are (x, y))
SHAPES = [("ida_hexrays", r"def func_printed\(self, cfunc: cfunc_t\) -> int:"),
          ("ida_hexrays", r"find_item_coords\(item: citem_t\) -> Tuple\[int, int\]"),
          ("ida_hexrays", r"def get_eamap\(self\) -> eamap_t:"), ("ida_hexrays", r"def get_pseudocode\(self\) -> strvec_t:"),
          ("ida_hexrays", r"def __getitem__\(self, i: int\) -> cinsn_t:"),
          ("ida_hexrays", r"def clear_cached_cfuncs\(\) -> None:"), ("ida_hexrays", r"def init_hexrays_plugin\(flags: int = 0\) -> bool:"),
          ("ida_pro", r"def __getitem__\(self, i: int\) -> simpleline_t:"), ("ida_lines", r"def COLSTR\(str: Any, tag: Any\)"),
          ("ida_funcs", r"def get_func\(ea: ida_idaapi.ea_t\) -> Optional\[func_t\]:"),
          ("ida_segment", r"def get_segm_qty\(\) -> int:"), ("ida_segment", r"def getnseg\(n: int\) -> Optional\[segment_t\]:")]
for mod, pattern in SHAPES:
    checked += 1
    if not re.search(pattern, open(os.path.join(sys.argv[1], mod + ".pyi")).read()):
        print("MISSING", mod, pattern)
        missing += 1
print("checked", checked, "missing", missing)
sys.exit(1 if missing else 0)
