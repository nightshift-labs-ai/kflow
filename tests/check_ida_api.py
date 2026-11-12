#!/usr/bin/env python3
"""Check every ida_* name kflow uses against the official IDAPython stubs, plus the object members and the
signatures/return shapes the Hex-Rays pseudocode hook and WARN fall-through rely on.

    python3 tests/check_ida_api.py <dir containing ida_*.pyi>

It proves the names exist, not that the calls behave as intended in IDA.
"""
import ast
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FILES = ["kflow/idalayer.py"] + [f for f in ("kflow_entry.py", "kflow/warnflow.py") if os.path.exists(os.path.join(ROOT, f))]


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
    [("ida_funcs", "func_t", m) for m in ("start_ea", "end_ea", "owner")] + \
    [("ida_ua", "insn_t", m) for m in ("ea", "size", "itype", "add_cref")] + \
    [("ida_idp", "IDP_Hooks", m) for m in ("__init__", "hook", "unhook", "ev_emu_insn")] + \
    [("ida_hexrays", "udc_filter_t", m) for m in ("__init__", "init", "match")] + [("ida_hexrays", "codegen_t", "insn")]
for mod, cls, name in MEMBERS:
    checked += 1
    src = open(os.path.join(sys.argv[1], mod + ".pyi")).read()
    body = re.search(r"^class %s\b.*?(?=^class |\Z)" % cls, src, re.M | re.S)
    if not body or not re.search(r"(?:def\s+%s\b|^\s+%s\s*:)" % (name, name), body.group(0), re.M):
        print("MISSING", "%s.%s.%s" % (mod, cls, name))
        missing += 1
# signatures and return shapes the pseudocode hook relies on (the hook returns 0; coords are (x, y)); a class name
# limits the search to that class's body, None to the whole module (^ matches at a line start)
SHAPES = [("ida_hexrays", "Hexrays_Hooks", r"def func_printed\(self, cfunc: cfunc_t\) -> int:"),
          ("ida_hexrays", "cfunc_t", r"find_item_coords\(item: citem_t\) -> Tuple\[int, int\]"),
          ("ida_hexrays", "cfunc_t", r"def get_eamap\(self\) -> eamap_t:"),
          ("ida_hexrays", "cfunc_t", r"def get_pseudocode\(self\) -> strvec_t:"),
          ("ida_hexrays", "cinsnptrvec_t", r"def __getitem__\(self, i: int\) -> cinsn_t:"),
          ("ida_hexrays", None, r"def clear_cached_cfuncs\(\) -> None:"),
          ("ida_hexrays", None, r"def init_hexrays_plugin\(flags: int = 0\) -> bool:"),
          ("ida_pro", "strvec_t", r"def __getitem__\(self, i: int\) -> simpleline_t:"), ("ida_lines", None, r"def COLSTR\(str: Any, tag: Any\)"),
          ("ida_funcs", None, r"def get_func\(ea: ida_idaapi.ea_t\) -> Optional\[func_t\]:"),
          ("ida_segment", None, r"def get_segm_qty\(\) -> int:"), ("ida_segment", None, r"def getnseg\(n: int\) -> Optional\[segment_t\]:"),
          # WARN fall-through (kflow/warnflow.py): the hook, flow flags, reanalysis, function tails, the microcode filter
          ("ida_idp", "IDP_Hooks", r"def __init__\(self, _flags: int = 0, _hkcb_flags: int = 1\)"),
          ("ida_idp", "IDP_Hooks", r"def ev_emu_insn\(self, insn: insn_t\) -> bool:"),
          ("ida_idp", None, r"def has_insn_feature\(icode: int, bit: int\) -> bool:"),
          ("ida_idp", None, r"^CF_STOP: int"), ("ida_allins", None, r"^NN_ud2: int  # 632"), ("ida_allins", None, r"^ARM_brk: int"),
          ("ida_ua", "insn_t", r"def add_cref\(self, to: ida_idaapi.ea_t, opoff: int, type: cref_t\) -> None:"),
          ("ida_xref", None, r"^fl_F: int  # 21"), ("ida_auto", None, r"def plan_ea\(ea: ida_idaapi.ea_t\) -> None:"),
          ("ida_auto", None, r"def auto_wait\(\) -> bool:"), ("ida_bytes", None, r"def get_flags\(ea: ida_idaapi.ea_t\) -> int:"),
          ("ida_bytes", None, r"def is_flow\(F: int\) -> bool:"), ("ida_bytes", None, r"def is_code\(F: int\) -> bool:"),
          ("ida_funcs", None, r"def append_func_tail\(pfn: func_t, ea1: ida_idaapi.ea_t, ea2: ida_idaapi.ea_t\) -> bool:"),
          ("ida_funcs", None, r"def remove_func_tail\(pfn: func_t, tail_ea: ida_idaapi.ea_t\) -> bool:"),
          ("ida_funcs", None, r"def get_fchunk\(ea: ida_idaapi.ea_t\) -> Optional\[func_t\]:"),
          ("ida_funcs", None, r"def get_next_fchunk\(ea: ida_idaapi.ea_t\) -> Optional\[func_t\]:"),
          ("ida_funcs", None, r"def is_func_tail\(pfn: func_t\) -> bool:"),
          ("ida_funcs", None, r"def reanalyze_function\(\*args: Any\) -> None:"),
          ("ida_hexrays", None, r"^class udc_filter_t\(microcode_filter_t\):"),
          ("ida_hexrays", "udc_filter_t", r"def init\(self, decl: str\) -> bool:"),
          ("ida_hexrays", "udc_filter_t", r"def match\(self, cdg: codegen_t\) -> bool:"),
          ("ida_hexrays", None, r"def install_microcode_filter\(filter: microcode_filter_t, install: bool = True\) -> bool:"),
          ("ida_kernwin", None, r"def info\(message: str\) -> int:"),
          # Go to oops/WARN line: the multi-line text dialog, the jump, and IDA's name list for name.<suffix>
          ("ida_kernwin", None, r"def ask_text\(max_size: int, defval: str, prompt: str\) -> Union\[str, None\]:"),
          ("ida_kernwin", None, r"def jumpto\(ea: ida_idaapi.ea_t, opnum: int = -1"),
          ("ida_name", None, r"def get_name_ea\(_from: ida_idaapi.ea_t, name: str\) -> ida_idaapi.ea_t:"),
          ("ida_name", None, r"def get_nlist_name\(idx: int\) -> str:"),
          ("ida_name", None, r"def get_nlist_ea\(idx: int\) -> ida_idaapi.ea_t:")]
for mod, cls, pattern in SHAPES:
    checked += 1
    src = open(os.path.join(sys.argv[1], mod + ".pyi")).read()
    if cls is not None:
        body = re.search(r"^class %s\b.*?(?=^class |\Z)" % cls, src, re.M | re.S)
        src = body.group(0) if body else ""
    if not re.search(pattern, src, re.M):
        print("MISSING", mod, cls or "", pattern)
        missing += 1
print("checked", checked, "missing", missing)
sys.exit(1 if missing else 0)
