#!/usr/bin/env python3
"""Name-only check for older IDA versions: every ida_*.name kflow's code uses exists in a folder of IDAPython
stubs (ida_*.pyi), for example those of the idapro package of an older IDA (PyPI idapro 0.0.5, 0.0.7, 0.0.9 and
0.0.11 carry the stubs of IDA SDK 9.1, 9.2, 9.3 and 9.4). tests/check_ida_api.py checks the latest stubs in more
detail (members and signatures); this one only asks whether each name is there at all.

    python3 tests/check_ida_names.py <dir containing ida_*.pyi> [more dirs...]
"""
import ast
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FILES = ["kflow/idalayer.py", "kflow/warnflow.py", "kflow_entry.py", "tools/kflow_headless.py"]


def used_names():
    out = {}
    for f in FILES:
        p = os.path.join(ROOT, f)
        if not os.path.exists(p):
            continue
        for node in ast.walk(ast.parse(open(p).read())):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id.startswith("ida_"):
                out.setdefault((node.value.id, node.attr), set()).add(f)
    return out


def main(dirs):
    if not dirs:
        print(__doc__.strip().splitlines()[-1].strip())
        return 2
    names = used_names()
    bad = 0
    for d in dirs:
        missing = []
        for mod, name in sorted(names):
            path = os.path.join(d, mod + ".pyi")
            src = open(path).read() if os.path.exists(path) else ""
            if not re.search(r"^\s*(def|class)\s+%s\b|^\s*%s\s*[:=]" % (re.escape(name), re.escape(name)), src, re.M):
                missing.append("%s.%s" % (mod, name))
        print("%s: %d names, %d missing%s" % (d, len(names), len(missing), (": " + ", ".join(missing)) if missing else ""))
        bad += bool(missing)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
