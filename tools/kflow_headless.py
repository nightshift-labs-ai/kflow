#!/usr/bin/env python3
"""kflow without the IDA window, through idalib (IDA 9.0 or newer).

    python3 tools/kflow_headless.py <vmlinux or kernel ELF, or an existing database> [--no-analysis] [--remove]
                                    [--json sites.json]

Opens the file as an IDA database and does what kflow: Annotate kernel sites does (comments at every BUG/WARN,
static-key and exception-table site; jump references where IDA has none); --remove takes kflow's comments and
references out again. Prints the counts and saves the database. --json also writes every decoded site with IDA's
function names (addresses as hex strings, read before Annotate/Remove change anything): bug [{addr, kind WARN|BUG,
function, file, line}], jump [{addr, key, kind likely|unlikely, now jump|no jump, target, function}], ex [{addr,
fixup, type (or null), handler (or null), function}]. It calls the plugin's own kflow.idalayer
functions. Not yet run with a real idalib: we have no IDA licence. Without IDA at all, `python3 -m kflow <file>`
decodes the same tables.

idalib setup (from Hex-Rays): install the idapro wheel shipped in <IDA>/idalib/python and run its
py-activate-idalib.py once, or set IDADIR to your IDA folder.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def site_records(t, arch, path):
    """Every decoded site as plain data with IDA's names, for --json."""
    import ida_funcs
    from kflow import idalayer
    names = {}

    def h(ea):
        return None if ea is None else "0x%X" % ea

    def fn(ea):
        return ida_funcs.get_func_name(ea) or None
    return {
        "input": os.path.basename(path),
        "bug_layout": t.get("bug_layout"),
        "missing": list(t["missing"]),
        "errors": {k: str(v) for k, v in t.get("errors", {}).items()},   # a table found but not decoded (its list is empty)
        "bug": [{"addr": h(b.addr), "kind": "WARN" if b.warn else "BUG", "function": fn(b.addr), "file": b.file,
                 "line": b.line} for b in t["bug"]],
        "jump": [{"addr": h(j.code), "key": idalayer.site_key_name(j, names), "kind": "likely" if j.branch else "unlikely",
                  "now": "jump" if idalayer.branches_to(j.code, j.target, arch) else "no jump", "target": h(j.target),
                  "function": fn(j.code)} for j in t["jump"]],
        "ex": [{"addr": h(x.insn), "fixup": h(x.fixup), "type": None if x.data is None else x.type_name(arch),
                "handler": h(x.handler), "function": fn(x.insn)} for x in t["ex"]],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Apply kflow to a kernel with idalib (no IDA window).")
    parser.add_argument("input", help="kernel file to open in IDA (vmlinux, kernel ELF, or an existing database)")
    parser.add_argument("--no-analysis", action="store_true", help="skip IDA's auto-analysis (faster)")
    parser.add_argument("--remove", action="store_true", help="remove kflow's comments and references instead of adding them")
    parser.add_argument("--json", metavar="PATH", help="also write every decoded site with IDA's function names to PATH")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.input):
        parser.error("no such file: %s" % args.input)
    try:
        import idapro  # must be imported before any ida_* module
    except ImportError as error:
        print("kflow_headless: idalib is not available (%s). It needs IDA 9.0 or newer; see the top of this file." % error, file=sys.stderr)
        return 2
    if idapro.open_database(args.input, not args.no_analysis) != 0:
        print("kflow_headless: IDA could not open %s" % args.input, file=sys.stderr)
        return 1
    try:
        from kflow import idalayer
        arch = idalayer.current_arch()
        if arch is None:
            print("kflow_headless: not a 64-bit x86_64 or aarch64 database", file=sys.stderr)
            return 3
        try:
            t = idalayer.scan()
        except ValueError as error:
            print("kflow_headless: %s" % error, file=sys.stderr)
            return 3
        print("[kflow] BUG/WARN %d (%s), static-key %d, exception-table %d; not found: %s%s"
              % (len(t["bug"]), t.get("bug_layout") or "-", len(t["jump"]), len(t["ex"]), ", ".join(t["missing"]) or "none",
                 idalayer.not_decoded(t)))
        if args.json:
            with open(args.json, "w") as fh:
                json.dump(site_records(t, arch, args.input), fh, indent=1)
            print("[kflow] sites written to %s" % args.json)
        if args.remove:
            res = {}
            removed = idalayer.remove_annotations(t, res)
            print("[kflow] references removed: %d jump references, %d static-key site -> key references, %d data references"
                  " to targets inside another function" % (removed, res["key_refs"], res["other_refs"]))
        else:
            import ida_auto  # an existing database opened with --no-analysis may be fully analysed already
            from kflow import selfcheck
            check = selfcheck.start(t, arch, headless=True)  # with Hex-Rays: decompile a few functions before and after Annotate
            res = idalayer.annotate(t, arch)
            line = selfcheck.finish(check)
            print("[kflow] %s" % idalayer.annotate_text(res, analysis_done=ida_auto.auto_is_ok()))
            if line:
                print("[kflow] %s" % line)
            if args.no_analysis:
                print("[kflow] --no-analysis: IDA has not made the instructions and functions yet, so references were "
                      "added only from sites that are instructions already, and targets inside other functions kept jump "
                      "references; run again without --no-analysis to add the rest and change those")
        return 0
    finally:
        idapro.close_database(True)


if __name__ == "__main__":
    sys.exit(main())
