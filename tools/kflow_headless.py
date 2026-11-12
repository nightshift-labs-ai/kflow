#!/usr/bin/env python3
"""kflow without the IDA window, through idalib (IDA 9.0 or newer).

    python3 tools/kflow_headless.py <vmlinux or kernel ELF, or an existing database> [--no-analysis] [--remove]

Opens the file as an IDA database and does what kflow: Annotate kernel sites does (comments at every BUG/WARN,
static-key and exception-table site; jump references where IDA has none); --remove takes kflow's comments and
references out again. Prints the counts and saves the database. It calls the plugin's own kflow.idalayer
functions. Not yet run with a real idalib: we have no IDA licence. Without IDA at all, `python3 -m kflow <file>`
decodes the same tables.

idalib setup (from Hex-Rays): install the idapro wheel shipped in <IDA>/idalib/python and run its
py-activate-idalib.py once, or set IDADIR to your IDA folder.
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Apply kflow to a kernel with idalib (no IDA window).")
    parser.add_argument("input", help="kernel file to open in IDA (vmlinux, kernel ELF, or an existing database)")
    parser.add_argument("--no-analysis", action="store_true", help="skip IDA's auto-analysis (faster)")
    parser.add_argument("--remove", action="store_true", help="remove kflow's comments and references instead of adding them")
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
        if args.remove:
            res = {}
            removed = idalayer.remove_annotations(t, res)
            print("[kflow] references removed: %d jump references, %d static-key site -> key references"
                  % (removed, res["key_refs"]))
        else:
            print("[kflow] %s" % idalayer.annotate_text(idalayer.annotate(t, arch)))
        return 0
    finally:
        idapro.close_database(True)


if __name__ == "__main__":
    sys.exit(main())
