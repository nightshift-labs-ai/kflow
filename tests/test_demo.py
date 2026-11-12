"""Invariants on a real kernel ELF (e.g. the MemLens demo kernel.elf, Debian 6.12).
Usage: python3 tests/test_demo.py <kernel.elf>   (SKIPs without a path)"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from kflow.cli import Elf, load  # noqa: E402

if len(sys.argv) < 2:
    print("SKIP: pass a kernel ELF path")
    sys.exit(0)
e = Elf(sys.argv[1])
t = load(e)
if e.relocatable and len(t["missing"]) == 3:
    print("SKIP: this module has none of the three tables")
    sys.exit(0)
# stripped vmlinux: no jump table symbols; a module (.ko) has only the tables its code needs
assert not t["missing"] or t["missing"] == ["jump"] or (e.relocatable and set(t["missing"]) < {"bug", "jump", "ex"}), \
    t["missing"]
assert not t.get("errors"), t["errors"]
bugs, jumps, exs = t.get("bug", []), t.get("jump", []), t.get("ex", [])
# every enabled jump-label site (x86 jmp rel8/rel32, arm64 b) must land on the decoded target
checked = 0
ib, ie = e.symbols.get("__init_begin"), e.symbols.get("__init_end")


def in_init(ea):
    # bit 1 of the key means "init" only in a running kernel (on disk x86 objtool uses it as a NOP marker)
    return ib <= ea < ie if ib and ie else False


for j in jumps:
    if in_init(j.code):
        continue  # init text is freed after boot (memory images hold other bytes there)
    if e.arch == "aarch64":
        w = int.from_bytes(e.read(j.code, 4), "little")
        if w >> 26 == 0b000101:
            imm = w & 0x3FFFFFF
            imm -= (1 << 26) if imm & (1 << 25) else 0
            assert j.code + 4 * imm == j.target, hex(j.code)
            checked += 1
        else:
            assert w == 0xD503201F, (hex(j.code), hex(w))
        continue
    b = e.read(j.code, 5)
    if b[0] == 0xE9:
        assert j.code + 5 + int.from_bytes(b[1:5], "little", signed=True) == j.target, hex(j.code)
        checked += 1
    elif b[0] == 0xEB:
        assert j.code + 2 + int.from_bytes(b[1:2], "little", signed=True) == j.target, hex(j.code)
        checked += 1
    else:
        assert b in (bytes.fromhex("0f1f440000"), bytes(5)) or b[:2] == b"\x66\x90", (hex(j.code), b.hex())
# a module's sites are often all NOPs on disk (tracepoints are static_branch_unlikely): then every target must lie in
# the same function as its site
assert checked > 0 or not jumps or (e.relocatable and all(e.func(j.code) and e.func(j.code) == e.func(j.target)
                                                          for j in jumps)), checked
# file names are real kernel paths (a wrong pointer base gives cut names such as "el/workqueue.c")
TOP = ("arch/", "kernel/", "mm/", "fs/", "net/", "drivers/", "include/", "lib/", "block/", "crypto/", "security/",
       "sound/", "virt/", "init/", "ipc/", "io_uring/", "certs/", "rust/", "usr/", "samples/", "./", "/")
named = [b for b in bugs if b.file]
assert len(named) >= 0.95 * len(bugs), (len(named), len(bugs))
good = sum(1 for b in named if b.file.startswith(TOP))
assert good >= 0.95 * len(named), (good, len(named), [b.file for b in named if not b.file.startswith(TOP)][:5])
# every bug entry that names a file has a line; WARN/BUG sites that are not freed init text are ud2
for b in bugs:
    assert (b.file is None) == (b.line is None)
    trap = b"\x00\x00\x21\xd4" if e.arch == "aarch64" else b"\x0f\x0b"
    code = e.read(b.addr, len(trap))
    if b.args:  # Linux 6.19+ x86_64 WARN with a message: a call to the WARN trap, not ud2
        continue
    assert code in (trap, bytes(len(trap))) or not e.func(b.addr), (hex(b.addr), code.hex())
# MSR fixups point at wrmsr/rdmsr unless the bytes were freed (init text)
for x in exs:
    code = e.read(x.insn, 2)
    if x.type_name() == "WRMSR" and code != b"\x0f\x30":
        assert not e.func(x.insn) or code[:1] != b"\x0f", hex(x.insn)
# x86_64 before 5.16: the third field is a handler function; with symbols, they are the kernel's ex_handler_*
hs = [x for x in exs if x.handler is not None]
if e.arch == "x86_64" and "ex_handler_default" in e.symbols:  # handler-pointer kernel: the layout must be detected
    assert exs and len(hs) == len(exs), (len(hs), len(exs))
if hs and e.by_addr:
    names = [e.by_addr.get(x.handler, "") for x in hs]
    assert sum(n.startswith("ex_handler_") for n in names) >= 0.95 * len(hs), sorted(set(names))[:5]
    for x, n in zip(hs, names):
        if "msr" in n and e.func(x.insn):  # ex_handler_{rd,wr}msr_{unsafe,fault}
            assert e.read(x.insn, 2) == (b"\x0f\x30" if "wrmsr" in n else b"\x0f\x32"), (hex(x.insn), n)
    print("  handler entries: %d of %d point at an ex_handler_* function (%s)"
          % (sum(n.startswith("ex_handler_") for n in names), len(hs), ", ".join(sorted(set(names)))))
print("OK: %d bug sites (%d WARN), %d jump sites (%d enabled checked), %d ex sites"
      % (len(bugs), sum(b.warn for b in bugs), len(jumps), checked, len(exs)))
