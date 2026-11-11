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
assert not t["missing"] or t["missing"] == ["jump"], t["missing"]  # stripped vmlinux: no jump table symbols
bugs, jumps, exs = t["bug"], t.get("jump", []), t["ex"]
# every enabled jump-label site (x86 jmp rel8/rel32, arm64 b) must land on the decoded target
checked = 0
for j in jumps:
    if j.init:
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
assert checked > 0 or not jumps
# every bug entry that names a file has a line; WARN/BUG sites that are not freed init text are ud2
for b in bugs:
    assert (b.file is None) == (b.line is None)
    trap = b"\x00\x00\x21\xd4" if e.arch == "aarch64" else b"\x0f\x0b"
    code = e.read(b.addr, len(trap))
    assert code in (trap, bytes(len(trap))) or not e.func(b.addr), (hex(b.addr), code.hex())
# MSR fixups point at wrmsr/rdmsr unless the bytes were freed (init text)
for x in exs:
    code = e.read(x.insn, 2)
    if x.type_name() == "WRMSR" and code != b"\x0f\x30":
        assert not e.func(x.insn) or code[:1] != b"\x0f", hex(x.insn)
print("OK: %d bug sites (%d WARN), %d jump sites (%d enabled checked), %d ex sites"
      % (len(bugs), sum(b.warn for b in bugs), len(jumps), checked, len(exs)))
