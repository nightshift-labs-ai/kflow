"""Synthetic tables: python3 tests/test_core.py"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from kflow.core import decode_bug_table, decode_ex_table, decode_jump_table  # noqa: E402

BASE = 0xFFFFFFFF81000000


class Mem:
    def __init__(self):
        self.buf = bytearray(0x4000)

    def put(self, ea, raw):
        self.buf[ea - BASE:ea - BASE + len(raw)] = raw

    def read(self, ea, n):
        o = ea - BASE
        if o < 0 or o >= len(self.buf):
            return None
        return bytes(self.buf[o:o + n])


class Tables(unittest.TestCase):
    def test_bug_12(self):
        m = Mem()
        m.put(BASE + 0x1FFF, b"\0mm/slub.c\0")
        tab = BASE + 0x1000
        # entry 0: WARN at BASE+0x100, line 77, taint 9; entry 1: BUG at BASE+0x200 line 5
        for k, (addr, line, flags) in enumerate([(BASE + 0x100, 77, 0x901), (BASE + 0x200, 5, 0)]):
            ea = tab + 12 * k
            m.put(ea, struct.pack("<iiHH", addr - ea, BASE + 0x2000 - (ea + 4), line, flags))
        layout, sites = decode_bug_table(m.read, tab, tab + 24)
        self.assertEqual(layout, "addr,file,line,flags")
        self.assertEqual([(s.addr, s.where(), s.warn, s.taint) for s in sites],
                         [(BASE + 0x100, "mm/slub.c:77", True, 9), (BASE + 0x200, "mm/slub.c:5", False, 0)])

    def test_bug_12_entry_relative_before_5_19(self):
        # before Linux 5.19 file_disp counts from the start of the entry, not from the field
        m = Mem()
        m.put(BASE + 0x1FFF, b"\0kernel/workqueue.c\0")
        tab = BASE + 0x1000
        for k in range(3):
            ea = tab + 12 * k
            m.put(ea, struct.pack("<iiHH", BASE + 0x100 + k - ea, BASE + 0x2000 - ea, 10 + k, 1))
        layout, sites = decode_bug_table(m.read, tab, tab + 36)
        self.assertEqual(layout, "addr,file,line,flags (entry-relative)")
        self.assertEqual([s.where() for s in sites], ["kernel/workqueue.c:%d" % (10 + k) for k in range(3)])

    def test_bug_16_format_layout(self):
        m = Mem()
        m.put(BASE + 0x1FFF, b"\0kernel/fork.c\0")
        tab = BASE + 0x1000
        ea = tab
        m.put(ea, struct.pack("<iiiHH", BASE + 0x300 - ea, 0, BASE + 0x2000 - (ea + 8), 42, 1))
        ea = tab + 16
        m.put(ea, struct.pack("<iiiHH", BASE + 0x310 - ea, 0, BASE + 0x2000 - (ea + 8), 43, 1))
        # 32 bytes also fits the 8-byte layout; the file strings decide
        layout, sites = decode_bug_table(m.read, tab, tab + 32)
        self.assertEqual(layout, "addr,format,file,line,flags")
        self.assertEqual([s.where() for s in sites], ["kernel/fork.c:42", "kernel/fork.c:43"])

    def test_jump(self):
        m = Mem()
        tab = BASE + 0x1000
        key = BASE + 0x3000
        m.put(tab, struct.pack("<iiq", BASE + 0x100 - tab, BASE + 0x180 - (tab + 4), (key - (tab + 8)) | 1))
        (j,) = decode_jump_table(m.read, tab, tab + 16)
        self.assertEqual((j.code, j.target, j.key, j.branch, j.init), (BASE + 0x100, BASE + 0x180, key, True, False))

    def test_ex(self):
        m = Mem()
        tab = BASE + 0x1000
        m.put(tab, struct.pack("<iii", BASE + 0x100 - tab, BASE + 0x110 - (tab + 4), 3))
        layout, (x,) = decode_ex_table(m.read, tab, tab + 12)
        self.assertEqual((layout, x.insn, x.fixup, x.type_name()), ("insn,fixup,data", BASE + 0x100, BASE + 0x110, "UACCESS"))
        self.assertEqual(x.type_name("aarch64"), "KACCESS_ERR_ZERO")  # same number, arm64 meaning
        self.assertEqual(x.type_name("riscv"), "type 3")

    def test_ex_8_byte_layout_by_sort_order(self):
        # arm64 before 5.16: {int insn, fixup}; 6 entries = 48 bytes also fit 4 x 12
        m = Mem()
        tab = BASE + 0x1000
        for k in range(6):
            ea = tab + 8 * k
            m.put(ea, struct.pack("<ii", BASE + 0x100 + 0x40 * k - ea, BASE + 0x800 + 8 * k - (ea + 4)))
        layout, xs = decode_ex_table(m.read, tab, tab + 48)
        self.assertEqual(layout, "insn,fixup")
        self.assertEqual([x.insn for x in xs], [BASE + 0x100 + 0x40 * k for k in range(6)])
        self.assertEqual(xs[0].type_name(), "-")

    def test_bad_sizes(self):
        m = Mem()
        with self.assertRaises(ValueError):
            decode_jump_table(m.read, BASE, BASE + 10)
        with self.assertRaises(ValueError):
            decode_ex_table(m.read, BASE, BASE + 13)


if __name__ == "__main__":
    unittest.main()
