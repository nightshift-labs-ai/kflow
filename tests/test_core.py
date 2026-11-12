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

    def test_ex_x86_before_5_16_handler(self):
        m = Mem()
        tab = BASE + 0x1000
        text = (BASE, BASE + 0x800)
        for k in range(3):
            ea = tab + 12 * k
            m.put(ea, struct.pack("<iii", BASE + 0x100 + 0x10 * k - ea, BASE + 0x400 - (ea + 4), BASE + 0x600 - (ea + 8)))
        layout, xs = decode_ex_table(m.read, tab, tab + 36, in_text=lambda a: text[0] <= a < text[1])
        self.assertEqual(layout, "insn,fixup,handler")
        self.assertEqual({x.handler for x in xs}, {BASE + 0x600})
        self.assertTrue(all(x.data is None and x.type_name() == "-" for x in xs))

    def test_bad_sizes(self):
        m = Mem()
        with self.assertRaises(ValueError):
            decode_jump_table(m.read, BASE, BASE + 10)
        with self.assertRaises(ValueError):
            decode_ex_table(m.read, BASE, BASE + 13)


class BugFormat(unittest.TestCase):
    def test_619_without_bugverbose(self):
        # {int addr, int format, u16 flags, pad}: field-relative; formats are messages, not file names
        m = Mem()
        start, text = BASE + 0x2000, lambda ea: BASE <= ea < BASE + 0x1000  # noqa: E731
        m.put(BASE + 0x2FFF, b"\0bad value %d\n\0")
        for k in range(4):
            ea = start + 12 * k
            m.put(ea, struct.pack("<iiHH", BASE + 0x100 + 4 * k - ea, BASE + 0x3000 - (ea + 4), 0x11, 0))
        layout, sites = decode_bug_table(m.read, start, start + 48, in_text=text)
        self.assertEqual(layout, "addr,format,flags")
        self.assertEqual([(s.addr, s.warn, s.args, s.file) for s in sites[:2]],
                         [(BASE + 0x100, True, True, None), (BASE + 0x104, True, True, None)])


class Flags(unittest.TestCase):
    def test_warn_with_message_flag(self):
        from kflow.core import BugSite
        self.assertEqual([(b.warn, b.args) for b in (BugSite(1, flags=0x11), BugSite(1, flags=0x01), BugSite(1, flags=0x0A))],
                         [(True, True), (True, False), (False, False)])


class OldJump(unittest.TestCase):
    def test_absolute_24_byte_entries_rejected(self):
        # Linux 4.19 and older: {u64 code, u64 target, u64 key} absolute. 2 entries = 48 bytes, a multiple of 16.
        m = Mem()
        start = BASE + 0x800
        for k in range(2):
            m.put(start + 24 * k, struct.pack("<QQQ", BASE + 0x100 + k, BASE + 0x180, BASE + 0x3000))
        text = lambda ea: BASE <= ea < BASE + 0x400  # noqa: E731
        with self.assertRaises(ValueError):
            decode_jump_table(m.read, start, start + 48, in_text=text)
        # the same bytes without a code check decode to garbage silently: in_text is what catches it
        self.assertEqual(len(decode_jump_table(m.read, start, start + 48)), 3)


class Keys(unittest.TestCase):
    def test_key_labels(self):
        from kflow.core import key_label
        m = Mem()
        names = {BASE + 0x100: "__tracepoint_sched_switch", BASE + 0x200: "__UNIQUE_ID_ddebug12.3",
                 BASE + 0x300: "my_keys", BASE + 0x400: "plain_key"}
        m.put(BASE + 0x200, struct.pack("<QQQQI", 0, 0, BASE + 0x1000, BASE + 0x1100, 1329 | (5 << 18)))
        m.put(BASE + 0x1000, b"init/main.c\0")
        m.put(BASE + 0x1100, b"  with \"arguments\":\nnext\n\0")
        at = lambda ea: names.get(ea, "")  # noqa: E731
        self.assertEqual(key_label(at, BASE + 0x400, m.read), "plain_key")
        self.assertEqual(key_label(at, BASE + 0x108, m.read), "tracepoint sched_switch")
        self.assertEqual(key_label(at, BASE + 0x228, m.read), "pr_debug init/main.c:1329 \"with 'arguments':\\nnext\"")
        self.assertEqual(key_label(at, BASE + 0x228, None), "__UNIQUE_ID_ddebug12.3+0x28")  # no reader: plain offset
        self.assertEqual(key_label(at, BASE + 0x110, m.read), "__tracepoint_sched_switch+0x10")
        self.assertEqual(key_label(at, BASE + 0x330, m.read), "my_keys+0x30")
        self.assertIsNone(key_label(at, BASE + 0x500, m.read))  # nothing named within 64 bytes


def module_elf(path):
    """A minimal x86_64 relocatable ELF (.ko) with one BUG entry and one static-key entry, both only meaningful
    after relocation: .text = ud2 + 2-byte NOP, .rodata.str = "\\0a/b.c\\0", the key is an undefined symbol."""
    text, rodata = b"\x0f\x0b\x66\x90", b"\0a/b.c\0"
    bug, jump = bytes(12), bytes(32)
    struct_bug = bytearray(bug)
    struct.pack_into("<HH", struct_bug, 8, 42, 1 << 0)  # line 42, BUGFLAG_WARNING
    strtab = b"\0my_key\0__tracepoint_foo\0"
    names = [b"", b".text", b".rodata.str", b"__bug_table", b".rela__bug_table", b"__jump_table",
             b".rela__jump_table", b".symtab", b".strtab", b".shstrtab"]
    shstr = b"\0".join(names) + b"\0"
    off = {n: shstr.index(b"\0" + n + b"\0") + 1 if n else 0 for n in names}
    # symbols: 0 null, 1 section .text, 2 section .rodata.str, 3 undefined __tracepoint_foo, 4 undefined my_key
    # (a core-kernel tracepoint used from a module: its key is __tracepoint_foo + 8, which must not land on my_key)
    sym = bytes(24) + struct.pack("<IBBHQQ", 0, 3, 0, 1, 0, 0) + struct.pack("<IBBHQQ", 0, 3, 0, 2, 0, 0) \
        + struct.pack("<IBBHQQ", 8, 0x10, 0, 0, 0, 0) + struct.pack("<IBBHQQ", 1, 0x10, 0, 0, 0, 0)
    rela = lambda o, s, t, a: struct.pack("<QQq", o, (s << 32) | t, a)  # noqa: E731
    rbug = rela(0, 1, 2, 0) + rela(4, 2, 2, 1)  # PC32: insn -> .text+0, file -> .rodata.str+1
    rjump = rela(0, 1, 2, 2) + rela(4, 1, 2, 4) + rela(8, 4, 24, 0) \
        + rela(16, 1, 2, 2) + rela(20, 1, 2, 4) + rela(24, 3, 24, 8)  # keys: my_key; __tracepoint_foo + 8 (PC64)
    blobs = [b"", text, rodata, bytes(struct_bug), rbug, jump, rjump, sym, strtab, shstr]
    body, offs = b"", []
    for b in blobs:
        body += bytes((-len(body)) % 8)
        offs.append(64 + len(body))
        body += b
    shoff = 64 + len(body) + ((-(64 + len(body))) % 8)
    body += bytes(shoff - 64 - len(body))
    # (name, type, flags, info, link, entsize)
    spec = [(b"", 0, 0, 0, 0, 0), (b".text", 1, 6, 0, 0, 0), (b".rodata.str", 1, 2, 0, 0, 0), (b"__bug_table", 1, 3, 0, 0, 0),
            (b".rela__bug_table", 4, 0x40, 3, 7, 24), (b"__jump_table", 1, 3, 0, 0, 0),
            (b".rela__jump_table", 4, 0x40, 5, 7, 24), (b".symtab", 2, 0, 3, 8, 24), (b".strtab", 3, 0, 0, 0, 0),
            (b".shstrtab", 3, 0, 0, 0, 0)]
    sh = b""
    for i, (n, t, f, info, link, ent) in enumerate(spec):
        sh += struct.pack("<IIQQQQIIQQ", off[n], t, f, 0, offs[i] if i else 0, len(blobs[i]), link, info, 8 if i else 0, ent)
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, shoff, 0, 64, 0, 0,
                                                                   64, len(spec), len(spec) - 1)
    with open(path, "wb") as fh:
        fh.write(hdr + body + sh)


class Module(unittest.TestCase):
    def test_relocated_module(self):
        import tempfile
        from kflow.cli import Elf, load
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "toy.ko")
            module_elf(p)
            e = Elf(p)
            t = load(e)
        self.assertTrue(e.relocatable)
        text = e.sections[".text"][0]
        self.assertEqual(t["missing"], ["ex"])
        (b,) = t["bug"]
        self.assertEqual((b.addr, b.file, b.line, b.warn), (text, "a/b.c", 42, True))
        j, j2 = t["jump"]
        self.assertEqual((j.code, j.target, j.key), (text + 2, text + 4, e.externs["my_key"]))
        self.assertNotIn("my_key", e.symbols)  # imports never count as __start_/__stop_ table bounds
        self.assertEqual(e.key_name(j2.key), "tracepoint foo")  # PC64 key: also checks 8-byte relocations
        self.assertEqual(e.by_addr[j.key], "my_key")
        self.assertGreater(j.key, max(end for a, end in e.sections.values()))  # extern slot after the sections

    def test_debug_only_file(self):
        import tempfile
        from kflow.cli import Elf, load
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "toy.ko")
            module_elf(p)
            b = bytearray(open(p, "rb").read())
            shoff, = struct.unpack_from("<Q", b, 0x28)
            struct.pack_into("<I", b, shoff + 3 * 64 + 4, 8)  # section 3 (__bug_table) -> SHT_NOBITS, as in debug info
            with open(p, "wb") as fh:
                fh.write(b)
            t = load(Elf(p))
        self.assertIn("no contents in this file", t["errors"]["bug"])
        self.assertEqual(len(t["jump"]), 2)  # the other tables are still decoded

    def test_compressed_and_broken(self):
        import gzip
        import lzma
        import tempfile
        from kflow.cli import Elf, InputError, load
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "toy.ko")
            module_elf(p)
            raw = open(p, "rb").read()
            ref = load(Elf(p))["bug"]
            for name, pack in (("toy.ko.xz", lzma.compress), ("toy.ko.gz", gzip.compress)):
                q = os.path.join(d, name)
                with open(q, "wb") as fh:
                    fh.write(pack(raw))
                self.assertEqual(load(Elf(q))["bug"][0].file, ref[0].file)
            for name, data in (("cut.ko", raw[:200]), ("zst.ko.zst", b"\x28\xb5\x2f\xfd" + bytes(20)),
                               ("cut.ko.xz", lzma.compress(raw)[:60]), ("cut.ko.gz", gzip.compress(raw)[:40]),
                               ("junk.elf", b"\x7fELF\x02\x01" + b"\xff" * 100)):
                q = os.path.join(d, name)
                with open(q, "wb") as fh:
                    fh.write(data)
                with self.assertRaises(InputError):
                    Elf(q)


if __name__ == "__main__":
    unittest.main()
