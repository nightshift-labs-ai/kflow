"""tools/reach.py rules on a synthetic objdump listing (no objdump, no kernel): python3 tests/test_reach.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import reach  # noqa: E402

B = 0xFFFFFFFF81000000


def listing(rows):
    """rows: (offset, length, text) -> a Listing fed with objdump -d -w lines."""
    lines = ["", "Disassembly of section .text:", "", "%016x <f>:" % B]
    for off, n, text in rows:
        lines.append("%016x:\t%s\t%s" % (B + off, " ".join(["90"] * n), text))
    lst = reach.Listing()
    lst.feed(lines)
    lst.finish()
    return lst


def j(off):
    return "%016x <f+0x%x>" % (B + off, off)


ROWS = [
    (0x00, 3, "mov    %rsp,%rbp"),
    (0x03, 2, "mov    %eax,%edx"),          # after a plain instruction: fallthrough
    (0x05, 2, "jne    " + j(0x40)),
    (0x07, 1, "push   %rbx"),               # after a jcc: fallthrough
    (0x08, 5, "call   " + j(0x60)),
    (0x0d, 2, "xor    %eax,%eax"),          # after a call: fallthrough (calls return)
    (0x0f, 2, "jmp    " + j(0x50)),
    (0x11, 3, "mov    %rdi,%rax"),          # after an unconditional jmp: HIDDEN
    (0x14, 1, "ret"),
    (0x15, 2, "add    %eax,%eax"),          # after ret: HIDDEN
    (0x17, 2, "ud2"),
    (0x19, 2, "pop    %rbx"),               # after ud2 (a WARN trap): HIDDEN
    (0x1b, 1, "int3"),
    (0x1c, 2, "mov    %ecx,%eax"),          # after int3 padding: HIDDEN
    (0x1e, 1, "hlt"),
    (0x1f, 1, "cltq"),                      # after hlt: fallthrough (resumes on an interrupt)
    (0x20, 5, "nopl   0x0(%rax,%rax,1)"),   # a static-key site (NOP state)
    (0x25, 2, "mov    %eax,%ebx"),          # after a static-key NOP site: fallthrough, not padding
    (0x27, 2, "jmp    *%rax"),              # indirect jmp: no fall-through
    (0x29, 3, "nopw   0x0(%rax,%rax,1)"),   # alignment NOPs after a stop
    (0x2c, 2, "mov    %edx,%eax"),          # after NOPs that follow a stop: HIDDEN
    (0x2e, 2, "inc    %eax"),
    (0x30, 3, "nopl   (%rax)"),             # alignment NOPs after a real instruction
    (0x33, 2, "dec    %eax"),               # via padding
    (0x35, 1, "ret"),
    (0x36, 2, "sub    %eax,%ecx"),          # block: sub, mov, jmp (3 insns, 7 bytes)
    (0x38, 3, "mov    %rcx,%rax"),
    (0x3b, 2, "jmp    " + j(0x50)),
    (0x3d, 3, "or     %eax,%eax"),          # block stops before the join at 0x40 (1 insn, 3 bytes)
    (0x40, 2, "and    %eax,%eax"),          # a branch target (from 0x05)
    (0x42, 1, "ret"),
]
SITES = frozenset({B + 0x20})


class Rules(unittest.TestCase):
    def setUp(self):
        self.l = listing(ROWS)

    def reason(self, off):
        return self.l.reason(B + off, SITES)

    def test_fallthrough(self):
        for off in (0x03, 0x07, 0x0d, 0x1f, 0x25):
            self.assertEqual(self.reason(off), "fallthrough", hex(off))

    def test_no_fallthrough(self):
        for off in (0x11, 0x15, 0x19, 0x1c, 0x2c, 0x3d):
            self.assertEqual(self.reason(off), "hidden", hex(off))

    def test_padding_and_branch(self):
        self.assertEqual(self.reason(0x33), "padding")
        self.assertEqual(self.reason(0x40), "branch")
        self.assertEqual(self.reason(0x29), "hidden")  # the NOP run itself, after an indirect jmp
        self.assertEqual(self.l.reason(B + 0x41, SITES), "unaligned")  # inside an instruction

    def test_distinct_targets_and_blocks(self):
        # three sites share 0x36, one goes to 0x3d, one to 0x40 (reachable), one into the middle of an instruction
        targets = [B + 0x36, B + 0x36, B + 0x36, B + 0x3d, B + 0x40, B + 0x41]
        s = reach.measure(self.l, targets, SITES)
        self.assertEqual(s["sites"], 6)
        self.assertEqual(s["hidden"], 4)
        self.assertEqual(s["reasons"]["branch"], 1)
        self.assertEqual(s["reasons"]["unaligned"], 1)
        self.assertEqual(s["hidden_pct"], 80.0)  # 4 of the 5 sites whose target is an instruction
        self.assertEqual(s["hidden_distinct"], 2)
        self.assertEqual(s["hidden_insns"], 3 + 1)  # each distinct block counted once
        self.assertEqual(s["hidden_bytes"], 7 + 3)
        self.assertEqual(s["hidden_union_bytes"], 10)

    def test_ignore_site_jmp(self):
        lst = listing([(0x00, 2, "jmp    " + j(0x04)), (0x02, 2, "ud2"), (0x04, 1, "ret")])
        self.assertEqual(lst.reason(B + 4), "branch")
        self.assertEqual(lst.reason(B + 4, frozenset({B}), ignore=frozenset({B})), "hidden")

    def test_classify(self):
        self.assertEqual(reach.classify("notrack jmp *%rax")[0], reach.STOP)
        self.assertEqual(reach.classify("call   *0x10(%rax)")[0], reach.NORMAL)
        self.assertEqual(reach.classify("cs nopw 0x0(%rax,%rax,1)")[0], reach.NOP)
        self.assertEqual(reach.classify("xchg   %ax,%ax")[0], reach.NOP)
        self.assertEqual(reach.classify("jmp    ffffffff81000010 <f+0x10>"), (reach.JMP, 0xFFFFFFFF81000010))
        self.assertEqual(reach.classify("loop   ffffffff81000010 <f+0x10>"), (reach.COND, 0xFFFFFFFF81000010))


if __name__ == "__main__":
    unittest.main()
