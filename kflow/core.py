"""Decoders for the Linux kernel's own site tables. No IDA imports here.

Every decoder takes `read(ea, size) -> bytes | None` (kernel virtual addresses)
and the table's [start, stop) range, as given by the __start_/__stop_ symbols.
Supported: 64-bit little-endian kernels with relative table entries
(x86_64 since about 4.x for __ex_table, CONFIG_GENERIC_BUG_RELATIVE_POINTERS
for __bug_table, CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE for __jump_table).
"""
import struct
from dataclasses import dataclass

BUGFLAG_WARNING = 1 << 0
BUGFLAG_ONCE = 1 << 1
BUGFLAG_DONE = 1 << 2
BUGFLAG_NO_CUT_HERE = 1 << 3

# include/asm-generic/bug.h, struct bug_entry with relative pointers.
# name: (entry size, field offsets) ; None = field absent.
BUG_LAYOUTS = {
    "addr,file,line,flags": (12, {"addr": 0, "file": 4, "line": 8, "flags": 10, "format": None}),
    "addr,format,file,line,flags": (16, {"addr": 0, "format": 4, "file": 8, "line": 12, "flags": 14}),
    "addr,flags": (8, {"addr": 0, "file": None, "line": None, "flags": 4, "format": None}),
}

EX_TYPE_NAMES = {
    0: "NONE", 1: "DEFAULT", 2: "FAULT", 3: "UACCESS", 5: "CLEAR_FS",
    6: "FPU_RESTORE", 7: "BPF", 8: "WRMSR", 9: "RDMSR", 10: "WRMSR_SAFE",
    11: "RDMSR_SAFE", 12: "WRMSR_IN_MCE", 13: "RDMSR_IN_MCE", 14: "DEFAULT_MCE_SAFE",
    15: "FAULT_MCE_SAFE", 16: "POP_REG", 17: "IMM_REG", 18: "FAULT_SGX",
    19: "UCOPY_LEN", 20: "ZEROPAD", 21: "ERETU",
}  # low byte of the data word; values from Linux v6.12 arch/x86/include/asm/extable_fixup_types.h
# (the immediate sits in the upper bits: EFAULT_REG = IMM_REG with imm -EFAULT). Older kernels number differently.
EX_TYPE_NAMES_ARM64 = {0: "NONE", 1: "BPF", 2: "UACCESS_ERR_ZERO", 3: "KACCESS_ERR_ZERO", 4: "LOAD_UNALIGNED_ZEROPAD"}
# arch/arm64/include/asm/asm-extable.h, same numbers in v6.1 and v6.12 (16-bit type at offset 8; 12-byte entries since 5.16)


@dataclass
class BugSite:
    addr: int
    file: str = None
    line: int = None
    flags: int = 0
    entry: int = 0  # address of the table entry

    @property
    def warn(self):
        return bool(self.flags & BUGFLAG_WARNING)

    @property
    def taint(self):
        return self.flags >> 8

    def where(self):
        return "%s:%d" % (self.file, self.line) if self.file else None


@dataclass
class JumpSite:
    code: int
    target: int
    key: int
    branch: bool  # bit 0 of the key field: jump_entry_is_branch (static_branch_likely)
    init: bool  # bit 1: set by the running kernel for sites in init text (memory images); on disk, x86 objtool uses it as a NOP marker
    entry: int = 0


@dataclass
class ExSite:
    insn: int
    fixup: int
    data: int
    entry: int = 0
    handler: int = None  # x86 before 5.16: address of the fixup handler function (then data is None)

    @property
    def type(self):
        return None if self.data is None else self.data & 0xFF

    def type_name(self, arch="x86_64"):
        if self.data is None:
            return "-"
        names = {"x86_64": EX_TYPE_NAMES, "aarch64": EX_TYPE_NAMES_ARM64}.get(arch)
        if names is None:
            return "type %d" % self.type
        return names.get(self.type, "type %d" % self.type)


def _cstr(read, ea, limit=256):
    raw = read(ea, limit)
    if not raw:
        return None
    end = raw.find(b"\0")
    if end <= 0:
        return None
    try:
        s = raw[:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    return s if s.isprintable() else None


def _plausible_file(s):
    return bool(s) and s.endswith((".c", ".h", ".S", ".rs")) and " " not in s


def decode_bug_table(read, start, stop, layout=None, in_text=None):
    """Return (layout name, [BugSite]). With layout=None the layout whose entries
    decode best wins: most entries with a source-file string, then most bug
    addresses inside text (in_text(ea) -> bool, optional)."""
    size = stop - start
    if size <= 0:
        return None, []
    raw = read(start, size)
    if raw is None or len(raw) < size:
        raise ValueError("bug table not readable at 0x%x" % start)
    names = [layout] if layout else list(BUG_LAYOUTS)
    best = None
    # Before Linux 5.19 (commit 69505e3d9a39) every displacement is relative to the START of the entry;
    # since then each is relative to its own field. Both are tried; the one whose file pointers start strings wins.
    for name, field_rel in [(n, r) for n in names for r in (True, False)]:
        es, off = BUG_LAYOUTS[name]
        if size % es:
            continue
        sites, good = [], 0
        for k in range(size // es):
            base = k * es
            ea = start + base
            disp, = struct.unpack_from("<i", raw, base + off["addr"])
            site = BugSite(addr=ea + (off["addr"] if field_rel else 0) + disp, entry=ea)
            site.flags, = struct.unpack_from("<H", raw, base + off["flags"])
            if off["file"] is not None:
                fd, = struct.unpack_from("<i", raw, base + off["file"])
                fea = ea + (off["file"] if field_rel else 0) + fd
                f = _cstr(read, fea)
                if _plausible_file(f):
                    site.file = f
                    site.line, = struct.unpack_from("<H", raw, base + off["line"])
                    # the right base points at string starts (the linker may still merge a name into another's tail)
                    good += 1 if read(fea - 1, 1) in (b"\0", None) else 0
            if in_text is not None and in_text(site.addr):
                good += 1
            sites.append(site)
        score = good / max(1, len(sites))
        if best is None or score > best[0]:
            best = (score, name + ("" if field_rel else " (entry-relative)"), sites)
    if best is None:
        raise ValueError("bug table size %d fits no known layout" % size)
    return best[1], best[2]


def decode_jump_table(read, start, stop):
    size = stop - start
    if size <= 0:
        return []
    if size % 16:
        raise ValueError("jump table size %d is not a multiple of 16 (absolute layout?)" % size)
    raw = read(start, size)
    if raw is None or len(raw) < size:
        raise ValueError("jump table not readable at 0x%x" % start)
    out = []
    for k in range(size // 16):
        ea = start + 16 * k
        c, t, kr = struct.unpack_from("<iiq", raw, 16 * k)
        out.append(JumpSite(code=ea + c, target=ea + 4 + t, key=ea + 8 + (kr & ~3),
                            branch=bool(kr & 1), init=bool(kr & 2), entry=ea))
    return out


EX_LAYOUTS = {"insn,fixup,data": 12, "insn,fixup": 8}  # "insn,fixup,handler" is reported when 12-byte data points into text  # x86_64 4.x+ and arm64 5.16+: 12; arm64 before 5.16: 8


def decode_ex_table(read, start, stop, layout=None, in_text=None):
    """Return (layout name, [ExSite]). With layout=None the layout with the most
    entries whose instruction and fixup both lie in text wins (in_text optional;
    without it, the 12-byte layout is assumed when the size allows)."""
    size = stop - start
    if size <= 0:
        return None, []
    raw = read(start, size)
    if raw is None or len(raw) < size:
        raise ValueError("exception table not readable at 0x%x" % start)
    best = None
    for name in ([layout] if layout else list(EX_LAYOUTS)):
        es = EX_LAYOUTS[name]
        if size % es:
            continue
        out, good = [], 0
        for k in range(size // es):
            ea = start + es * k
            i, f = struct.unpack_from("<ii", raw, es * k)
            d = struct.unpack_from("<i", raw, es * k + 8)[0] if es == 12 else None
            x = ExSite(insn=ea + i, fixup=ea + 4 + f, data=d, entry=ea)
            if in_text is not None and in_text(x.insn) and in_text(x.fixup):
                good += 1
            out.append(x)
        # x86 before 5.16: the third field is a relative pointer to a handler function, not a type
        if es == 12 and in_text is not None and out:
            targets = [x.entry + 8 + x.data for x in out]
            handlers = sum(1 for a in targets if in_text(a))
            # real handlers are a few functions shared by many entries; a type read as a pointer
            # gives a different address for every entry
            if handlers > len(out) // 2 and len(set(targets)) <= max(16, len(out) // 10):
                for x in out:
                    x.handler, x.data = x.entry + 8 + x.data, None
                name = "insn,fixup,handler"
        # the build sorts __ex_table by instruction address (scripts/sorttable), so the
        # right layout gives an ascending list; in-text counts break ties
        ordered = sum(1 for a, b in zip(out, out[1:]) if b.insn >= a.insn)
        score = (ordered / max(1, len(out) - 1), good / max(1, len(out)))
        if best is None or score > best[0]:
            best = (score, name, out)
    if best is None:
        raise ValueError("exception table size %d fits no known layout" % size)
    return best[1], best[2]

TABLES = {
    "bug": ("__start___bug_table", "__stop___bug_table"),
    "jump": ("__start___jump_table", "__stop___jump_table"),
    "ex": ("__start___ex_table", "__stop___ex_table"),
}
