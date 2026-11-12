# tools/reach.py results

How much of the code kflow points at does ordinary control flow reach without kflow? `tools/reach.py` disassembles the
kernel's executable sections with objdump (linear sweep, whole kernel, no sampling). A site's target counts as
reachable when any direct jmp / jcc / loop / call targets it ("branch"), when the instruction just before it can fall
into it ("fallthrough"; everything except jmp, indirect jmp, ret / iret / sysret, ud0-ud2, int3 and (bad); calls are assumed to
return; a static-key site falls through), or when it can only be reached by running alignment NOPs after such an
instruction ("padding"). Every other target is HIDDEN: no direct branch targets it and nothing falls into it, so
kflow's reference is the only one that leads there. Bytes and instructions are counted once per DISTINCT hidden
target; a block runs from the target up to and including the next unconditional transfer, and stops before the next
branch target (a join). The rules are in the docstring of `tools/reach.py` and checked by `tests/test_reach.py`.

Rows: `key, NOP sites` keeps only the static-key sites that are NOPs in this file (the number quoted in the README);
`key` also counts the sites that are a jmp in this file (they already branch to their target);
`key, site jmps ignored` acts as if every key were in its NOP state. HIDDEN % is of the sites whose target is an
instruction in the listing ("unal." sites, e.g. in init code a memory image no longer has, are left out).

Runtime: about 15 s per kernel (objdump on 16-22 MB of .text).

## MemLens demo kernel (x86_64)

```
$ python3 tools/reach.py /home/agent/tools/memlens-demo/x/kernel.elf      # exit 0
kernel: /home/agent/tools/memlens-demo/x/kernel.elf
disassembled: .text 16384 KB, .hook.ffffffffc0004940 8 KB, .mod.virtio_blk.text 12 KB, .mod.i2c_i801.text 12 KB, .mod.failover.text 4 KB, .mod.net_failover.text 8 KB, ... (73 sections); 8148797 instructions, 831946 direct branches/calls to 419520 distinct targets (19 s)
static-key sites in this file: 8349 NOP, 663 jmp (already branch to their target), 225 other
WARN sites that are not ud2 here (skipped): 327
kind                     sites          HIDDEN  branch  fallthr padding  unal.  distinct    insns     bytes     union    avg
----------------------------------------------------------------------------------------------------------------------------
warn                      7504    6740 (89.8%)     764        0       0      0      6740    11448     41187     41187    1.7
key                       9237    8037 (89.2%)     816      159       0    225      8011    62593    264287    264287    7.8
key, NOP sites            8349    8037 (96.3%)     153      159       0      0      8011    62593    264287    264287    7.8
key, site jmps ignored    9237    8643 (95.9%)     173      196       0    225      8616    66724    277735    277735    7.7
ex                         671     322 (48.9%)      54      241      41     13        51      129       426       426    2.5
HIDDEN %: of sites - unal.; unal.: the target is not an instruction start in the listing (or outside every disassembled section)
distinct, insns, bytes, union, avg: the distinct HIDDEN targets and their out-of-line blocks
```

Same with `--section .text` (exit 0): identical rows (the module sections add nothing).

## Ubuntu 6.8.0-149 amd64 vmlinux

```
$ python3 tools/reach.py ubuntu-6.8.0-149-amd64.elf                       # exit 0
kernel: /home/agent/tools/kflow-kernels/ubuntu-6.8.0-149-amd64.elf
disassembled: .text 22528 KB, .init.text 807 KB, .altinstr_aux 13 KB, .altinstr_replacement 35 KB, .exit.text 17 KB; 9680675 instructions, 1103227 direct branches/calls to 494532 distinct targets (18 s)
static-key sites in this file: 8055 NOP, 249 jmp (already branch to their target), 0 other
kind                     sites          HIDDEN  branch  fallthr padding  unal.  distinct    insns     bytes     union    avg
----------------------------------------------------------------------------------------------------------------------------
warn                      8259    7423 (89.9%)     836        0       0      0      7423    16678     56229     56229    2.2
key                       8304    7771 (93.6%)     389      144       0      0      7731    68620    304900    304900    8.9
key, NOP sites            8055    7771 (96.5%)     140      144       0      0      7731    68620    304900    304900    8.9
key, site jmps ignored    8304    7918 (95.4%)     201      185       0      0      7877    69769    309820    309820    8.9
ex                         632     284 (44.9%)      52      251      45      0        49      216       529       529    4.4
HIDDEN %: of sites - unal.; unal.: the target is not an instruction start in the listing (or outside every disassembled section)
distinct, insns, bytes, union, avg: the distinct HIDDEN targets and their out-of-line blocks
```

```
$ python3 tools/reach.py ubuntu-6.8.0-149-amd64.elf --section .text       # exit 0
kernel: /home/agent/tools/kflow-kernels/ubuntu-6.8.0-149-amd64.elf
disassembled: .text 22528 KB; 9435445 instructions, 1054696 direct branches/calls to 472955 distinct targets (15 s)
static-key sites in this file: 7822 NOP, 243 jmp (already branch to their target), 239 other
kind                     sites          HIDDEN  branch  fallthr padding  unal.  distinct    insns     bytes     union    avg
----------------------------------------------------------------------------------------------------------------------------
warn                      8259    7176 (89.8%)     814        0       0    269      7176    16109     54282     54282    2.2
key                       8304    7565 (93.8%)     380      120       0    239      7525    67204    297996    297996    8.9
key, NOP sites            7822    7565 (96.7%)     137      120       0      0      7525    67204    297996    297996    8.9
key, site jmps ignored    8304    7705 (95.5%)     198      162       0    239      7665    68310    302723    302723    8.9
ex                         632     285 (46.0%)      49      240      45     13        50      219       540       540    4.4
HIDDEN %: of sites - unal.; unal.: the target is not an instruction start in the listing (or outside every disassembled section)
distinct, insns, bytes, union, avg: the distinct HIDDEN targets and their out-of-line blocks
```

## Against the earlier independent measurement (review s160, script not kept)

| | earlier measurement | reach.py |
|---|---|---|
| demo warn | 7504 sites, 6740 HIDDEN (89.8%), 41187 bytes, 1.7 insns | same |
| demo key (NOP sites) | 8349, 8038 HIDDEN (96.3%); branch 153, fallthrough 144 + 14 via padding; 8012 distinct, 264,304 bytes, 7.8 | 8349, 8037 HIDDEN (96.3%); branch 153, fallthrough 159, padding 0; 8011 distinct, 264,287 bytes, 7.8 |
| demo ex | 658 sites, 322 HIDDEN (48.9%); fallthrough 240, padding 42, branch 54; 51 distinct, 426 bytes | 671 sites (13 outside every section), 322 HIDDEN (48.9%); fallthrough 241, padding 41, branch 54; 51 distinct, 426 bytes |
| Ubuntu warn | 89.8% (7176) | 89.9% (7423) all sections; 89.8% (7176) with `--section .text` |
| Ubuntu key | 96.7%, 7525 distinct, 298 KB | 96.5%, 7731 distinct, 304,900 bytes all sections; 96.7%, 7525 distinct, 297,996 bytes with `--section .text` |
| Ubuntu ex | 45.9%, 49 distinct, 529 bytes | 44.9%, 49 distinct, 529 bytes all sections; 46.0%, 50 distinct, 540 bytes with `--section .text` |

Every percentage is within 1.1 points. The differences come from two rules:
- **Which sections are disassembled.** By default reach.py reads every executable section; on Ubuntu that adds
  .init.text, .exit.text, .altinstr_replacement and .altinstr_aux to .text. The earlier measurement read .text only.
  The extra sections bring 269 WARN sites and 233 static-key NOP sites that lie outside .text (with `--section .text`
  they are "unal." and left out), plus a few more branch sources. With `--section .text`, warn and key match the earlier numbers exactly. The demo kernel is a
  memory image whose init code is gone, so there the choice changes nothing.
- **A static-key NOP right before a target.** 26 of the demo's key targets follow another static-key site.
  reach.py counts that site as a real instruction that falls through ("fallthrough"). The earlier measurement
  reported 144 fallthrough + 14 via padding (158) against reach.py's 159 fallthrough. Its script was not kept, so
  its exact rule is unknown (most likely it treated a static-key NOP before a target as padding). The HIDDEN count
  differs by one site (8037 vs 8038) and the bytes by one 17-byte block.
- The 13 demo fixups (and 225 static-key sites, 327 WARN entries) outside every executable section are in init code
  the memory image no longer has. reach.py lists them as "unal." and leaves them out of the %. The earlier measurement
  did the same (658 = 671 - 13).

Fixups are mostly reached by ordinary flow, and the hidden ones are shared: 322 hidden fixup sites go to only 51
distinct handlers (426 bytes). That is why the README quotes only the static-key and WARN numbers.
