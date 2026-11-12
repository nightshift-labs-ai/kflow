# WARN fall-through (experimental)

**Experimental, off by default, x86_64 only, not yet run in real IDA: kflow: Let WARN sites fall through.** In the IDA menu: **Edit > Plugins > kflow: Let WARN sites fall through (experimental)** and **kflow: Remove WARN fall-through**. Back to the [README](../README.md).

## Why

IDA treats `ud2` as the end of code flow. So the code after a WARN trap, where the kernel continues, is unreachable in IDA and missing from the function, and Hex-Rays prints the trap as `BUG();`, which it models as never returning. Annotate only says so in a comment.

## What the action does

- This action adds ordinary flow after exactly the WARN `ud2` traps listed in the kernel's `__bug_table` (BUG traps stay as they are; on the MemLens demo kernel that is 7,504 WARN `ud2` traps, and its 1,825 BUG `ud2` traps, the 1,825 of its 2,019 BUG entries whose trap is a `ud2` in code, are left alone).
- It then lets IDA reanalyse those sites, adds newly reachable code that is in no function to the trap's function as a function tail (code that already belongs to another function is left alone and counted), and reanalyses those functions.
- If the decompiler is present and at least one site got flow, it also asks Hex-Rays to decompile each of those traps as a call to `__WARN()` that returns and changes no register; whether Hex-Rays accepts this for `ud2` is unconfirmed.
- The Output window shows how many sites got flow and whether IDA's processor module marks `ud2` as the end of flow, so a log shows whether it worked.

## The processor hook and the database record

- kflow records the sites in the database and installs its processor hook only for databases with that record, whenever it loads one; the hook adds a Python call for every instruction IDA analyses there.
- If you open the database without kflow, the added flow stays until IDA reanalyses those instructions, and the decompiler shows `BUG();` again; the next time kflow loads it says how many sites lost their flow, and running the action again restores it.

## Undo

**kflow: Remove WARN fall-through** undoes it:

- it removes each function tail kflow added that is still exactly the chunk kflow added (kflow records where each tail ends; a tail IDA has merged with its own code stays in the function, and the Output window counts it),
- lets IDA reanalyse the sites without the hook
- and deletes the record (the code after the traps stays disassembled, unreachable again).

## How it was tested

This part was written from the IDA SDK documentation and tested only on fake `ida_*` modules (`tests/test_warnflow_stub.py`); it is the part most likely to need a fix, so reports are very welcome.

## arm64

On arm64 it changes nothing: public Hex-Rays output of arm64 kernels shows code continuing after `brk #0x800` (IDA version unknown), and the action reports whether IDA's ARM module marks `brk` as the end of flow in your IDA.

## Prior art

[linux_und.py](https://git.zx2c4.com/ida-plugins/tree/linux_und.py) by Jason A. Donenfeld (2017) re-decodes every `ud0`/`ud1`/`ud2` as a custom instruction, so (as far as we can tell from its code) IDA stops ending flow at all of them, BUG traps included. kflow changes only the WARN traps the kernel lists.
