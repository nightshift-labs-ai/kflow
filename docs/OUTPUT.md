# kflow output

Real command-line output and the comments kflow writes in IDA; the `--json` records are in [USAGE.md](USAGE.md#headless-idalib). Back to the [README](../README.md).

## What you get (real output, not IDA screenshots)

The MemLens demo `kernel.elf` (Debian 13, 6.12.115, x86_64):

```
$ python3 -m kflow kernel.elf
__bug_table (addr,file,line,flags): 9850 sites, 7831 WARN (resume after the trap), 2019 BUG; 9850 with file:line in 1168 source files
  WARN sites that are ud2 here: 7504; sites inside a function symbol: 9329
__jump_table: 9237 static-key sites, 9237 keys named (1728 tracepoints, 2198 pr_debug sites, 182 as symbol+offset), 9006 targets in the same function
  sites by key class (--list jump --class): hardening 82, feature 5229, tracepoint 1728, debug 2198
  hardening keys, default in this build: init_on_alloc on, randomize_kstack_offset on, init_on_free off, cr_pinning off (on in this file), bypass_usercopy_checks off (checks on), switch_mm_cond_ibpb off, switch_mm_always_ibpb off, switch_to_cond_stibp off, switch_mm_cond_l1d_flush off, cpu_buf_idle_clear off
__ex_table (insn,fixup,data): 671 faulting instructions with a fixup, 635 fixups in the same function; types UACCESS 410, IMM_REG 87, WRMSR 42, RDMSR 39, FAULT_SGX 23, CLEAR_FS 15

$ python3 -m kflow kernel.elf --list jump --limit 3   (summary lines and the '... more' line left out here)
0xffffffff8e391de7 -> 0xffffffff8e391dfc  arch_exit_to_user_mode_prepare.isra.0    key randomize_kstack_offset (likely)
0xffffffff8ef08602 -> 0xffffffff8ef08625  __do_fast_syscall_32                     key randomize_kstack_offset (likely)
0xffffffff8ef08705 -> 0xffffffff8ef087f2  do_syscall_64                            key randomize_kstack_offset (likely)

$ python3 -m kflow kernel.elf --list ex --limit 3   (same)
0xffffffff8e200029 -> 0xffffffff8e20002b  sev_es_terminate                         WRMSR
0xffffffff8e20057d -> 0xffffffff8e20057f  early_set_pages_state                    WRMSR
0xffffffff8e200583 -> 0xffffffff8e200585  early_set_pages_state                    RDMSR
```

(`--list warn` and `--list bug` print `address  WARN|BUG  function  file:line`; WARN sites whose bytes are no longer `ud2` sit in init code that the running kernel had freed.)

The comments kflow writes in IDA, for the three sites of the [README's before/after block](../README.md) (the last two are in the lists above; text produced by `kflow/idalayer.py` through the fake-IDA test, not an IDA screenshot):

```
0xffffffff8e629bc4 (mfill_atomic_copy):  kflow: WARN at mm/userfaultfd.c:755 (the kernel reports and continues after this trap)
0xffffffff8e391de7 (arch_exit_to_user_mode_prepare.isra.0):  kflow: static key randomize_kstack_offset (static_branch_likely): runtime-patched NOP/branch; jumps to 0xFFFFFFFF8E391DFC when the key is off
0xffffffff8e200029 (sev_es_terminate):  kflow: may fault -> fixup at 0xFFFFFFFF8E20002B (WRMSR)
```
