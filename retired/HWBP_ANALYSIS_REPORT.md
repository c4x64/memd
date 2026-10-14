# memd_hwbp.c Analysis Report

## Executive Summary

The `memd_hwbp.c` module implements hardware breakpoint/watchpoint management for ARM64 using the kernel's debug monitor infrastructure. While functional for basic use cases, it has **critical bugs**, **universality gaps**, and **missing enhancements** that prevent it from being a robust, production-ready solution across Android GKI kernels 5.4-6.12.

---

## 1. Bugs Found

### 1.1 Race Conditions (Critical)

| Location | Issue | Impact |
|----------|-------|--------|
| `memd_hwbp_set:150-153` | TOCTOU: Checks `hwbp_table[i].enabled` without lock, then acquires lock | Slot can be claimed by another thread between check and lock |
| `memd_hwbp_remove:203-214` | TOCTOU: Checks `hwbp_table[slot].enabled` without lock | Race with concurrent set/remove operations |
| `memd_hwbp_list:248-257` | Iterates table while holding lock but compares `dms` pointers that may become stale | Use-after-free if task exits during iteration |

### 1.2 Use-After-Free / Missing Reference Counting (Critical)

| Location | Issue | Impact |
|----------|-------|--------|
| `memd_hwbp_set:168` | Stores `dms = task->thread.debug_monitors` without `get_task_struct()` | Task can exit, freeing `debug_monitors` while hwbp holds reference |
| `memd_hwbp_remove:216` | Same issue - uses stale `task` pointer | Dereference of freed memory |
| `memd_hwbp_list:244` | Same issue - iterates over potentially freed task's debug monitors | Kernel panic / data corruption |

### 1.3 Incorrect State Management

| Location | Issue | Impact |
|----------|-------|--------|
| `memd_hwbp_set:185-186` | `hwbp_count = 16` on first set, never decremented | `hwbp_count` meaningless; breaks any logic depending on it |
| `memd_hwbp_cleanup:57-62` | Only disables monitors for entries where `dms` is non-NULL | Misses entries where task already exited (dangling dms) |
| `memd_hwbp_set:150-153` | If explicit `hwbp_id` provided but slot already used, silently overwrites | No error for collision; loses existing breakpoint |

### 1.4 Missing Error Handling

| Location | Issue |
|----------|-------|
| `memd_hwbp_set:138-139` | Returns `-EINVAL` if `task->thread.debug_monitors` is NULL, but does not verify that the task's debug monitors have been initialized |
| `memd_hwbp_set:141-146` | No validation that `cmd->addr` is canonical/user-space address |
| `memd_hwbp_set:150-166` | No bounds check on `cmd->hwbp_id` when > 16 (silently falls to auto-assign) |
| `memd_hwbp_remove:199` | No check that `hwbp_table[slot].dms == dms` (could remove another task's breakpoint) |

### 1.5 ARM64 Debug Register Usage Issues

| Location | Issue |
|----------|-------|
| `hwbp_encode_type:111` | `DBGBCR` encoding hardcoded: `(1<<0) | (len_enc<<5) | (0x1<<8)` - assumes BAS=0, PMC=0, SSC=0. May not match all v8.x implementations |
| `hwbp_encode_type:114-120` | `DBGWCR` encoding hardcoded: LSC=0, BAS=0, LBN=0. No support for linked contexts, data value matching (DVS), or MASK |
| `memd_hwbp_get_info:87-88` | `brp_len_mask` and `wrp_len_mask` hardcoded to `0xF` (1,2,4,8). Some CPUs support 16/32/64 byte watchpoints |
| `memd_hwbp_init:40-44` | Only checks `MDSCR_EL1.SS` for single-step. Doesn't verify `MDSCR_EL1.MDE` (monitor debug enable) or `MDSCR_EL1.KDE` (kernel debug enable) |

---

## 2. Universality Issues (Android GKI 5.4-6.12)

### 2.1 Direct Struct Access Without Offset Learning

```c
// Current code - BREAKS on foreign kernels
dms = task->thread.debug_monitors;
dms->bvr[slot] = cmd->addr;
dms->bcr[slot] = dbgbcr;
```

**Problem**: The offset of `task->thread.debug_monitors` varies across kernel versions and vendor trees. The project provides `memd_learn.h` infrastructure but does not employ it.

### 2.2 Debug Architecture Version Handling

| Architecture | ID_AA64DFR0_EL1 | BRPs | WRPs | Notes |
|--------------|-----------------|------|------|-------|
| ARMv8.0 | Baseline | 2-16 | 2-16 | Basic BCR/WCR |
| ARMv8.2 | +DVS | 2-16 | 2-16 | Data Value Sampling |
| ARMv8.3 | +PAN | 2-16 | 2-16 | Privileged Access Never |
| ARMv8.4 | +PMUv3 | 2-16 | 2-16 | |
| ARMv8.5 | +MTE/BTI | 2-16 | 2-16 | Memory Tagging, Branch Target ID |
| ARMv8.6 | +ECV/FGT | 2-16 | 2-16 | Enhanced Counter Virtualization |

**Current code**: Reads `ID_AA64DFR0_EL1` once during initialization but does not adapt its encoding for DVS, MTE, or linked contexts.

### 2.3 Missing Symbol Resolution via kallsyms

The module uses:
- `read_sysreg()` - OK (inline asm)
- `disable_debug_monitor()` - **NOT resolved via kallsyms** (kernel internal)
- `task->thread.debug_monitors` - **NOT resolved via kallsyms** (kernel internal struct)

### 2.4 Kernel Version Compatibility

| Kernel Range | Issue |
|--------------|-------|
| 5.4-5.10 | `debug_monitor_state` layout may differ; `find_vma` vs `__find_vma` |
| 5.10-5.15 | `mmap_sem` → `mmap_lock` transition (handled in memd_utils.h) |
| 5.15-6.1 | Maple tree VMA (find_vma still works) |
| 6.1-6.6 | `struct mm_struct` layout changes (memd_learn handles) |
| 6.6-6.12 | `struct file_operations` rework (memd_learn handles) |

---

## 3. Self-Contained Issues

### 3.1 External Symbol Dependencies

| Symbol | Source | Resolved via kallsyms? |
|--------|--------|------------------------|
| `disable_debug_monitor` | kernel/arch/arm64/kernel/debug-monitors.c | **NO** |
| `enable_debug_monitor` | kernel/arch/arm64/kernel/debug-monitors.c | **NO** |
| `debug_monitor_state` struct | kernel/include/asm/debug-monitors.h | **NO** (header only) |
| `read_sysreg`/`write_sysreg` | arch/arm64/include/asm/sysreg.h | OK (inline) |

### 3.2 Kernel Internal Struct Dependency

```c
// From asm/debug-monitors.h (kernel internal)
struct debug_monitor_state {
    u64 bvr[16];
    u64 bcr[16];
    u64 wvr[16];
    u64 wcr[16];
    // ... may have more fields in newer kernels
};
```

**Risk**: Struct layout changes between kernel versions. The code assumes fixed 16-entry arrays at fixed offsets.

---

## 4. Enhancement Requirements

### 4.1 Watchpoint Conditions (Data Value Matching)
- Support `DBGWCR.DVS` (Data Value Select) for ARMv8.2+
- Support `DBGWCR.MASK` for address range masking
- Support linked breakpoints (LBN - Linked Breakpoint Number)

### 4.2 Breakpoint Hit Callbacks
- Register per-breakpoint callback functions
- Pass context: `task_struct*`, `pt_regs*`, `hwbp_id`, trap type
- Support both synchronous (breakpoint) and asynchronous (watchpoint) handlers

### 4.3 Per-CPU Debug State Saving/Restoring
- Save/restore debug registers on context switch
- Handle CPU hotplug
- Support `CONFIG_DEBUG_INFO` / `CONFIG_HW_BREAKPOINT` integration

### 4.4 Hardware Single-Step Emulation
- Implement `MDSCR_EL1.SS` single-step control
- Provide `memd_hwbp_single_step(task, enable, callback)`
- Handle `MDSCR_EL1.KDE`/`MDE` for kernel/user stepping

### 4.5 Context-Switch Debug Register Preservation
- Hook `context_switch()` or use `ptrace` infrastructure
- Save/restore all BVR/BCR/WVR/WCR per task
- Handle `PTRACE_SINGLESTEP` compatibility

---

## 5. Recommended Fixes Priority

### P0 - Critical (Must Fix)
1. Add `get_task_struct()`/`put_task_struct()` around all task usage
2. Fix TOCTOU races by holding lock during entire check+act sequence
3. Fix `hwbp_count` tracking
4. Validate `hwbp_id` bounds explicitly

### P1 - High (Universality)
1. Use `memd_learned_ext.t_thread` offset for `task->thread`
2. Use `memd_learned_ext.t_debug_monitors` (new) for `thread.debug_monitors`
3. Resolve `disable_debug_monitor`/`enable_debug_monitor` via `kallsyms_lookup_name_ex`
4. Detect debug architecture version at runtime

### P2 - Medium (Robustness)
1. Add address canonicality checks
2. Add watchpoint condition support (DVS, MASK, LBN)
3. Add breakpoint hit callback registration
4. Implement proper cleanup for exited tasks

### P3 - Enhancement (New Features)
1. Hardware single-step emulation
2. Per-CPU debug state management
3. Context-switch preservation
4. Linked breakpoint support

---

## 6. Proposed Architecture

```
memd_hwbp.c (refactored)
├── hwbp_core.c          # Core slot management, locking, refcounting
├── hwbp_arch.c          # ARM64-specific register encoding, version detection
├── hwbp_callbacks.c     # Hit callback registration/invocation
├── hwbp_singlestep.c    # Single-step emulation
├── hwbp_context.c       # Context-switch save/restore
├── hwbp_learn.c         # Runtime offset learning for task/thread/debug_monitors
└── hwbp_kallsyms.c      # Runtime symbol resolution for kernel internals
```

This modular design enables:
- Independent testing of each component
- Clear separation of arch-specific vs generic logic
- Easy backporting to older kernels
- Selective compilation of features
<!-- retired/HWBP_ANALYSIS_REPORT.md[´ø¬ µ∂] -->
