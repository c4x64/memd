# memd_hwbp.c Analysis Report

## Executive Summary

The `memd_hwbp.c` implementation has **critical flaws** that prevent it from functioning on any Android GKI kernel (5.4-6.12). The code accesses a non-existent kernel structure (`task->thread.debug_monitors`), has severe race conditions, incorrect ARM64 debug register programming, and lacks universality across kernel versions and CPU debug architectures.

---

## 1. Critical Bugs

### 1.1 Non-Existent Kernel Structure Access (BLOCKER)
**File**: `memd_hwbp.c`, lines 138, 168, 207, 216, 244
**Issue**: Code accesses `task->thread.debug_monitors` which **does not exist** in any upstream or Android GKI kernel.
**Actual kernel structure**: `task->thread.debug` (type `struct debug_info`) contains `perf_event` pointers for hw breakpoints, not raw register arrays.
**Impact**: Kernel panic / NULL pointer dereference on first use.

### 1.2 Race Conditions
| Location | Issue |
|----------|-------|
| Global `hwbp_table[16]` | Shared across all tasks without per-task isolation; concurrent `memd_hwbp_set`/`remove` on different tasks corrupt each other's state |
| `hwbp_table[slot].dms` | Raw pointer to task's debug state without reference counting; task exit causes use-after-free |
| No context-switch sync | Debug registers not saved/restored on task switch; breakpoints leak across processes |
| `hwbp_count` logic | Line 186: `if (hwbp_count == 0) hwbp_count = 16;` - incorrect semantics, should track active count |

### 1.3 Memory Leaks / Use-After-Free
- No `task_struct` death notification (no `task_work` or `perf_event` cleanup callback)
- `memd_hwbp_cleanup()` disables monitors but does not free per-task state.
- `hwbp_table[slot].dms` becomes dangling pointer when task exits
- No RCU grace period for task lifetime

### 1.4 Incorrect ARM64 Debug Register Usage

#### Length Encoding (Lines 93-102) - **WRONG**
```c
// Current (WRONG): returns 0,1,2,3 for 1,2,4,8 bytes
// Correct (ARM64 DBGWCRn_EL1.LEN field): 0x1,0x3,0x7,0xf (2^(LEN+1)-1)
case 1: return 0;  // Should be 0 (2^(0+1)-1 = 1) OK
case 2: return 1;  // Should be 1 (2^(1+1)-1 = 3) WRONG
case 4: return 2;  // Should be 2 (2^(2+1)-1 = 7) WRONG
case 8: return 3;  // Should be 3 (2^(3+1)-1 = 15) WRONG
```

#### BCR/WCR Encoding (Lines 109-121) - **INCOMPLETE**
```c
// Current: Missing critical fields
*dbgbcr = (1ULL << 0) | ((u64)len_enc << 5) | (0x1ULL << 8);
// Missing: PMC (privilege), BT (breakpoint type), LBN (linked BRP), SSC (security state), HMC (hyp mode), BAS (address mask)

// Watchpoint missing: PAC (privilege access control), LSC (load/store control)
```

#### Single-Step Check (Lines 40-44) - **INSUFFICIENT**
```c
// Current: Only checks MDSCR_EL1_SS
mdscr_el1 = read_sysreg(mdscr_el1);
if (!(mdscr_el1 & MDSCR_EL1_SS)) { ... }

// Missing: MDSCR_EL1_KDE (Kernel Debug Enable) required for EL1 debugging
// Missing: debug_monitors_arch() >= 6 (ARMv8.2+) for enhanced features
```

#### Hardcoded Slot Count (Line 27) - **NON-UNIVERSAL**
```c
static struct memd_hwbp_entry hwbp_table[16];  // Should use get_num_brps()/get_num_wrps()
```

### 1.5 Missing Error Handling
- No address alignment validation (watchpoints require alignment = length)
- No page-boundary crossing check for watchpoints
- No validation that `enable_debug_monitors()` succeeds
- No check that `task` is still alive (`pid_alive()`, `task->mm`)
- `memd_hwbp_remove()` does not verify that `dms` matches the current task's debug state.

---

## 2. Universality Failures (Android GKI 5.4-6.12)

### 2.1 Kernel Version Compatibility
| Feature | 5.4 | 5.10 | 5.15 | 6.1 | 6.6 | 6.12 |
|---------|-----|------|------|-----|-----|------|
| `debug_monitors_arch()` | Yes | Yes | Yes | Yes | Yes | Yes |
| `enable_debug_monitors()` | Yes | Yes | Yes | Yes | Yes | Yes |
| `CONFIG_HAVE_HW_BREAKPOINT` | Yes | Yes | Yes | Yes | Yes | Yes |
| `task->thread.debug` | Yes | Yes | Yes | Yes | Yes | Yes |
| `task->thread.debug_monitors` | No | No | No | No | No | No |
| `perf_event` hw bp API | Yes | Yes | Yes | Yes | Yes | Yes |

### 2.2 CPU Debug Architecture (ID_AA64DFR0_EL1.DebugVer)
| Version | DebugVer | Features |
|---------|----------|----------|
| ARMv8.0 | 0x0 | Basic breakpoints/watchpoints |
| ARMv8.1 | 0x1 | + Virtualization (VMID) |
| ARMv8.2 | 0x2 | + EDSR, enhanced watchpoints |
| ARMv8.3 | 0x3 | + Pointer auth, nested virt |
| ARMv8.4 | 0x4 | + TTL, FPAC |
| ARMv8.5 | 0x5 | + BTI, MTE |
| ARMv8.6 | 0x6 | + ECV, fine-grained traps |

**Current code**: Ignores `debug_monitors_arch()` entirely.

### 2.3 Exported Symbol Dependencies (NOT Universal)
| Symbol | Exported? | Resolution Needed |
|--------|-----------|-------------------|
| `enable_debug_monitors` | NO (NOKPROBE_SYMBOL) | kallsyms_lookup_name_ex |
| `disable_debug_monitors` | NO (NOKPROBE_SYMBOL) | kallsyms_lookup_name_ex |
| `debug_monitors_arch` | NO | kallsyms_lookup_name_ex |
| `hw_breakpoint_slots` | NO | kallsyms_lookup_name_ex |
| `arch_install_hw_breakpoint` | NO | kallsyms_lookup_name_ex |

---

## 3. Self-Contained Violations

### 3.1 Direct Symbol Dependencies (Not Resolved via kallsyms)
```c
// memd_hwbp.c uses these WITHOUT runtime resolution:
enable_debug_monitors()      // Line 59 (in cleanup)
disable_debug_monitors()     // Line 59
read_sysreg(mdscr_el1)       // Lines 40, 81 - inline asm, OK
write_sysreg()               // Not used directly but via enable/disable
task->thread.debug_monitors  // Lines 138, 168, 207, 216, 244 - DOES NOT EXIST
```

### 3.2 Required Runtime Symbol Resolution
All kernel helper functions must be resolved via `kallsyms_lookup_name_ex()` at init:
- `enable_debug_monitors`
- `disable_debug_monitors`
- `debug_monitors_arch`
- `get_num_brps` / `get_num_wrps` (or inline equivalents)
- `arch_install_hw_breakpoint` / `arch_uninstall_hw_breakpoint` (for perf_event path)

---

## 4. Required Enhancements

### 4.1 Watchpoint Conditions (Data Value Matching)
ARMv8.2+ supports data value matching via `DBGWVRn_EL1` + `DBGWCRn_EL1` with `DBGWCR.LSC` and data masking.
API needed:
```c
struct memd_hwbp_watchpoint_condition {
    u64 data_value;
    u64 data_mask;    // 0 = exact match, ~0 = no comparison
};
```

### 4.2 Breakpoint Hit Callbacks
```c
typedef void (*memd_hwbp_hit_cb_t)(struct task_struct *task, u32 hwbp_id, 
                                    struct pt_regs *regs, void *ctx);
int memd_hwbp_set_callback(u32 hwbp_id, memd_hwbp_hit_cb_t cb, void *ctx);
```

### 4.3 Per-CPU Debug State Save/Restore
```c
struct memd_hwbp_cpu_state {
    u64 bvr[ARM_MAX_BRP];
    u64 bcr[ARM_MAX_BRP];
    u64 wvr[ARM_MAX_WRP];
    u64 wcr[ARM_MAX_WRP];
    u64 mdscr_el1;
};
void memd_hwbp_save_cpu_state(struct memd_hwbp_cpu_state *state);
void memd_hwbp_restore_cpu_state(const struct memd_hwbp_cpu_state *state);
```

### 4.4 Hardware Single-Step Emulation
```c
int memd_hwbp_single_step_enable(struct task_struct *task);
int memd_hwbp_single_step_disable(struct task_struct *task);
bool memd_hwbp_single_step_active(struct task_struct *task);
```

### 4.5 Context-Switch Debug Register Preservation
Integrate with `hw_breakpoint_thread_switch()` / `ptrace_hw_copy_thread()` or implement custom notifier.

---

## 5. Recommended Architecture

### 5.1 Use perf_event API (Universal, Supported)
The **only** universal way to use hardware breakpoints/watchpoints across all GKI kernels:
```c
struct perf_event_attr attr = {
    .type = PERF_TYPE_BREAKPOINT,
    .bp_type = HW_BREAKPOINT_X,  // HW_BREAKPOINT_R/W/RW/X
    .bp_addr = addr,
    .bp_len = len,
};
struct perf_event *bp = perf_event_create_kernel_counter(&attr, -1, task, NULL, NULL);
```

### 5.2 Fallback: Direct Register Access (If perf_event Unavailable)
Only if `CONFIG_HAVE_HW_BREAKPOINT=n`, use direct sysreg access with:
- Per-task debug register state in `task->thread.debug` (via `perf_event` pointers)
- Context switch hooks via `hw_breakpoint_thread_switch()`
- CPU hotplug notifiers for debug monitor enable/disable

### 5.3 Per-Task State Management
```c
struct memd_hwbp_task_state {
    struct task_struct *task;
    struct perf_event *brps[ARM_MAX_BRP];
    struct perf_event *wrps[ARM_MAX_WRP];
    struct list_head node;
    struct rw_semaphore lock;
    u32 active_brps;
    u32 active_wrps;
};
```

---

## 6. Patch Strategy

The patch will:
1. **Remove** the non-existent `debug_monitors` field usage
2. **Implement** perf_event-based hardware breakpoint/watchpoint API
3. **Add** runtime symbol resolution for all kernel helpers
4. **Add** CPU debug architecture detection and feature gating
5. **Implement** per-task state with proper locking and lifetime management
6. **Add** all requested enhancements (conditions, callbacks, single-step, context-switch)
<!-- retired/MEMD_HWBP_ANALYSIS_REPORT.md[´ø¬ µ∂] -->
