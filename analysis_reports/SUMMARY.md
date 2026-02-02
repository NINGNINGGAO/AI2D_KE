# Kernel Crash Analysis Summary

## Analysis Overview

Two kernel crash dumps have been analyzed:

### Crash 00: db.fatal.00.KE.dbg.DEC

| Attribute | Value |
|-----------|-------|
| **Exception Type** | Watchdog Timeout (WDT status: 2, type: 2) |
| **PC** | `pick_next_task_fair+0x32c/0x434` |
| **Process** | `kworker/u16:3` (PID: 267) |
| **Time** | Tue Jul 15 17:32:48 CST 2025 |
| **Uptime** | 18.75 seconds |
| **Platform** | MT6789 |
| **Kernel** | 5.10.226-android12-9 |

**Root Cause:**
- NULL pointer dereference at virtual address 0x150 in scheduler code
- Workqueue leaked lock or atomic
- Scheduling while atomic detected
- Crash occurred in CFS scheduler during process scheduling

**Key Finding:** The kernel log shows `BUG: scheduling while atomic` and `BUG: workqueue leaked lock or atomic` warnings right before the crash, indicating a workqueue-related issue that corrupted scheduler data structures.

---

### Crash 01: db.fatal.01.KE.dbg.DEC

| Attribute | Value |
|-----------|-------|
| **Exception Type** | Watchdog Timeout (WDT status: 2, type: 2) |
| **PC** | `__queue_work+0x28/0xba4` |
| **Process** | `kworker/3:1H` (PID: 26858) |
| **Time** | Mon Jun 9 12:05:26 CST 2025 |
| **Uptime** | 114.75 seconds |
| **Platform** | MT6789 |
| **Kernel** | 5.10.226-android12-9 |

**Root Cause:**
- NULL pointer dereference at virtual address 0x102 in workqueue code
- Crash occurred in `__queue_work()` function
- Triggered from `delayed_work_timer_fn()` timer callback
- Likely corrupted workqueue data structure

**Key Finding:** The crash happened in the workqueue subsystem while processing a delayed work timer, suggesting a race condition or use-after-free in workqueue management.

---

## Common Patterns

Both crashes share these characteristics:

1. **Same Exception Type**: Both are Watchdog Timeout (WDT status: 2)
2. **Same Platform**: MT6789 (MediaTek)
3. **Same Kernel Version**: 5.10.226-android12-9
4. **Kernel Worker Threads**: Both crashed in kworker threads
5. **NULL Pointer Dereference**: Both involve accessing invalid memory
6. **Scheduler/Workqueue Related**: Both in kernel scheduling/workqueue code paths

## Recommendations

### Immediate Actions

1. **Enable Kernel Debugging**:
   - Enable CONFIG_DEBUG_ATOMIC_SLEEP
   - Enable CONFIG_DEBUG_SPINLOCK
   - Enable CONFIG_DEBUG_MUTEXES

2. **Memory Debugging**:
   - Use KASAN (Kernel Address Sanitizer) builds for testing
   - Enable CONFIG_DEBUG_KMEMLEAK for memory leak detection

3. **Lock Debugging**:
   - Enable CONFIG_PROVE_LOCKING
   - Enable CONFIG_LOCK_STAT

### Code Review Focus

1. **Scheduler Code**:
   - Review any out-of-tree scheduler modifications
   - Check for proper locking in scheduler_tick paths
   - Verify rq (runqueue) lock usage

2. **Workqueue Code**:
   - Review delayed work initialization
   - Check for workqueue cancellation/synchronization
   - Verify timer callback safety

3. **Kernel Modules**:
   - Both crashes mention vendor modules (scheduler.ko, authon.ko)
   - Review module interaction with core kernel

## Generated Reports

- `analysis_reports/report_00_KE.md` - Full analysis of Crash 00
- `analysis_reports/report_01_KE.md` - Full analysis of Crash 01

## Tools Used

- `local_analyzer.py` - Custom local crash dump analyzer
- Built-in kernel log parser
- Symbol analysis (limited without gdb-multiarch)

---

*Generated on 2026-02-02*
