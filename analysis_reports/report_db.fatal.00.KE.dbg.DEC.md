# Kernel Crash Analysis Report
## db.fatal.00.KE.dbg.DEC

## 基本信息

| 项目 | 值 |
|------|-----|
| Crash ID | db.fatal.00.KE.dbg.DEC |
| 异常类型 | Kernel |
| 异常时间 | Tue Jul 15 17:32:48 CST 2025 |
| 系统运行时间 | 18.75017 |
| 平台 | MT6789 |
| WDT Status | 2 |
| Exception Type | 2 |

## 进程信息

- **当前进程**: kworker/u16:3 (PID: 267)
- **父进程**: kthreadd (PID: 2)

## 崩溃位置

- **PC (程序计数器)**: [ffffffdf725b9158] pick_next_task_fair+0x32c/0x434
- **LR (链接寄存器)**: [ffffffdf725b914c] pick_next_task_fair+0x320/0x434

## 调用栈 (Backtrace)

```
# 1 [ffffffdf724abff8] die_kernel_fault+0x80/0x94
# 2 [ffffffdf724abf28] __do_kernel_fault+0x23c/0x28c
# 3 [ffffffdf73e11e90] do_page_fault+0xb0/0x858
# 4 [ffffffdf73e11dc0] do_translation_fault+0x44/0x64
# 5 [ffffffdf724ab2f4] do_mem_abort+0x68/0x164
# 6 [ffffffdf73b55bd0] el1_abort+0x40/0x68
# 7 [ffffffdf73b55b5c] el1_sync_handler+0x54/0x88
# 8 [ffffffdf72412488] el1_sync+0x88/0x140
# 9 [ffffffdf725b9158] pick_next_task_fair+0x32c/0x434
#10 [ffffffdf73e021a4] __schedule+0x308/0xc48
#11 [ffffffdf73e02b60] schedule+0x7c/0x164
#12 [ffffffdf72570bb8] worker_thread+0x558/0x920
#13 [ffffffdf7257f498] kthread+0x14c/0x200
#14 [ffffffdf72415918] ret_from_fork+0xc/0x30
```

## 根因分析

异常类型为 Watchdog Timeout (WDT status: 2)，表示发生了硬件看门狗超时。
PC 指向调度器函数 pick_next_task_fair()，这是一个 CFS 调度器函数。
崩溃发生在进程调度过程中，可能原因包括：
- 调度器数据结构损坏
- 内存访问越界导致调度队列损坏
- 内核模块干扰了调度器正常操作
崩溃发生在内核工作线程 kworker/u16:3 中，这是一个内核态线程。

## 涉及模块

- kernel/mm
- kernel/sched

## 关键日志片段

```
[    6.823000] [T1700001] Call trace:
[    7.940051] [T1200174] [BLK-IO]is_disable_blk_io: bootargs:  console=tty0 root=/dev/ram loglevel=8 8250.nr_uarts=4 initcall_debug=1 transparent_hugepage=never vmalloc=400M swiotlb=noforce firmware_class.path=/vendor/firmware page_owner=on pelt=8 loop.max_part=7 FlashID=Jbl+C2G072 mem_index=3 earlycon=uart8250,mmio32,0x11002000 console=ttyS0,921600n1 has_battery_removed=0 ramoops.mem_address=0x48090000 ramoops.mem_size=0xe0000 ramoops.pmsg_size=0x40000 ramoops.console_size=0x40000 usb2jtag_mode=0 root=/dev/ram bootopt=64S3,32N2,64N2 log_buf_len=2m mtk_printk_ctrl.disable_uart=0 panic_on_taint=20 sfi=0x00000000 PN=x6886_h8921 tran_aging_mode=0 arm64.nomte tkv=4294930432 bootconfig
[    8.221228] [T1100001] tkv_get_cmd: bootargs:  console=tty0 root=/dev/ram loglevel=8 8250.nr_uarts=4 initcall_debug=1 transparent_hugepage=never vmalloc=400M swiotlb=noforce firmware_class.path=/vendor/firmware page_owner=on pelt=8 loop.max_part=7 FlashID=Jbl+C2G072 mem_index=3 earlycon=uart8250,mmio32,0x11002000 console=ttyS0,921600n1 has_battery_removed=0 ramoops.mem_address=0x48090000 ramoops.mem_size=0xe0000 ramoops.pmsg_size=0x40000 ramoops.console_size=0x40000 usb2jtag_mode=0 root=/dev/ram bootopt=64S3,32N2,64N2 log_buf_len=2m mtk_printk_ctrl.disable_uart=0 panic_on_taint=20 sfi=0x00000000 PN=x6886_h8921 tran_aging_mode=0 arm64.nomte tkv=4294930432 bootconfig
[    8.241625] [T1100001] tkv_recovery_get_cmd: bootargs:  console=tty0 root=/dev/ram loglevel=8 8250.nr_uarts=4 initcall_debug=1 transparent_hugepage=never vmalloc=400M swiotlb=noforce firmware_class.path=/vendor/firmware page_owner=on pelt=8 loop.max_part=7 FlashID=Jbl+C2G072 mem_index=3 earlycon=uart8250,mmio32,0x11002000 console=ttyS0,921600n1 has_battery_removed=0 ramoops.mem_address=0x48090000 ramoops.mem_size=0xe0000 ramoops.pmsg_size=0x40000 ramoops.console_size=0x40000 usb2jtag_mode=0 root=/dev/ram bootopt=64S3,32N2,64N2 log_buf_len=2m mtk_printk_ctrl.disable_uart=0 panic_on_taint=20 sfi=0x00000000 PN=x6886_h8921 tran_aging_mode=0 arm64.nomte tkv=4294930432 bootconfig
[    8.301617] [T1700001] e2fsck: linker: Warning: failed to find generated linker configuration from "/linkerconfig/ld.config.txt"
[    8.303972] [T1700001] e2fsck: WARNING: linker: Warning: failed to find generated linker configuration from "/linkerconfig/ld.config.txt"
[    8.536585] [T1700001] init: [libfstab] Warning: unknown flag: resize
[   10.376737] [T1300408] platform +platform:mt63xx-oc-debug mt63xx-oc-debug mt63xx-oc-debug: fail to get regulator vpa
[   10.378024] [T1300408] platform +platform:mt63xx-oc-debug mt63xx-oc-debug mt63xx-oc-debug: fail to get regulator vcore_pr
[   10.380161] [T1300408] platform +platform:mt63xx-oc-debug mt63xx-oc-debug mt63xx-oc-debug: fail to get regulator vcn33
[   10.381483] [T1300408] platform +platform:mt63xx-oc-debug mt63xx-oc-debug mt63xx-oc-debug: fail to get regulator vm18
[   10.382826] [T1300408] platform +platform:mt63xx-oc-debug mt63xx-oc-debug mt63xx-oc-debug: fail to get regulator vmddr
[   10.557230] [T1600537] 0x74659dc-0xvold: [libfstab] Warning: unknown flag: resize
[   13.264482] [T1600408] WARNING: CPU: 6 PID: 408 at fs/proc/generic.c:382 proc_register+0x1bc/0x320
[   13.484928] [T1600408] Call trace:
[   13.879731] [T1600408] Call trace:
[   14.958214] [T1600891] WARNING: Unprivileged eBPF is enabled, data leaks possible via Spectre v2 BHB attacks!
[   17.457937] [T1701304] capability: warning: `netdiag' uses 32-bit capabilities (legacy support in use)
[   18.405137] [T1700267] BUG: scheduling while atomic: kworker/u16:3/267/0x00000002
[   18.441286] [T1700267] Call trace:
[   18.459691] [T1700267] BUG: workqueue leaked lock or atomic: kworker/u16:3/0xffffffff/267
[   18.464448] [T1700267] Call trace:
[   18.465839] [T1700267] BUG: workqueue leaked lock or atomic: kworker/u16:3/0xffffffff/267
[   18.468880] [T1700267] Call trace:
[   18.471529] [T1700267] BUG: scheduling while atomic: kworker/u16:3/267/0x00000000
[   18.537725] [T1200267] Call trace:
[   18.543333] [T1200267] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000150
[   18.544305] [T1200267] Internal error: Oops: 96000005 [#1] PREEMPT SMP
[   18.578235] [T1200267] Call trace:
[   18.578322] [T1200267]  ipanic_die+0x24/0x38 [mrdump]
```

## 修复建议

1. 检查 kernel log 中崩溃前的警告信息，寻找潜在问题线索
2. 确认 vmlinux 符号文件与运行内核版本完全匹配
3. 检查是否有内核模块修改了调度器相关数据结构
4. 使用 Kernel Address Sanitizer (KASAN) 重新编译内核以检测内存越界
5. 检查是否存在自旋锁或互斥锁的死锁情况
6. 分析看门狗超时前的系统状态，检查是否有无限循环或死锁
7. 考虑增加看门狗超时时间以收集更多信息

## 构建信息

```
alps-vf-mp-s0.mp1unknown:alps-vf-mp-s0.mp1unknown-V17.23_reallytek.s0mp1rc.k61v1.64.bsp_P18.V13.8_reallytek.v0mp1rc.k6991v1.64_P2:mt6789:S01,Infinix/X6886-OP/Infinix-X6886:15/AP3A.240
```

## 内核版本

```
5.10.226-android12-9-00047-g4968e29b7f92-ab12786767 (build-user@build-host) (Android (7284624, based on r416183b) clang version 12.0.5 (https://android.googlesource.com/toolchain/llvm-project c935d99d7cf2016289302412d708641d52d2f7ee), LLD 12.0.5 (/buildbot/src/android/llvm-toolchain/out/llvm-project/lld c935d99d7cf2016289302412d708641d52d2f7ee)) #1 SMP PREEMPT Wed Dec 11 21:50:47 UTC 2024
```

---
*Report generated by ke-analyzer on 2026-02-02 23:31:33*