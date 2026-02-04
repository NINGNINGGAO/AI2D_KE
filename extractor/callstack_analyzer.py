"""
增强的调用栈分析器
分析函数调用关系和调用场景
"""
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class CallFrame:
    """调用栈帧信息"""
    frame_number: int
    function_name: str
    address: Optional[str] = None
    module: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    
    # 增强信息
    function_type: Optional[str] = None  # syscall, irq, workqueue, timer, etc.
    subsystem: Optional[str] = None      # mm, fs, net, etc.
    is_kernel_core: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CallChain:
    """函数调用链"""
    caller: str
    callee: str
    call_type: str  # direct, indirect, callback, irq
    context: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StackAnalysis:
    """完整的调用栈分析结果"""
    frames: List[CallFrame] = field(default_factory=list)
    call_chains: List[CallChain] = field(default_factory=list)
    entry_point: Optional[str] = None
    crash_function: Optional[str] = None
    
    # 场景分析
    execution_context: Optional[str] = None  # process, irq, softirq, syscall
    subsystem_trace: List[str] = field(default_factory=list)
    
    # 可疑信息
    suspicious_patterns: List[Dict[str, str]] = field(default_factory=list)
    likely_scenarios: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'frames': [f.to_dict() for f in self.frames],
            'call_chains': [c.to_dict() for c in self.call_chains],
            'entry_point': self.entry_point,
            'crash_function': self.crash_function,
            'execution_context': self.execution_context,
            'subsystem_trace': self.subsystem_trace,
            'suspicious_patterns': self.suspicious_patterns,
            'likely_scenarios': self.likely_scenarios
        }


class CallStackAnalyzer:
    """调用栈分析器"""
    
    # 内核子系统识别模式
    SUBSYSTEM_PATTERNS = {
        'memory_management': ['mm/', 'slab', 'alloc', 'free', 'page', 'vma', 'pte'],
        'filesystem': ['fs/', 'vfs', 'inode', 'dentry', 'ext4', 'xfs'],
        'network': ['net/', 'tcp', 'udp', 'skbuff', 'socket'],
        'block': ['block/', 'bio', 'request', 'scsi'],
        'scheduling': ['sched', 'schedule', 'wait', 'wake', 'mutex'],
        'irq': ['irq', 'interrupt', 'handler'],
        'driver': ['driver', 'pci', 'usb', 'i2c', 'platform'],
        'security': ['security', 'selinux', 'apparmor'],
        'virtualization': ['kvm', 'hyperv', 'xen'],
    }
    
    # 执行上下文识别
    CONTEXT_PATTERNS = {
        'syscall': ['sys_', 'SyS_', 'do_syscall'],
        'irq': ['irq_handler', 'handle_irq', '__do_irq'],
        'softirq': ['do_softirq', '__softirqentry_text_start'],
        'workqueue': ['worker_thread', 'process_one_work'],
        'timer': ['timer_callback', 'hrtimer_', 'run_timer_softirq'],
        'kthread': ['kthread', 'kernel_thread'],
    }
    
    # 特殊内核函数
    KERNEL_CORE_FUNCTIONS = [
        'schedule', '__schedule', 'do_IRQ', 'ret_from_fork',
        'do_syscall', 'system_call', 'entry_', 'exit_'
    ]
    
    def __init__(self, crash_tool, gdb_tool, addr2line_tool):
        self.crash_tool = crash_tool
        self.gdb_tool = gdb_tool
        self.addr2line_tool = addr2line_tool
    
    async def analyze(self, vmcore_path: str, vmlinux_path: str, 
                      panic_overview: Optional[Dict] = None) -> StackAnalysis:
        """
        分析调用栈
        
        Args:
            vmcore_path: vmcore 文件路径
            vmlinux_path: vmlinux 文件路径
            panic_overview: 可选的 panic 概述信息
            
        Returns:
            StackAnalysis 对象
        """
        analysis = StackAnalysis()
        
        # 获取 backtrace
        bt_result = await self.crash_tool.get_backtrace(vmcore_path, vmlinux_path, all_cpus=False)
        if not bt_result.success:
            logger.error(f"Failed to get backtrace: {bt_result.stderr}")
            return analysis
        
        # 解析调用栈帧
        analysis.frames = self._parse_frames(bt_result.output)
        
        if not analysis.frames:
            logger.warning("No frames parsed from backtrace")
            return analysis
        
        # 设置关键帧
        analysis.crash_function = analysis.frames[0].function_name if analysis.frames else None
        analysis.entry_point = analysis.frames[-1].function_name if analysis.frames else None
        
        # 增强每帧信息
        await self._enhance_frames(analysis.frames, vmcore_path, vmlinux_path)
        
        # 构建调用链
        analysis.call_chains = self._build_call_chains(analysis.frames)
        
        # 分析执行上下文
        analysis.execution_context = self._detect_execution_context(analysis.frames)
        
        # 分析子系统路径
        analysis.subsystem_trace = self._trace_subsystems(analysis.frames)
        
        # 检测可疑模式
        analysis.suspicious_patterns = self._detect_suspicious_patterns(
            analysis.frames, panic_overview
        )
        
        # 推断可能场景
        analysis.likely_scenarios = self._infer_scenarios(
            analysis, panic_overview
        )
        
        return analysis
    
    def _parse_frames(self, bt_output: str) -> List[CallFrame]:
        """解析 backtrace 输出为帧列表"""
        frames = []
        
        for line in bt_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # crash bt 格式: #0 [ffff888123456000] __schedule at ffffffff81234567
            match = re.match(
                r'#(\d+)\s+\[([0-9a-fA-F]+)\]\s+(\S+)(?:\s+at\s+([0-9a-fA-F]+))?',
                line
            )
            
            if match:
                frame = CallFrame(
                    frame_number=int(match.group(1)),
                    function_name=match.group(3),
                    address=match.group(4) if match.group(4) else match.group(2)
                )
                frames.append(frame)
            else:
                # 尝试其他格式
                alt_match = re.match(r'#(\d+)\s+(\S+)\s*\(', line)
                if alt_match:
                    frame = CallFrame(
                        frame_number=int(alt_match.group(1)),
                        function_name=alt_match.group(2)
                    )
                    frames.append(frame)
        
        return frames
    
    async def _enhance_frames(self, frames: List[CallFrame], 
                              vmcore_path: str, vmlinux_path: str):
        """增强每帧的详细信息"""
        for frame in frames:
            # 识别函数类型和子系统
            frame.function_type = self._identify_function_type(frame.function_name)
            frame.subsystem = self._identify_subsystem(frame.function_name)
            frame.is_kernel_core = self._is_kernel_core_function(frame.function_name)
            
            # 尝试获取源代码位置
            if frame.address:
                try:
                    source_info = await self.addr2line_tool.resolve(
                        vmlinux_path, frame.address
                    )
                    if source_info:
                        frame.file_path = source_info.get('file')
                        frame.line_number = source_info.get('line')
                except Exception as e:
                    logger.debug(f"Failed to resolve source for {frame.function_name}: {e}")
    
    def _build_call_chains(self, frames: List[CallFrame]) -> List[CallChain]:
        """构建函数调用链"""
        chains = []
        
        for i in range(len(frames) - 1):
            caller = frames[i + 1].function_name
            callee = frames[i].function_name
            
            # 确定调用类型
            call_type = self._determine_call_type(caller, callee, frames[i])
            
            chain = CallChain(
                caller=caller,
                callee=callee,
                call_type=call_type,
                context=self._get_call_context(caller, callee)
            )
            chains.append(chain)
        
        return chains
    
    def _determine_call_type(self, caller: str, callee: str, 
                             callee_frame: CallFrame) -> str:
        """确定调用类型"""
        # 检查是否是中断处理
        if 'irq' in callee.lower() or 'interrupt' in callee.lower():
            return 'irq'
        
        # 检查是否是回调
        if any(x in callee.lower() for x in ['callback', 'handler', 'complete']):
            return 'callback'
        
        # 检查是否是系统调用
        if callee_frame.function_type == 'syscall':
            return 'syscall'
        
        # 检查是否是内核核心函数调度
        if callee_frame.is_kernel_core:
            return 'kernel_dispatch'
        
        return 'direct'
    
    def _get_call_context(self, caller: str, callee: str) -> Optional[str]:
        """获取调用上下文描述"""
        contexts = []
        
        # 检查内存分配
        if any(x in callee.lower() for x in ['kmalloc', 'kzalloc', 'vmalloc']):
            contexts.append("memory allocation")
        
        # 检查锁操作
        if any(x in callee.lower() for x in ['mutex', 'spin_lock', 'rwsem']):
            contexts.append("synchronization")
        
        # 检查调度
        if any(x in callee.lower() for x in ['schedule', 'sleep', 'wait']):
            contexts.append("task scheduling")
        
        # 检查IO
        if any(x in callee.lower() for x in ['read', 'write', 'io', 'request']):
            contexts.append("I/O operation")
        
        return ', '.join(contexts) if contexts else None
    
    def _detect_execution_context(self, frames: List[CallFrame]) -> str:
        """检测执行上下文"""
        all_functions = [f.function_name for f in frames]
        all_text = ' '.join(all_functions).lower()
        
        for context, patterns in self.CONTEXT_PATTERNS.items():
            if any(p in all_text for p in patterns):
                return context
        
        # 检查是否是进程上下文
        if frames:
            # 如果最顶层是内核核心函数，可能是进程上下文
            if frames[-1].is_kernel_core:
                return 'process'
        
        return 'unknown'
    
    def _trace_subsystems(self, frames: List[CallFrame]) -> List[str]:
        """追踪涉及的子系统"""
        subsystems = []
        seen = set()
        
        for frame in frames:
            if frame.subsystem and frame.subsystem not in seen:
                subsystems.append(frame.subsystem)
                seen.add(frame.subsystem)
        
        return subsystems
    
    def _detect_suspicious_patterns(self, frames: List[CallFrame],
                                    panic_overview: Optional[Dict]) -> List[Dict[str, str]]:
        """检测可疑模式"""
        patterns = []
        
        all_functions = [f.function_name for f in frames]
        all_text = ' '.join(all_functions).lower()
        
        # 检查递归调用
        seen_funcs = {}
        for i, func in enumerate(all_functions):
            if func in seen_funcs:
                patterns.append({
                    'type': 'recursion',
                    'severity': 'high',
                    'description': f"Possible recursion detected: {func} appears at frames "
                                   f"{seen_funcs[func]} and {i}",
                    'affected_function': func
                })
            else:
                seen_funcs[func] = i
        
        # 检查异常的调用深度
        if len(frames) > 50:
            patterns.append({
                'type': 'deep_stack',
                'severity': 'medium',
                'description': f"Unusually deep call stack ({len(frames)} frames) - "
                               "possible stack overflow or infinite recursion",
                'affected_function': frames[0].function_name
            })
        
        # 检查 IRQ 相关的可疑模式
        irq_frames = [f for f in frames if 'irq' in f.function_name.lower()]
        if len(irq_frames) > 3:
            patterns.append({
                'type': 'nested_irq',
                'severity': 'high',
                'description': f"Multiple IRQ frames detected ({len(irq_frames)}) - "
                               "possible interrupt storm or recursive interrupt",
                'affected_function': irq_frames[0].function_name
            })
        
        # 检查锁相关的可疑模式
        lock_frames = [f for f in frames if any(x in f.function_name.lower() 
                                                 for x in ['lock', 'mutex'])]
        if len(lock_frames) > 5:
            patterns.append({
                'type': 'lock_heavy',
                'severity': 'medium',
                'description': f"Heavy locking activity ({len(lock_frames)} lock-related frames) - "
                               "possible lock contention",
                'affected_function': lock_frames[0].function_name
            })
        
        # 检查调度相关的可疑模式
        sched_frames = [f for f in frames if any(x in f.function_name.lower() 
                                                  for x in ['schedule', 'sleep'])]
        if len(sched_frames) > 3:
            patterns.append({
                'type': 'frequent_scheduling',
                'severity': 'low',
                'description': f"Frequent scheduling calls ({len(sched_frames)} frames) - "
                               "may indicate CPU intensive work",
                'affected_function': sched_frames[0].function_name
            })
        
        # 基于 panic 类型的额外检查
        if panic_overview:
            crash_type = panic_overview.get('crash_type', '')
            if 'NULL' in crash_type and any('copy' in f.lower() for f in all_functions):
                patterns.append({
                    'type': 'null_in_copy',
                    'severity': 'high',
                    'description': "NULL pointer in copy operation - check source/destination pointers",
                    'affected_function': frames[0].function_name
                })
        
        return patterns
    
    def _infer_scenarios(self, analysis: StackAnalysis, 
                         panic_overview: Optional[Dict]) -> List[str]:
        """推断可能的崩溃场景"""
        scenarios = []
        frames = analysis.frames
        
        if not frames:
            return scenarios
        
        crash_func = analysis.crash_function
        entry_func = analysis.entry_point
        context = analysis.execution_context
        
        # 基于执行上下文的场景
        if context == 'irq':
            scenarios.append(
                f"Interrupt handler '{crash_func}' failed while processing hardware interrupt. "
                "Check for shared IRQ conflicts or driver issues."
            )
        elif context == 'syscall':
            scenarios.append(
                f"System call from userspace triggered crash in '{crash_func}'. "
                "Check for invalid arguments or unsafe pointer access."
            )
        elif context == 'workqueue':
            scenarios.append(
                f"Deferred work in '{crash_func}' failed. Check for race conditions "
                "between workqueue handler and other code paths."
            )
        elif context == 'timer':
            scenarios.append(
                f"Timer callback '{crash_func}' crashed. May be due to timer "
                "reentry or use-after-free of timer data."
            )
        
        # 基于子系统的场景
        if analysis.subsystem_trace:
            primary_subsys = analysis.subsystem_trace[0]
            if primary_subsys == 'memory_management':
                scenarios.append(
                    "Memory management operation failed. Possible causes: "
                    "double-free, use-after-free, or corrupted memory metadata."
                )
            elif primary_subsys == 'filesystem':
                scenarios.append(
                    "Filesystem operation failed. Check for corrupted filesystem, "
                    "race conditions in VFS, or driver bugs."
                )
            elif primary_subsys == 'network':
                scenarios.append(
                    "Network stack crash. May be triggered by malformed packets, "
                    "race conditions in socket handling, or driver issues."
                )
        
        # 基于调用链的场景
        if analysis.call_chains:
            first_chain = analysis.call_chains[0]
            if first_chain.call_type == 'callback':
                scenarios.append(
                    f"Callback function '{crash_func}' crashed when invoked by "
                    f"'{first_chain.caller}'. Check callback registration and "
                    "lifetime management."
                )
        
        # 基于 panic 类型的场景
        if panic_overview:
            crash_type = panic_overview.get('crash_type', '')
            if 'Watchdog' in crash_type:
                scenarios.append(
                    "System became unresponsive, likely due to: "
                    "(1) Infinite loop in kernel code, "
                    "(2) Deadlock with interrupts disabled, or "
                    "(3) Hardware interrupt storm."
                )
            elif 'NULL' in crash_type:
                scenarios.append(
                    "NULL pointer dereference suggests: "
                    "(1) Missing NULL check after allocation failure, "
                    "(2) Uninitialized pointer, or "
                    "(3) Race condition between init and access."
                )
        
        return scenarios
    
    def _identify_function_type(self, function_name: str) -> Optional[str]:
        """识别函数类型"""
        fn_lower = function_name.lower()
        
        for ftype, patterns in self.CONTEXT_PATTERNS.items():
            if any(p in fn_lower for p in patterns):
                return ftype
        
        return None
    
    def _identify_subsystem(self, function_name: str) -> Optional[str]:
        """识别所属子系统"""
        fn_lower = function_name.lower()
        
        for subsys, patterns in self.SUBSYSTEM_PATTERNS.items():
            if any(p in fn_lower for p in patterns):
                return subsys
        
        return None
    
    def _is_kernel_core_function(self, function_name: str) -> bool:
        """检查是否是内核核心函数"""
        fn_lower = function_name.lower()
        return any(core.lower() in fn_lower for core in self.KERNEL_CORE_FUNCTIONS)
    
    async def get_function_arguments(self, frame: CallFrame, vmcore_path: str, 
                                     vmlinux_path: str) -> Dict[str, Any]:
        """
        获取函数的参数信息
        
        使用 GDB 分析特定栈帧的参数
        """
        args = {}
        
        try:
            # 获取 frame 信息
            frame_idx = frame.frame_number
            
            # 使用 GDB 获取参数
            commands = [
                f"frame {frame_idx}",
                "info args",
                "info locals"
            ]
            
            result = await self.gdb_tool.execute(vmlinux_path, commands, vmcore_path)
            if result.success:
                output = result.output
                
                # 解析参数
                in_args = False
                in_locals = False
                
                for line in output.split('\n'):
                    line = line.strip()
                    
                    if 'arguments' in line.lower():
                        in_args = True
                        in_locals = False
                        continue
                    
                    if 'local variables' in line.lower():
                        in_args = False
                        in_locals = True
                        continue
                    
                    if '= ' in line:
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            name = parts[0].strip()
                            value = parts[1].strip()
                            
                            if in_args:
                                args[name] = {'value': value, 'type': 'argument'}
                            elif in_locals:
                                args[name] = {'value': value, 'type': 'local'}
        
        except Exception as e:
            logger.error(f"Failed to get function arguments: {e}")
        
        return args
