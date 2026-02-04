"""
高级寄存器分析器
追踪寄存器变化历史和函数入参分析
"""
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class RegisterType(Enum):
    """寄存器类型"""
    GENERAL_PURPOSE = "general"
    STACK_POINTER = "stack"
    FRAME_POINTER = "frame"
    PROGRAM_COUNTER = "pc"
    LINK_REGISTER = "link"
    STATUS = "status"


@dataclass
class RegisterValue:
    """寄存器值"""
    name: str
    value: str
    register_type: RegisterType
    
    # 分析信息
    is_null: bool = False
    is_kernel_addr: bool = False
    is_user_addr: bool = False
    is_stack_addr: bool = False
    is_valid_ptr: bool = False
    
    def __post_init__(self):
        self._analyze_value()
    
    def _analyze_value(self):
        """分析寄存器值"""
        try:
            val = int(self.value, 16) if self.value.startswith('0x') else int(self.value)
            
            # 检查 NULL
            self.is_null = (val == 0)
            
            # 检查内核地址 (64-bit Linux kernel space)
            self.is_kernel_addr = (val >= 0xFFFF000000000000)
            
            # 检查用户地址
            self.is_user_addr = (0x0 < val < 0x00007FFFFFFFFFFF)
            
            # 检查是否是有效的指针（粗略检查）
            self.is_valid_ptr = self.is_kernel_addr or self.is_user_addr
            
        except (ValueError, TypeError):
            pass
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RegisterHistory:
    """寄存器历史记录"""
    instruction_address: str
    instruction: str
    register_name: str
    old_value: Optional[str]
    new_value: str
    operation: str  # mov, load, store, arithmetic, etc.
    source_info: Optional[str] = None  # 来自哪个内存地址或寄存器
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionRegisterState:
    """函数寄存器状态"""
    function_name: str
    frame_index: int
    entry_registers: Dict[str, RegisterValue] = field(default_factory=dict)
    exit_registers: Dict[str, RegisterValue] = field(default_factory=dict)
    register_history: List[RegisterHistory] = field(default_factory=list)
    
    # 关键参数
    arguments: Dict[str, Any] = field(default_factory=dict)
    return_value: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'frame_index': self.frame_index,
            'entry_registers': {k: v.to_dict() for k, v in self.entry_registers.items()},
            'exit_registers': {k: v.to_dict() for k, v in self.exit_registers.items()},
            'register_history': [h.to_dict() for h in self.register_history],
            'arguments': self.arguments,
            'return_value': self.return_value
        }


@dataclass
class RegisterAnalysis:
    """完整的寄存器分析结果"""
    # 当前寄存器状态
    current_registers: Dict[str, RegisterValue] = field(default_factory=dict)
    
    # 崩溃时关键寄存器
    crash_pc: Optional[str] = None
    crash_sp: Optional[str] = None
    crash_fp: Optional[str] = None
    faulting_address: Optional[str] = None
    
    # 每帧的寄存器状态
    frame_states: List[FunctionRegisterState] = field(default_factory=list)
    
    # 关键发现
    suspicious_registers: List[Dict[str, Any]] = field(default_factory=list)
    register_chain: List[Dict[str, Any]] = field(default_factory=list)
    
    # 分析结论
    likely_fault_source: Optional[str] = None
    root_cause_function: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'current_registers': {k: v.to_dict() for k, v in self.current_registers.items()},
            'crash_pc': self.crash_pc,
            'crash_sp': self.crash_sp,
            'crash_fp': self.crash_fp,
            'faulting_address': self.faulting_address,
            'frame_states': [s.to_dict() for s in self.frame_states],
            'suspicious_registers': self.suspicious_registers,
            'register_chain': self.register_chain,
            'likely_fault_source': self.likely_fault_source,
            'root_cause_function': self.root_cause_function
        }


class AdvancedRegisterAnalyzer:
    """高级寄存器分析器"""
    
    # ARM64 寄存器定义
    ARM64_REGISTERS = {
        'x0': RegisterType.GENERAL_PURPOSE,
        'x1': RegisterType.GENERAL_PURPOSE,
        'x2': RegisterType.GENERAL_PURPOSE,
        'x3': RegisterType.GENERAL_PURPOSE,
        'x4': RegisterType.GENERAL_PURPOSE,
        'x5': RegisterType.GENERAL_PURPOSE,
        'x6': RegisterType.GENERAL_PURPOSE,
        'x7': RegisterType.GENERAL_PURPOSE,
        'x8': RegisterType.GENERAL_PURPOSE,
        'x9': RegisterType.GENERAL_PURPOSE,
        'x10': RegisterType.GENERAL_PURPOSE,
        'x11': RegisterType.GENERAL_PURPOSE,
        'x12': RegisterType.GENERAL_PURPOSE,
        'x13': RegisterType.GENERAL_PURPOSE,
        'x14': RegisterType.GENERAL_PURPOSE,
        'x15': RegisterType.GENERAL_PURPOSE,
        'x16': RegisterType.GENERAL_PURPOSE,
        'x17': RegisterType.GENERAL_PURPOSE,
        'x18': RegisterType.GENERAL_PURPOSE,
        'x19': RegisterType.GENERAL_PURPOSE,
        'x20': RegisterType.GENERAL_PURPOSE,
        'x21': RegisterType.GENERAL_PURPOSE,
        'x22': RegisterType.GENERAL_PURPOSE,
        'x23': RegisterType.GENERAL_PURPOSE,
        'x24': RegisterType.GENERAL_PURPOSE,
        'x25': RegisterType.GENERAL_PURPOSE,
        'x26': RegisterType.GENERAL_PURPOSE,
        'x27': RegisterType.GENERAL_PURPOSE,
        'x28': RegisterType.GENERAL_PURPOSE,
        'x29': RegisterType.FRAME_POINTER,  # FP
        'x30': RegisterType.LINK_REGISTER,  # LR
        'sp': RegisterType.STACK_POINTER,
        'pc': RegisterType.PROGRAM_COUNTER,
    }
    
    # x86_64 寄存器定义
    X86_64_REGISTERS = {
        'rax': RegisterType.GENERAL_PURPOSE,
        'rbx': RegisterType.GENERAL_PURPOSE,
        'rcx': RegisterType.GENERAL_PURPOSE,
        'rdx': RegisterType.GENERAL_PURPOSE,
        'rsi': RegisterType.GENERAL_PURPOSE,
        'rdi': RegisterType.GENERAL_PURPOSE,
        'rbp': RegisterType.FRAME_POINTER,
        'rsp': RegisterType.STACK_POINTER,
        'r8': RegisterType.GENERAL_PURPOSE,
        'r9': RegisterType.GENERAL_PURPOSE,
        'r10': RegisterType.GENERAL_PURPOSE,
        'r11': RegisterType.GENERAL_PURPOSE,
        'r12': RegisterType.GENERAL_PURPOSE,
        'r13': RegisterType.GENERAL_PURPOSE,
        'r14': RegisterType.GENERAL_PURPOSE,
        'r15': RegisterType.GENERAL_PURPOSE,
        'rip': RegisterType.PROGRAM_COUNTER,
        'eflags': RegisterType.STATUS,
    }
    
    def __init__(self, crash_tool, gdb_tool):
        self.crash_tool = crash_tool
        self.gdb_tool = gdb_tool
        self.arch = 'arm64'  # 默认架构，可以通过检测设置
    
    async def analyze(self, vmcore_path: str, vmlinux_path: str,
                      callstack_info: Optional[List[Dict]] = None,
                      panic_overview: Optional[Dict] = None) -> RegisterAnalysis:
        """
        执行完整的寄存器分析
        
        Args:
            vmcore_path: vmcore 文件路径
            vmlinux_path: vmlinux 文件路径
            callstack_info: 可选的调用栈信息
            panic_overview: 可选的 panic 概述
            
        Returns:
            RegisterAnalysis 对象
        """
        analysis = RegisterAnalysis()
        
        # 1. 获取当前寄存器状态
        analysis.current_registers = await self._get_current_registers(
            vmcore_path, vmlinux_path
        )
        
        if not analysis.current_registers:
            logger.error("Failed to get current registers")
            return analysis
        
        # 2. 识别关键寄存器
        self._identify_critical_registers(analysis)
        
        # 3. 分析每帧的寄存器状态
        if callstack_info:
            analysis.frame_states = await self._analyze_frame_registers(
                callstack_info, vmcore_path, vmlinux_path
            )
        
        # 4. 追踪寄存器变化链
        analysis.register_chain = self._trace_register_chain(analysis)
        
        # 5. 检测可疑寄存器
        analysis.suspicious_registers = self._detect_suspicious_registers(
            analysis, panic_overview
        )
        
        # 6. 推断故障源
        analysis.likely_fault_source = self._infer_fault_source(analysis)
        analysis.root_cause_function = self._identify_root_cause_function(
            analysis, callstack_info
        )
        
        return analysis
    
    async def _get_current_registers(self, vmcore_path: str, 
                                     vmlinux_path: str) -> Dict[str, RegisterValue]:
        """获取当前寄存器状态"""
        registers = {}
        
        # 使用 crash 获取寄存器
        result = await self.crash_tool.execute(vmcore_path, 'bt -a', vmlinux_path)
        if result.success:
            # 从 bt -a 输出中解析寄存器
            bt_regs = self._parse_registers_from_bt(result.output)
            registers.update(bt_regs)
        
        # 使用 GDB 获取更多寄存器信息
        gdb_result = await self.gdb_tool.get_registers(vmlinux_path, vmcore_path)
        if gdb_result.success:
            gdb_regs = self._parse_registers_from_gdb(gdb_result.output)
            registers.update(gdb_regs)
        
        return registers
    
    def _parse_registers_from_bt(self, bt_output: str) -> Dict[str, RegisterValue]:
        """从 crash bt 输出解析寄存器"""
        registers = {}
        
        # ARM64 寄存器模式
        # PC: ffffffe91549e3b8  LR: ffffffe91549e390
        # SP: ffffffc00801bcf0  PSTATE: 604001c5
        patterns = [
            (r'(PC)\s*:\s*(0x[0-9a-fA-F]+)', RegisterType.PROGRAM_COUNTER),
            (r'(LR)\s*:\s*(0x[0-9a-fA-F]+)', RegisterType.LINK_REGISTER),
            (r'(SP)\s*:\s*(0x[0-9a-fA-F]+)', RegisterType.STACK_POINTER),
            (r'(x\d+)\s*:\s*(0x[0-9a-fA-F]+|\d+)', RegisterType.GENERAL_PURPOSE),
        ]
        
        for pattern, reg_type in patterns:
            for match in re.finditer(pattern, bt_output, re.IGNORECASE):
                reg_name = match.group(1).lower()
                reg_value = match.group(2)
                
                registers[reg_name] = RegisterValue(
                    name=reg_name,
                    value=reg_value,
                    register_type=reg_type
                )
        
        return registers
    
    def _parse_registers_from_gdb(self, gdb_output: str) -> Dict[str, RegisterValue]:
        """从 GDB 寄存器输出解析"""
        registers = {}
        
        # 匹配 x0 0xffffffc02b3cbd88 或 x0 : 0xffffffc02b3cbd88
        pattern = r'(x\d+|sp|pc|lr|fp|xzr)\s*:?\s+(0x[0-9a-fA-F]+|\d+)'
        
        for match in re.finditer(pattern, gdb_output, re.IGNORECASE):
            reg_name = match.group(1).lower()
            reg_value = match.group(2)
            
            # 确定寄存器类型
            reg_type = self._get_register_type(reg_name)
            
            registers[reg_name] = RegisterValue(
                name=reg_name,
                value=reg_value,
                register_type=reg_type
            )
        
        return registers
    
    def _get_register_type(self, reg_name: str) -> RegisterType:
        """获取寄存器类型"""
        if self.arch == 'arm64':
            return self.ARM64_REGISTERS.get(reg_name, RegisterType.GENERAL_PURPOSE)
        else:
            return self.X86_64_REGISTERS.get(reg_name, RegisterType.GENERAL_PURPOSE)
    
    def _identify_critical_registers(self, analysis: RegisterAnalysis):
        """识别崩溃时的关键寄存器"""
        regs = analysis.current_registers
        
        # PC
        if 'pc' in regs:
            analysis.crash_pc = regs['pc'].value
        
        # SP
        if 'sp' in regs:
            analysis.crash_sp = regs['sp'].value
        
        # FP (x29 in ARM64)
        if 'x29' in regs:
            analysis.crash_fp = regs['x29'].value
        elif 'fp' in regs:
            analysis.crash_fp = regs['fp'].value
        
        # 推断故障地址
        analysis.faulting_address = self._infer_faulting_address(regs)
    
    def _infer_faulting_address(self, registers: Dict[str, RegisterValue]) -> Optional[str]:
        """推断导致崩溃的内存地址"""
        # 检查 X0 - 通常是 NULL pointer 的目标
        if 'x0' in registers:
            x0 = registers['x0']
            if x0.is_null:
                return "0x0 (via X0 - NULL pointer)"
        
        # 检查其他可能包含地址的寄存器
        for reg_name in ['x1', 'x2', 'x3', 'x4', 'x5']:
            if reg_name in registers:
                reg = registers[reg_name]
                if reg.is_user_addr:
                    return f"{reg.value} (userspace address in {reg_name.upper()})"
        
        return None
    
    async def _analyze_frame_registers(self, callstack_info: List[Dict],
                                       vmcore_path: str, vmlinux_path: str) -> List[FunctionRegisterState]:
        """分析每帧的寄存器状态"""
        frame_states = []
        
        for i, frame in enumerate(callstack_info[:5]):  # 只分析前5帧
            func_name = frame.get('function', f"frame_{i}")
            func_addr = frame.get('address')
            
            state = FunctionRegisterState(
                function_name=func_name,
                frame_index=i
            )
            
            try:
                # 获取该函数的汇编
                asm_result = await self.gdb_tool.get_function_assembly_with_context(
                    vmlinux_path, func_name, vmcore_path, context_instructions=30
                )
                
                if asm_result.get('success'):
                    # 分析该函数的寄存器使用
                    state.register_history = self._analyze_register_usage(
                        asm_result['assembly'], func_name
                    )
                    
                    # 尝试获取参数信息
                    if i == 0:  # 只在崩溃函数获取详细参数
                        state.arguments = await self._extract_function_arguments(
                            func_name, vmcore_path, vmlinux_path
                        )
                
            except Exception as e:
                logger.warning(f"Failed to analyze registers for {func_name}: {e}")
            
            frame_states.append(state)
        
        return frame_states
    
    def _analyze_register_usage(self, assembly: str, 
                                function_name: str) -> List[RegisterHistory]:
        """分析函数中的寄存器使用"""
        history = []
        
        lines = assembly.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 解析汇编行
            # 格式示例: 0xffffffe91549e3b8 <+24>: ldr x0, [x19, #16]
            match = re.match(
                r'(0x[0-9a-fA-F]+).*:?\s*(\w+)\s+(.+)',
                line
            )
            
            if match:
                addr = match.group(1)
                opcode = match.group(2)
                operands = match.group(3)
                
                # 分析寄存器操作
                reg_hist = self._parse_register_operation(
                    addr, opcode, operands, function_name
                )
                if reg_hist:
                    history.append(reg_hist)
        
        return history
    
    def _parse_register_operation(self, addr: str, opcode: str, 
                                  operands: str, func_name: str) -> Optional[RegisterHistory]:
        """解析寄存器操作"""
        # ARM64 指令分析
        
        # MOV/LOAD 指令: ldr x0, [x1], mov x0, x1
        if opcode in ['ldr', 'ldp', 'mov', 'movk', 'adr', 'adrp']:
            # 提取目标寄存器
            match = re.match(r'(x\d+|sp|pc|lr|fp)\s*,', operands)
            if match:
                dest_reg = match.group(1)
                
                return RegisterHistory(
                    instruction_address=addr,
                    instruction=f"{opcode} {operands}",
                    register_name=dest_reg,
                    old_value=None,  # 无法知道旧值
                    new_value=f"computed from {operands}",
                    operation=opcode,
                    source_info=operands
                )
        
        # ARITHMETIC 指令: add x0, x1, x2
        elif opcode in ['add', 'sub', 'mul', 'and', 'orr', 'eor']:
            match = re.match(r'(x\d+|sp)\s*,', operands)
            if match:
                dest_reg = match.group(1)
                
                return RegisterHistory(
                    instruction_address=addr,
                    instruction=f"{opcode} {operands}",
                    register_name=dest_reg,
                    old_value=None,
                    new_value=f"result of {opcode}",
                    operation='arithmetic',
                    source_info=operands
                )
        
        return None
    
    async def _extract_function_arguments(self, function_name: str,
                                          vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]:
        """提取函数参数信息"""
        args = {}
        
        try:
            # 使用 GDB 获取参数
            commands = ["info args", "info locals"]
            result = await self.gdb_tool.execute(vmlinux_path, commands, vmcore_path)
            
            if result.success:
                args = self._parse_arguments(result.output)
        
        except Exception as e:
            logger.warning(f"Failed to extract arguments for {function_name}: {e}")
        
        return args
    
    def _parse_arguments(self, gdb_output: str) -> Dict[str, Any]:
        """解析 GDB 参数输出"""
        args = {}
        
        current_section = None
        for line in gdb_output.split('\n'):
            line = line.strip()
            
            if 'arguments' in line.lower():
                current_section = 'args'
                continue
            if 'local variables' in line.lower():
                current_section = 'locals'
                continue
            
            if '= ' in line:
                parts = line.split('=', 1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    value = parts[1].strip()
                    
                    # 分析参数值
                    arg_info = {'value': value, 'type': current_section}
                    
                    # 如果是地址，分析地址类型
                    if value.startswith('0x'):
                        try:
                            addr = int(value, 16)
                            if addr == 0:
                                arg_info['is_null'] = True
                                arg_info['risk'] = 'NULL pointer'
                            elif addr < 0x1000:
                                arg_info['risk'] = 'Very low address - likely invalid'
                            elif addr >= 0xFFFF000000000000:
                                arg_info['addr_type'] = 'kernel'
                            else:
                                arg_info['addr_type'] = 'userspace'
                        except ValueError:
                            pass
                    
                    args[name] = arg_info
        
        return args
    
    def _trace_register_chain(self, analysis: RegisterAnalysis) -> List[Dict[str, Any]]:
        """追踪寄存器变化链"""
        chain = []
        
        # 分析从哪个寄存器/内存地址获取了崩溃地址
        if 'x0' in analysis.current_registers:
            x0 = analysis.current_registers['x0']
            
            chain.append({
                'step': 1,
                'register': 'X0',
                'value': x0.value,
                'description': 'Target address for memory access',
                'is_suspicious': x0.is_null or x0.is_user_addr
            })
            
            if x0.is_null:
                chain.append({
                    'step': 2,
                    'description': 'X0 is NULL - likely cause of crash',
                    'recommendation': 'Check where X0 was set and why it is NULL'
                })
        
        # 分析 X1-X7 (参数寄存器)
        for i in range(1, 8):
            reg_name = f'x{i}'
            if reg_name in analysis.current_registers:
                reg = analysis.current_registers[reg_name]
                if reg.is_null or reg.is_user_addr:
                    chain.append({
                        'step': len(chain) + 1,
                        'register': reg_name.upper(),
                        'value': reg.value,
                        'description': f'Argument register {reg_name.upper()} has suspicious value',
                        'is_suspicious': True
                    })
        
        return chain
    
    def _detect_suspicious_registers(self, analysis: RegisterAnalysis,
                                     panic_overview: Optional[Dict]) -> List[Dict[str, Any]]:
        """检测可疑寄存器"""
        suspicious = []
        
        regs = analysis.current_registers
        
        # 检查 X0 (通常是操作的目标)
        if 'x0' in regs:
            x0 = regs['x0']
            if x0.is_null:
                suspicious.append({
                    'register': 'X0',
                    'value': x0.value,
                    'severity': 'critical',
                    'issue': 'NULL pointer in X0',
                    'description': 'X0 contains NULL, which is likely the cause of the crash',
                    'likely_cause': 'Missing NULL check or uninitialized pointer'
                })
            elif x0.is_user_addr:
                suspicious.append({
                    'register': 'X0',
                    'value': x0.value,
                    'severity': 'high',
                    'issue': 'Userspace address in kernel context',
                    'description': 'X0 contains a userspace address, may indicate missing copy_from_user()',
                    'likely_cause': 'Direct userspace pointer access'
                })
        
        # 检查 SP (栈指针)
        if 'sp' in regs:
            sp = regs['sp']
            # 检查栈是否对齐
            try:
                sp_val = int(sp.value, 16)
                if sp_val % 16 != 0:
                    suspicious.append({
                        'register': 'SP',
                        'value': sp.value,
                        'severity': 'medium',
                        'issue': 'Stack pointer misaligned',
                        'description': 'SP is not 16-byte aligned, may indicate stack corruption',
                        'likely_cause': 'Stack corruption or unwinding error'
                    })
            except ValueError:
                pass
        
        # 检查 LR (返回地址)
        if 'x30' in regs or 'lr' in regs:
            lr_name = 'x30' if 'x30' in regs else 'lr'
            lr = regs[lr_name]
            if lr.is_null:
                suspicious.append({
                    'register': 'LR',
                    'value': lr.value,
                    'severity': 'high',
                    'issue': 'NULL return address',
                    'description': 'Link register is NULL, function cannot return properly',
                    'likely_cause': 'Stack corruption or function pointer overwrite'
                })
        
        # 基于崩溃类型的额外检查
        if panic_overview:
            crash_type = panic_overview.get('crash_type', '')
            fault_addr = panic_overview.get('fault_address')
            
            if fault_addr:
                # 检查哪个寄存器可能包含故障地址
                for reg_name, reg_val in regs.items():
                    if reg_val.value.lower() == fault_addr.lower():
                        suspicious.append({
                            'register': reg_name.upper(),
                            'value': reg_val.value,
                            'severity': 'critical',
                            'issue': f'Register contains faulting address',
                            'description': f'{reg_name.upper()} contains the address that caused the fault',
                            'likely_cause': f'Check how {reg_name.upper()} was set and why the address is invalid'
                        })
        
        return suspicious
    
    def _infer_fault_source(self, analysis: RegisterAnalysis) -> Optional[str]:
        """推断故障源"""
        
        # 如果有 NULL 指针
        for susp in analysis.suspicious_registers:
            if susp.get('issue') == 'NULL pointer in X0':
                return "NULL pointer dereference - X0 was not properly initialized or checked"
        
        # 如果有用户空间地址
        for susp in analysis.suspicious_registers:
            if 'Userspace address' in susp.get('issue', ''):
                return "Userspace address accessed in kernel context - missing copy_from_user()"
        
        # 基于寄存器链分析
        if analysis.register_chain:
            for entry in analysis.register_chain:
                if entry.get('is_suspicious'):
                    return f"Suspicious value in {entry.get('register')} led to crash"
        
        return None
    
    def _identify_root_cause_function(self, analysis: RegisterAnalysis,
                                      callstack_info: Optional[List[Dict]]) -> Optional[str]:
        """识别根因函数"""
        
        # 分析可疑寄存器的来源
        if analysis.suspicious_registers:
            # 如果第一帧有可疑寄存器，根因可能在当前函数
            if analysis.frame_states:
                return analysis.frame_states[0].function_name
        
        # 如果有调用栈，分析参数传递
        if callstack_info and len(callstack_info) > 1:
            # 检查第二帧是否传递了可疑参数
            second_frame = callstack_info[1]
            return f"Possibly {second_frame.get('function')} - check argument passing"
        
        return None
    
    def format_analysis_report(self, analysis: RegisterAnalysis) -> str:
        """格式化分析报告"""
        lines = []
        
        lines.append("=" * 60)
        lines.append("REGISTER ANALYSIS REPORT")
        lines.append("=" * 60)
        
        # 当前寄存器状态
        lines.append("\n[Current Register State]")
        for reg_name, reg_val in analysis.current_registers.items():
            flags = []
            if reg_val.is_null:
                flags.append("NULL")
            if reg_val.is_kernel_addr:
                flags.append("KERNEL")
            if reg_val.is_user_addr:
                flags.append("USER")
            
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            lines.append(f"  {reg_name.upper():4s}: {reg_val.value}{flag_str}")
        
        # 关键崩溃信息
        lines.append("\n[Critical Crash Information]")
        if analysis.crash_pc:
            lines.append(f"  Crash PC: {analysis.crash_pc}")
        if analysis.crash_sp:
            lines.append(f"  Stack Pointer: {analysis.crash_sp}")
        if analysis.faulting_address:
            lines.append(f"  Faulting Address: {analysis.faulting_address}")
        
        # 可疑寄存器
        if analysis.suspicious_registers:
            lines.append("\n[Suspicious Registers Detected]")
            for susp in analysis.suspicious_registers:
                lines.append(f"  [!] {susp['register']}: {susp['issue']}")
                lines.append(f"      Value: {susp['value']}")
                lines.append(f"      Severity: {susp['severity'].upper()}")
                lines.append(f"      Likely Cause: {susp['likely_cause']}")
                lines.append("")
        
        # 寄存器变化链
        if analysis.register_chain:
            lines.append("\n[Register Chain Analysis]")
            for entry in analysis.register_chain:
                if 'register' in entry:
                    mark = "⚠️ " if entry.get('is_suspicious') else "  "
                    lines.append(f"  {mark}Step {entry['step']}: {entry['register']} = {entry['value']}")
                    lines.append(f"          {entry['description']}")
                else:
                    lines.append(f"    Step {entry['step']}: {entry['description']}")
                    if 'recommendation' in entry:
                        lines.append(f"          → {entry['recommendation']}")
        
        # 根因推断
        lines.append("\n[Root Cause Analysis]")
        if analysis.likely_fault_source:
            lines.append(f"  Likely Fault Source: {analysis.likely_fault_source}")
        if analysis.root_cause_function:
            lines.append(f"  Suspected Function: {analysis.root_cause_function}")
        
        # 每帧的寄存器状态
        if analysis.frame_states:
            lines.append("\n[Per-Frame Register States]")
            for state in analysis.frame_states[:3]:  # 只显示前3帧
                lines.append(f"\n  Frame {state.frame_index}: {state.function_name}")
                if state.arguments:
                    lines.append(f"    Arguments/Locals:")
                    for arg_name, arg_info in state.arguments.items():
                        risk = f" [RISK: {arg_info.get('risk')}]" if arg_info.get('risk') else ""
                        lines.append(f"      {arg_name} = {arg_info['value']}{risk}")
        
        lines.append("\n" + "=" * 60)
        
        return "\n".join(lines)
