"""
Assembly Level Analyzer - 汇编层次分析器
提供基于寄存器和汇编指令的深度分析能力
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RegisterType(Enum):
    """寄存器类型"""
    GENERAL_PURPOSE = "gp"      # 通用寄存器 X0-X30
    STACK_POINTER = "sp"        # 栈指针 SP
    PROGRAM_COUNTER = "pc"      # 程序计数器 PC
    FRAME_POINTER = "fp"        # 帧指针 X29
    LINK_REGISTER = "lr"        # 链接寄存器 X30
    ZERO_REGISTER = "xzr"       # 零寄存器 XZR


class InstructionType(Enum):
    """指令类型"""
    LOAD = "load"               # 加载指令 (LDR, LDRB, LDRH, etc.)
    STORE = "store"             # 存储指令 (STR, STRB, STRH, etc.)
    ARITHMETIC = "arithmetic"   # 算术指令 (ADD, SUB, MUL, etc.)
    LOGICAL = "logical"         # 逻辑指令 (AND, ORR, EOR, etc.)
    BRANCH = "branch"           # 分支指令 (B, BL, BR, RET, etc.)
    MOVE = "move"               # 数据传输 (MOV, MVN, etc.)
    COMPARE = "compare"         # 比较指令 (CMP, TST, etc.)
    SYSTEM = "system"           # 系统指令 (MSR, MRS, etc.)
    UNKNOWN = "unknown"


class AnomalyType(Enum):
    """异常类型"""
    NULL_POINTER = "null_pointer"           # 空指针访问
    BITFLIP = "bitflip"                     # 位翻转
    MEMORY_CORRUPTION = "memory_corruption" # 内存破坏
    STACK_CORRUPTION = "stack_corruption"   # 栈破坏
    USE_AFTER_FREE = "use_after_free"       # 释放后使用
    OUT_OF_BOUNDS = "out_of_bounds"         # 越界访问
    UNINITIALIZED = "uninitialized"         # 未初始化使用
    DOUBLE_FREE = "double_free"             # 重复释放
    UNKNOWN = "unknown"


@dataclass
class RegisterState:
    """寄存器状态"""
    name: str
    value: str
    value_int: int = 0
    is_null: bool = False
    is_suspicious: bool = False
    suspicious_reason: str = ""
    source_lines: List[int] = field(default_factory=list)
    
    def __post_init__(self):
        try:
            self.value_int = int(self.value, 16)
            self.is_null = self.value_int == 0
            
            # 检测可疑值
            self._detect_suspicious_patterns()
        except (ValueError, TypeError):
            self.value_int = 0
            self.is_null = False
    
    def _detect_suspicious_patterns(self):
        """检测可疑的寄存器值模式"""
        # 检测位翻转模式 (单个位被翻转)
        # 正常的指针应该对齐
        if self.value_int != 0 and self.value_int & 0xF != 0 and self.value_int & 0xF != 0x8:
            # 非对齐地址可能是位翻转
            binary = bin(self.value_int)[2:].zfill(64)
            if binary.count('1') == 1 or binary.count('1') == 2:
                self.is_suspicious = True
                self.suspicious_reason = f"Possible bitflip pattern: single/double bit set"
        
        # 检测近似 NULL 的地址 (可能是位翻转导致的)
        if 0 < self.value_int < 0x1000:
            self.is_suspicious = True
            self.suspicious_reason = f"Near-null address, possible bitflip from 0x0"
        
        # 检测异常高位地址
        if self.value_int > 0xFFFFFFFFFFFFF000:
            self.is_suspicious = True
            self.suspicious_reason = f"Unusual high address pattern"


@dataclass
class AsmInstruction:
    """汇编指令"""
    address: str
    instruction: str
    operands: str
    source_ref: Optional[str] = None
    line_number: Optional[int] = None
    
    # 分析结果
    inst_type: InstructionType = InstructionType.UNKNOWN
    read_regs: List[str] = field(default_factory=list)
    write_regs: List[str] = field(default_factory=list)
    memory_access: bool = False
    memory_address_reg: Optional[str] = None
    memory_offset: int = 0
    is_branch: bool = False
    branch_target: Optional[str] = None
    
    # 异常检测
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        self._parse_instruction()
    
    def _parse_instruction(self):
        """解析指令类型和寄存器"""
        inst_upper = self.instruction.upper()
        operands = self.operands
        
        # 识别指令类型
        if any(inst_upper.startswith(x) for x in ['LDR', 'LDUR', 'LDP', 'LDNP', 'LDAR', 'LDXR']):
            self.inst_type = InstructionType.LOAD
            self.memory_access = True
        elif any(inst_upper.startswith(x) for x in ['STR', 'STUR', 'STP', 'STNP', 'STLR', 'STXR']):
            self.inst_type = InstructionType.STORE
            self.memory_access = True
        elif any(inst_upper.startswith(x) for x in ['ADD', 'SUB', 'MUL', 'DIV', 'SDIV', 'UDIV', 'SMULL']):
            self.inst_type = InstructionType.ARITHMETIC
        elif any(inst_upper.startswith(x) for x in ['AND', 'ORR', 'EOR', 'ORN', 'BIC', 'BICS']):
            self.inst_type = InstructionType.LOGICAL
        elif any(inst_upper.startswith(x) for x in ['B ', 'BL ', 'BR ', 'BLR ', 'RET', 'CBZ', 'CBNZ', 'TBZ', 'TBNZ']):
            self.inst_type = InstructionType.BRANCH
            self.is_branch = True
        elif any(inst_upper.startswith(x) for x in ['MOV', 'MVN', 'MOVK', 'MOVZ', 'MOVN']):
            self.inst_type = InstructionType.MOVE
        elif any(inst_upper.startswith(x) for x in ['CMP', 'CMN', 'TST']):
            self.inst_type = InstructionType.COMPARE
        
        # 解析读写寄存器
        self._parse_registers(operands)
        
        # 解析内存访问
        if self.memory_access:
            self._parse_memory_access(operands)
    
    def _parse_registers(self, operands: str):
        """解析指令中的寄存器"""
        # ARM64 寄存器模式 - 匹配 Wn 和 Xn 寄存器
        # W0-W30 (32-bit), X0-X30 (64-bit), XZR/WZR (zero reg), SP
        reg_pattern = r'\b([WX])([0-9]|[12][0-9]|30|ZR)\b|\b(SP|LR|FP|PC)\b'
        matches = re.findall(reg_pattern, operands.upper())
        
        # 提取完整的寄存器名
        all_regs = []
        for match in matches:
            if isinstance(match, tuple):
                if match[0] in ['W', 'X'] and match[1]:
                    all_regs.append(match[0] + match[1])
                elif match[2]:  # SP, LR, FP, PC
                    all_regs.append(match[2])
        
        # 简化处理：第一个通常是目标，其余是源
        if all_regs:
            # 对于加载指令，第一个寄存器是目标(写)，其他是源(读)
            if self.inst_type == InstructionType.LOAD:
                self.write_regs = [all_regs[0]] if all_regs else []
                self.read_regs = all_regs[1:] if len(all_regs) > 1 else []
            # 对于存储指令，所有寄存器都是源(读)
            elif self.inst_type == InstructionType.STORE:
                self.read_regs = all_regs
            # 对于算术指令，第一个通常是目标(写)
            elif self.inst_type in [InstructionType.ARITHMETIC, InstructionType.LOGICAL, InstructionType.MOVE]:
                self.write_regs = [all_regs[0]] if all_regs else []
                self.read_regs = all_regs[1:] if len(all_regs) > 1 else []
            else:
                self.read_regs = all_regs
    
    def _parse_memory_access(self, operands: str):
        """解析内存访问信息"""
        # 匹配 [Xn, #offset] 或 [Xn] 或 [Xn, #offset]! 模式
        match = re.search(r'\[([WX]\d+|SP|LR|FP)\s*(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\s*\]', operands, re.IGNORECASE)
        if match:
            self.memory_address_reg = match.group(1).upper()
            offset_str = match.group(2)
            if offset_str:
                try:
                    if offset_str.startswith('0x'):
                        self.memory_offset = int(offset_str, 16)
                    else:
                        self.memory_offset = int(offset_str)
                except ValueError:
                    self.memory_offset = 0
            # 将基址寄存器添加到读寄存器列表
            if self.memory_address_reg and self.memory_address_reg not in self.read_regs:
                self.read_regs.append(self.memory_address_reg)


@dataclass
class FunctionAsmAnalysis:
    """函数汇编分析结果"""
    function_name: str
    function_address: Optional[str] = None
    instructions: List[AsmInstruction] = field(default_factory=list)
    
    # 寄存器状态跟踪
    register_states: Dict[str, RegisterState] = field(default_factory=dict)
    
    # 分析结果
    suspicious_instructions: List[AsmInstruction] = field(default_factory=list)
    potential_anomalies: List[Dict[str, Any]] = field(default_factory=list)
    
    # 调用信息
    called_functions: List[str] = field(default_factory=list)
    call_instructions: List[AsmInstruction] = field(default_factory=list)


class AssemblyAnalyzer:
    """汇编层次分析器"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'null_access': [
                r'LDR.*\[XZR',  # 从零寄存器加载
                r'LDR.*\[X0\]',  # 从X0(NULL)加载
                r'STR.*\[XZR',  # 存储到零寄存器
            ],
            'stack_operation': [
                r'SUB.*SP.*#',   # 栈分配
                r'ADD.*SP.*#',   # 栈释放
                r'STP.*SP',      # 栈上保存寄存器对
                r'LDP.*SP',      # 从栈恢复寄存器对
            ],
            'function_call': [
                r'BL\s+',        # 函数调用
                r'BLR\s+X',      # 间接函数调用
            ],
        }
    
    def parse_assembly_output(self, asm_output: str, function_name: Optional[str] = None) -> FunctionAsmAnalysis:
        """
        解析 GDB/crash 输出的汇编代码
        
        Args:
            asm_output: 汇编输出文本
            function_name: 函数名（可选）
            
        Returns:
            FunctionAsmAnalysis 对象
        """
        analysis = FunctionAsmAnalysis(function_name=function_name or "unknown")
        instructions = []
        
        # 解析每一行汇编
        for line in asm_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # 尝试匹配: 地址 <+偏移>: 指令 操作数
            # 格式1: 0xffffffe91b368dac <__queue_work+40>: ldrb w8, [x1, #258]
            # 格式2: ffffffe91b368dac: ldrb w8, [x1, #258]
            # 格式3: => 0xffffffe91b368dac <__queue_work+40>: ldrb w8, [x1, #258]  (当前执行位置)
            
            patterns = [
                # 带 => 标记的当前指令
                r'^(?:=>)?\s*(0x[0-9a-fA-F]+)\s+<([^+>]+)(?:\+(\d+))?>:\s+(\w+)\s+(.*)$',
                # 标准格式
                r'^(0x[0-9a-fA-F]+)\s+<([^+>]+)(?:\+(\d+))?>:\s+(\w+)\s+(.*)$',
                # 简化格式
                r'^(0x[0-9a-fA-F]+):\s+(\w+)\s+(.*)$',
                # 最简格式
                r'^\s*(0x[0-9a-fA-F]+)[:\s]+(\w+)\s+(.*)$',
            ]
            
            for pattern in patterns:
                match = re.match(pattern, line)
                if match:
                    groups = match.groups()
                    if len(groups) >= 5:  # 带函数名的格式
                        address, func, offset, inst, operands = groups[:5]
                        if func and not analysis.function_name:
                            analysis.function_name = func
                    elif len(groups) == 3:  # 简化格式
                        address, inst, operands = groups
                    else:
                        continue
                    
                    instruction = AsmInstruction(
                        address=address,
                        instruction=inst,
                        operands=operands,
                        source_ref=f"{analysis.function_name}+{offset}" if 'offset' in locals() and offset else None
                    )
                    instructions.append(instruction)
                    break
        
        analysis.instructions = instructions
        return analysis
    
    def analyze_with_registers(
        self,
        asm_analysis: FunctionAsmAnalysis,
        registers: Dict[str, str],
        crashed_address: Optional[str] = None
    ) -> FunctionAsmAnalysis:
        """
        结合寄存器值进行汇编分析
        
        Args:
            asm_analysis: 汇编分析结果
            registers: 寄存器值字典 {name: value}
            crashed_address: 崩溃时的 PC 地址
            
        Returns:
            更新后的 FunctionAsmAnalysis
        """
        # 初始化寄存器状态
        for reg_name, reg_value in registers.items():
            reg_state = RegisterState(name=reg_name, value=reg_value)
            asm_analysis.register_states[reg_name.upper()] = reg_state
        
        # 找到崩溃指令
        crash_instruction = None
        if crashed_address:
            crash_addr_int = int(crashed_address, 16)
            for inst in asm_analysis.instructions:
                inst_addr_int = int(inst.address, 16)
                if inst_addr_int == crash_addr_int:
                    crash_instruction = inst
                    break
        
        # 分析可疑指令
        for inst in asm_analysis.instructions:
            self._analyze_instruction_suspicious(inst, asm_analysis.register_states)
            
            # 如果是崩溃指令，进行深度分析
            if inst == crash_instruction:
                self._analyze_crash_instruction(inst, asm_analysis)
            
            if inst.anomalies:
                asm_analysis.suspicious_instructions.append(inst)
        
        return asm_analysis
    
    def _analyze_instruction_suspicious(self, inst: AsmInstruction, register_states: Dict[str, RegisterState]):
        """分析单条指令是否可疑"""
        anomalies = []
        
        # 分析内存访问指令
        if inst.memory_access and inst.memory_address_reg:
            addr_reg = inst.memory_address_reg.upper()
            if addr_reg in register_states:
                reg_state = register_states[addr_reg]
                
                # 检查是否访问空指针
                if reg_state.is_null:
                    anomaly = {
                        'type': AnomalyType.NULL_POINTER,
                        'severity': 'CRITICAL',
                        'description': f"{inst.instruction} accessing NULL pointer via {addr_reg}",
                        'instruction': inst,
                        'register': reg_state
                    }
                    anomalies.append(anomaly)
                
                # 检查是否访问可疑地址
                elif reg_state.is_suspicious:
                    anomaly = {
                        'type': AnomalyType.BITFLIP,
                        'severity': 'HIGH',
                        'description': f"Suspicious memory access via {addr_reg} ({reg_state.suspicious_reason})",
                        'instruction': inst,
                        'register': reg_state
                    }
                    anomalies.append(anomaly)
                
                # 检查偏移量是否异常
                if abs(inst.memory_offset) > 0x10000:  # 大偏移
                    anomaly = {
                        'type': AnomalyType.OUT_OF_BOUNDS,
                        'severity': 'MEDIUM',
                        'description': f"Large memory offset {inst.memory_offset:#x}, possible out-of-bounds",
                        'instruction': inst,
                        'register': reg_state
                    }
                    anomalies.append(anomaly)
        
        # 检查分支到异常地址
        if inst.is_branch:
            # 检查是否跳转到 NULL 或可疑地址
            for reg in inst.read_regs:
                reg_upper = reg.upper()
                if reg_upper in register_states:
                    reg_state = register_states[reg_upper]
                    if reg_state.is_null or reg_state.is_suspicious:
                        anomaly = {
                            'type': AnomalyType.NULL_POINTER,
                            'severity': 'CRITICAL',
                            'description': f"Branch using suspicious {reg}: {reg_state.suspicious_reason}",
                            'instruction': inst,
                            'register': reg_state
                        }
                        anomalies.append(anomaly)
        
        # 检查零寄存器使用
        if 'XZR' in inst.operands.upper() or 'X31' in inst.operands.upper():
            if inst.inst_type == InstructionType.LOAD:
                anomaly = {
                    'type': AnomalyType.NULL_POINTER,
                    'severity': 'CRITICAL',
                    'description': f"Loading from zero register address",
                    'instruction': inst
                }
                anomalies.append(anomaly)
        
        inst.anomalies = anomalies
    
    def _analyze_crash_instruction(self, inst: AsmInstruction, analysis: FunctionAsmAnalysis):
        """深度分析崩溃指令"""
        logger.info(f"Deep analyzing crash instruction: {inst.instruction} {inst.operands}")
        
        # 对于内存访问指令，计算实际访问的地址
        if inst.memory_access and inst.memory_address_reg:
            addr_reg = inst.memory_address_reg.upper()
            if addr_reg in analysis.register_states:
                base_addr = analysis.register_states[addr_reg].value_int
                target_addr = base_addr + inst.memory_offset
                
                anomaly = {
                    'type': AnomalyType.MEMORY_CORRUPTION,
                    'severity': 'CRITICAL',
                    'description': f"Crash accessing address {target_addr:#x} (base: {base_addr:#x} + offset: {inst.memory_offset:#x})",
                    'instruction': inst,
                    'calculated_address': f"{target_addr:#x}",
                    'analysis': self._analyze_target_address(target_addr)
                }
                inst.anomalies.append(anomaly)
    
    def _analyze_target_address(self, address: int) -> str:
        """分析目标地址的特征"""
        analysis = []
        
        # 检查地址范围
        if address == 0:
            analysis.append("NULL pointer access")
        elif address < 0x1000:
            analysis.append("Near-null access (likely bitflip or null pointer + small offset)")
        elif 0x1000 <= address < 0x10000:
            analysis.append("Low address access (possible userspace pointer in kernel)")
        
        # 检查地址对齐
        if address & 0x7 != 0 and address & 0x3 != 0:
            analysis.append("Unaligned address (suspicious)")
        
        # 检查位模式
        binary = bin(address)[2:].zfill(64)
        ones_count = binary.count('1')
        if ones_count <= 2:
            analysis.append(f"Sparse bit pattern ({ones_count} bits set), possible bitflip")
        
        # 检查是否是栈地址 (近似 SP 范围)
        # 内核栈通常在 0xFFFFFFC0xxxxxxxx 范围
        if 0xFFFFFFC000000000 <= address <= 0xFFFFFFD000000000:
            analysis.append("Likely kernel stack address")
        
        # 检查是否是内核文本地址
        if 0xFFFFFFE000000000 <= address <= 0xFFFFFFFF00000000:
            analysis.append("Likely kernel text address")
        
        return "; ".join(analysis) if analysis else "Normal kernel address"
    
    def analyze_call_stack(
        self,
        call_stack: List[Dict[str, str]],
        vmlinux_path: str,
        registers: Dict[str, str],
        crash_pc: str
    ) -> List[FunctionAsmAnalysis]:
        """
        分析调用栈中每个函数的汇编
        
        Args:
            call_stack: 调用栈列表
            vmlinux_path: vmlinux 路径
            registers: 寄存器状态
            crash_pc: 崩溃时的 PC
            
        Returns:
            每个函数的汇编分析列表
        """
        results = []
        
        for frame in call_stack[:5]:  # 只分析前5帧
            func_name = frame.get('function', '')
            func_addr = frame.get('address', '')
            
            if not func_name:
                continue
            
            # 这里需要从 GDB/crash 获取汇编
            # 实际使用时需要调用工具获取
            analysis = FunctionAsmAnalysis(
                function_name=func_name,
                function_address=func_addr
            )
            results.append(analysis)
        
        return results
    
    def detect_bitflip(self, value: int, expected_range: Tuple[int, int] = (0, 0xFFFFFFFFFFFFFFFF)) -> Optional[Dict[str, Any]]:
        """
        检测值是否可能是位翻转导致的
        
        Args:
            value: 要检测的值
            expected_range: 预期值范围
            
        Returns:
            检测结果或 None
        """
        # 检查单个位翻转的模式
        # 如果翻转单个位能得到一个合理的值，则可能是位翻转
        
        if value == 0:
            return None
        
        # 翻转每一位，检查是否能得到合理值
        for bit_pos in range(64):
            flipped = value ^ (1 << bit_pos)
            if expected_range[0] <= flipped <= expected_range[1]:
                return {
                    'detected': True,
                    'original_value': f"{value:#x}",
                    'flipped_value': f"{flipped:#x}",
                    'bit_position': bit_pos,
                    'confidence': 'HIGH' if bin(value).count('1') <= 2 else 'MEDIUM'
                }
        
        # 检查双位翻转
        for bit1 in range(64):
            for bit2 in range(bit1 + 1, 64):
                flipped = value ^ (1 << bit1) ^ (1 << bit2)
                if expected_range[0] <= flipped <= expected_range[1]:
                    return {
                        'detected': True,
                        'original_value': f"{value:#x}",
                        'flipped_value': f"{flipped:#x}",
                        'bit_positions': [bit1, bit2],
                        'confidence': 'MEDIUM'
                    }
        
        return None
    
    def generate_analysis_report(self, analysis: FunctionAsmAnalysis) -> Dict[str, Any]:
        """生成汇编分析报告"""
        report = {
            'function': analysis.function_name,
            'function_address': analysis.function_address,
            'instruction_count': len(analysis.instructions),
            'suspicious_instruction_count': len(analysis.suspicious_instructions),
            'registers_analyzed': list(analysis.register_states.keys()),
            'anomalies': [],
            'key_findings': [],
            'recommendations': []
        }
        
        # 收集所有异常
        for inst in analysis.suspicious_instructions:
            for anomaly in inst.anomalies:
                report['anomalies'].append({
                    'address': inst.address,
                    'instruction': f"{inst.instruction} {inst.operands}",
                    'type': anomaly['type'].value,
                    'severity': anomaly['severity'],
                    'description': anomaly['description']
                })
        
        # 生成关键发现
        if report['anomalies']:
            critical_count = sum(1 for a in report['anomalies'] if a['severity'] == 'CRITICAL')
            high_count = sum(1 for a in report['anomalies'] if a['severity'] == 'HIGH')
            
            if critical_count > 0:
                report['key_findings'].append(f"Found {critical_count} CRITICAL anomalies suggesting null pointer or severe corruption")
            if high_count > 0:
                report['key_findings'].append(f"Found {high_count} HIGH severity anomalies suggesting bitflip or memory corruption")
        
        # 生成建议
        null_anomalies = [a for a in report['anomalies'] if a['type'] == AnomalyType.NULL_POINTER.value]
        bitflip_anomalies = [a for a in report['anomalies'] if a['type'] == AnomalyType.BITFLIP.value]
        
        if null_anomalies:
            report['recommendations'].append("Check for missing NULL pointer checks in the code path")
            report['recommendations'].append("Review pointer initialization and validation logic")
        
        if bitflip_anomalies:
            report['recommendations'].append("Consider hardware issues (RAM/ECC errors) or radiation effects")
            report['recommendations'].append("Check for DMA corruption or driver bugs")
        
        if not report['anomalies']:
            report['key_findings'].append("No obvious anomalies detected in assembly analysis")
            report['recommendations'].append("Consider higher-level logic errors or race conditions")
        
        return report


# 便捷函数
def analyze_crash_with_assembly(
    asm_output: str,
    registers: Dict[str, str],
    crashed_address: str,
    function_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    便捷函数：分析 crash 的汇编层次信息
    
    Args:
        asm_output: GDB/crash 输出的汇编文本
        registers: 寄存器值
        crashed_address: 崩溃地址
        function_name: 函数名
        
    Returns:
        分析报告
    """
    analyzer = AssemblyAnalyzer()
    
    # 解析汇编
    asm_analysis = analyzer.parse_assembly_output(asm_output, function_name)
    
    # 结合寄存器分析
    asm_analysis = analyzer.analyze_with_registers(asm_analysis, registers, crashed_address)
    
    # 生成报告
    report = analyzer.generate_analysis_report(asm_analysis)
    
    return report
