"""
GDB Tool Gateway - Wrapper for GDB debugging commands
Provides kernel debugging capabilities.
"""

import subprocess
import asyncio
import logging
import tempfile
import os
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class GDBResult:
    """Result of GDB execution."""
    command: str
    returncode: int
    output: str
    success: bool
    execution_time: float = 0.0


class GDBToolGateway:
    """Gateway for GDB debugging operations."""
    
    def __init__(
        self,
        gdb_cmd: str = "gdb",
        default_timeout: int = 120
    ):
        self.gdb_cmd = gdb_cmd
        self.default_timeout = default_timeout
    
    async def execute(
        self,
        executable: str,
        commands: List[str],
        core_file: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> GDBResult:
        """Execute GDB commands."""
        
        if not os.path.exists(executable):
            return GDBResult(
                command="; ".join(commands),
                returncode=-1,
                output="",
                success=False
            )
        
        timeout = timeout or self.default_timeout
        
        # Build GDB script
        script_lines = [
            "set pagination off",
            "set confirm off",
            "set print pretty on",
        ]
        script_lines.extend(commands)
        script_lines.append("quit")
        
        import time
        start_time = time.time()
        
        try:
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write('\n'.join(script_lines))
                script_path = f.name
            
            # Build command
            args = [self.gdb_cmd, "-x", script_path, "-batch"]
            if core_file and os.path.exists(core_file):
                args.extend(["-c", core_file])
            args.append(executable)
            
            logger.info(f"Executing GDB commands: {commands}")
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            )
            
            execution_time = time.time() - start_time
            
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr
            
            return GDBResult(
                command="; ".join(commands),
                returncode=result.returncode,
                output=output,
                success=result.returncode == 0,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            return GDBResult(
                command="; ".join(commands),
                returncode=-1,
                output="",
                success=False,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            logger.error(f"GDB execution failed: {e}")
            return GDBResult(
                command="; ".join(commands),
                returncode=-1,
                output="",
                success=False,
                execution_time=time.time() - start_time
            )
        finally:
            if 'script_path' in locals() and os.path.exists(script_path):
                os.unlink(script_path)
    
    async def get_backtrace(
        self,
        executable: str,
        core_file: Optional[str] = None,
        full: bool = True
    ) -> GDBResult:
        """Get backtrace."""
        commands = ["bt full" if full else "bt"]
        return await self.execute(executable, commands, core_file)
    
    async def get_registers(
        self,
        executable: str,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Get register values."""
        commands = ["info registers"]
        return await self.execute(executable, commands, core_file)
    
    async def disassemble_function(
        self,
        executable: str,
        function_name: str,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Disassemble a function."""
        commands = [f"disassemble {function_name}"]
        return await self.execute(executable, commands, core_file)
    
    async def disassemble_address(
        self,
        executable: str,
        address: str,
        num_instructions: int = 20,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Disassemble at specific address."""
        commands = [f"x/{num_instructions}i {address}"]
        return await self.execute(executable, commands, core_file)
    
    async def examine_memory(
        self,
        executable: str,
        address: str,
        format_spec: str = "x",
        count: int = 16,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Examine memory at address."""
        commands = [f"x/{count}{format_spec} {address}"]
        return await self.execute(executable, commands, core_file)
    
    async def get_frame_info(
        self,
        executable: str,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Get current frame information."""
        commands = ["info frame", "info args", "info locals"]
        return await self.execute(executable, commands, core_file)
    
    async def get_threads(
        self,
        executable: str,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Get thread information."""
        commands = ["info threads"]
        return await self.execute(executable, commands, core_file)
    
    async def get_shared_libraries(
        self,
        executable: str,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Get shared library information."""
        commands = ["info sharedlibrary"]
        return await self.execute(executable, commands, core_file)
    
    async def get_source_line(
        self,
        executable: str,
        address: str,
        core_file: Optional[str] = None
    ) -> Optional[Dict[str, str]]:
        """Get source file and line for an address."""
        commands = [f"info line *{address}"]
        result = await self.execute(executable, commands, core_file)
        
        if not result.success:
            return None
        
        # Parse output like: "Line 123 of /path/to/file.c starts at address 0x..."
        match = re.search(
            r'Line\s+(\d+)\s+of\s+(.+?)\s+starts',
            result.output
        )
        if match:
            return {
                "line": match.group(1),
                "file": match.group(2)
            }
        
        return None
    
    async def print_variable(
        self,
        executable: str,
        variable: str,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Print variable value."""
        commands = [f"print {variable}"]
        return await self.execute(executable, commands, core_file)
    
    async def get_function_info(
        self,
        executable: str,
        function_name: str,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """Get function information."""
        commands = [f"info function {function_name}"]
        return await self.execute(executable, commands, core_file)
    
    async def list_source(
        self,
        executable: str,
        function_name: str,
        lines_before: int = 10,
        lines_after: int = 10,
        core_file: Optional[str] = None
    ) -> GDBResult:
        """List source code around a function."""
        commands = [
            f"list {function_name}:{lines_before if lines_before > 0 else 1}",
        ]
        return await self.execute(executable, commands, core_file)
    
    async def analyze_kernel_oops(
        self,
        vmlinux_path: str,
        fault_address: Optional[str] = None,
        stack_trace: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Analyze a kernel oops using GDB."""
        results = {
            "backtrace": "",
            "registers": "",
            "source_info": {},
            "disassembly": ""
        }
        
        # Get backtrace
        bt_result = await self.get_backtrace(vmlinux_path)
        if bt_result.success:
            results["backtrace"] = bt_result.output
        
        # Get registers
        reg_result = await self.get_registers(vmlinux_path)
        if reg_result.success:
            results["registers"] = reg_result.output
        
        # Analyze fault address
        if fault_address:
            source_info = await self.get_source_line(vmlinux_path, fault_address)
            if source_info:
                results["source_info"] = source_info
            
            disasm_result = await self.disassemble_address(
                vmlinux_path, fault_address, num_instructions=10
            )
            if disasm_result.success:
                results["disassembly"] = disasm_result.output
        
        # Analyze first stack frame
        if stack_trace and len(stack_trace) > 0:
            # Try to extract function name from first frame
            first_frame = stack_trace[0]
            func_match = re.search(r'(\w+)\s*\+', first_frame)
            if func_match:
                func_name = func_match.group(1)
                source_info = await self.get_source_line(vmlinux_path, func_name)
                if source_info:
                    results["crash_function_source"] = source_info
        
        return results

    async def get_function_assembly_with_context(
        self,
        vmlinux_path: str,
        function_name: str,
        core_file: Optional[str] = None,
        context_instructions: int = 20
    ) -> Dict[str, Any]:
        """
        获取函数的汇编代码，包含上下文信息
        
        Args:
            vmlinux_path: vmlinux 文件路径
            function_name: 函数名
            core_file: 可选的 core dump 文件
            context_instructions: 获取的指令数量
            
        Returns:
            包含汇编代码和元信息的字典
        """
        result = {
            "function": function_name,
            "assembly": "",
            "start_address": None,
            "end_address": None,
            "success": False
        }
        
        # 首先获取函数地址范围
        func_info = await self.get_function_info(vmlinux_path, function_name, core_file)
        if func_info.success:
            # 解析函数地址
            addr_match = re.search(r'0x([0-9a-fA-F]+)', func_info.output)
            if addr_match:
                result["start_address"] = f"0x{addr_match.group(1)}"
        
        # 反汇编函数
        disasm_result = await self.disassemble_function(vmlinux_path, function_name, core_file)
        if disasm_result.success:
            result["assembly"] = disasm_result.output
            result["success"] = True
            
            # 尝试解析结束地址
            lines = disasm_result.output.strip().split('\n')
            if lines:
                last_line = lines[-1]
                addr_match = re.match(r'\s*(0x[0-9a-fA-F]+)', last_line)
                if addr_match:
                    result["end_address"] = addr_match.group(1)
        
        return result

    async def analyze_crash_point_registers(
        self,
        vmlinux_path: str,
        crashed_pc: str,
        core_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        分析崩溃点的寄存器状态和指令
        
        Args:
            vmlinux_path: vmlinux 路径
            crashed_pc: 崩溃时的 PC 地址
            core_file: core dump 文件
            
        Returns:
            崩溃点分析结果
        """
        result = {
            "crashed_pc": crashed_pc,
            "registers": {},
            "disassembly_at_crash": "",
            "disassembly_before_crash": "",
            "function_context": {}
        }
        
        # 获取寄存器
        reg_result = await self.get_registers(vmlinux_path, core_file)
        if reg_result.success:
            result["registers"] = self._parse_registers_output(reg_result.output)
        
        # 获取崩溃点的汇编（前后各10条指令）
        try:
            pc_int = int(crashed_pc, 16)
            # 前面10条指令（假设每条指令4字节）
            before_addr = f"0x{pc_int - 40:x}"
            disasm_before = await self.disassemble_address(
                vmlinux_path, before_addr, num_instructions=20, core_file=core_file
            )
            if disasm_before.success:
                result["disassembly_before_crash"] = disasm_before.output
            
            # 崩溃点本身
            disasm_at = await self.disassemble_address(
                vmlinux_path, crashed_pc, num_instructions=10, core_file=core_file
            )
            if disasm_at.success:
                result["disassembly_at_crash"] = disasm_at.output
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to calculate disassembly addresses: {e}")
        
        # 获取源代码上下文
        source_info = await self.get_source_line(vmlinux_path, crashed_pc, core_file)
        if source_info:
            result["source_context"] = source_info
        
        return result

    def _parse_registers_output(self, output: str) -> Dict[str, str]:
        """解析 GDB 寄存器输出"""
        registers = {}
        
        # ARM64 寄存器格式
        # x0  0xffffffc02b3cbd88
        # x1  0x0
        # sp  0xffffffc00801bcf0
        
        patterns = [
            r'(x\d+|sp|pc|lr|fp|xzr)\s+(0x[0-9a-fA-F]+|\d+)',  # ARM64
            r'(r\d+|sp|pc|lr)\s+(0x[0-9a-fA-F]+|\d+)',          # ARM32
            r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r\d+)\s+(0x[0-9a-fA-F]+|\d+)',  # x86_64
        ]
        
        for line in output.split('\n'):
            for pattern in patterns:
                match = re.match(pattern, line.strip(), re.IGNORECASE)
                if match:
                    reg_name = match.group(1).lower()
                    reg_value = match.group(2)
                    registers[reg_name] = reg_value
                    break
        
        return registers

    async def get_backtrace_with_full_context(
        self,
        vmlinux_path: str,
        core_file: Optional[str] = None,
        max_frames: int = 10
    ) -> List[Dict[str, Any]]:
        """
        获取包含完整上下文的调用栈
        
        Returns:
            每帧包含汇编、寄存器、源代码的调用栈
        """
        frames = []
        
        # 获取基本调用栈
        bt_result = await self.get_backtrace(vmlinux_path, core_file, full=True)
        if not bt_result.success:
            return frames
        
        # 解析每一帧
        bt_lines = bt_result.output.split('\n')
        current_frame = None
        
        for line in bt_lines:
            line = line.strip()
            if not line:
                continue
            
            # 匹配帧头: #0  0xffffffe91b368dac in __queue_work ()
            frame_match = re.match(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)', line)
            if frame_match:
                if current_frame:
                    frames.append(current_frame)
                
                frame_num = frame_match.group(1)
                pc_addr = frame_match.group(2)
                func_name = frame_match.group(3)
                
                current_frame = {
                    "frame_number": int(frame_num),
                    "pc": pc_addr,
                    "function": func_name,
                    "locals": {},
                    "args": {}
                }
            
            # 解析局部变量
            elif current_frame and (' = ' in line or 'Local variables' in line):
                var_match = re.match(r'(\w+)\s+=\s+(.*)', line)
                if var_match:
                    var_name = var_match.group(1)
                    var_value = var_match.group(2)
                    current_frame["locals"][var_name] = var_value
            
            # 解析参数
            elif current_frame and 'arg' in line.lower():
                arg_match = re.match(r'(\w+)\s+=\s+(.*)', line)
                if arg_match:
                    arg_name = arg_match.group(1)
                    arg_value = arg_match.group(2)
                    current_frame["args"][arg_name] = arg_value
        
        if current_frame:
            frames.append(current_frame)
        
        # 限制帧数
        frames = frames[:max_frames]
        
        # 为每帧获取汇编代码
        for frame in frames:
            try:
                func_asm = await self.get_function_assembly_with_context(
                    vmlinux_path, frame["function"], core_file, context_instructions=20
                )
                if func_asm["success"]:
                    frame["assembly"] = func_asm
            except Exception as e:
                logger.warning(f"Failed to get assembly for frame {frame['frame_number']}: {e}")
        
        return frames
