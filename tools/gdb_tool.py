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
