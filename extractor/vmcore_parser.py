"""
vmcore 解析器
使用 crash 工具解析 vmcore 文件
"""
import os
import re
import asyncio
import logging
import tempfile
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path

from orchestrator.config import get_settings
from tools.crash_tool import CrashTool
from tools.gdb_tool import GDBTool

logger = logging.getLogger(__name__)


class VmcoredParser:
    """vmcore 解析器"""
    
    def __init__(self):
        self.settings = get_settings()
        self.crash_tool = CrashTool()
        self.gdb_tool = GDBTool()
    
    async def parse(self, vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]:
        """
        解析 vmcore 文件
        
        Args:
            vmcore_path: vmcore 文件路径
            vmlinux_path: vmlinux 文件路径
            
        Returns:
            解析结果字典
        """
        result = {
            'crash_type': None,
            'call_stack': [],
            'registers': {},
            'modules': [],
            'error_info': None
        }
        
        try:
            # 检查文件是否存在
            if not os.path.exists(vmcore_path):
                raise FileNotFoundError(f"vmcore not found: {vmcore_path}")
            if not os.path.exists(vmlinux_path):
                raise FileNotFoundError(f"vmlinux not found: {vmlinux_path}")
            
            # 使用 crash 工具获取基本信息
            logger.info(f"Parsing vmcore: {vmcore_path}")
            
            # 获取调用栈
            bt_result = await self.crash_tool.bt(vmcore_path, vmlinux_path)
            if bt_result:
                result['call_stack'] = self._parse_backtrace(bt_result)
            
            # 获取寄存器信息
            reg_result = await self.crash_tool.regs(vmcore_path, vmlinux_path)
            if reg_result:
                result['registers'] = self._parse_registers(reg_result)
            
            # 获取加载的模块
            mod_result = await self.crash_tool.mod(vmcore_path, vmlinux_path)
            if mod_result:
                result['modules'] = self._parse_modules(mod_result)
            
            # 获取系统信息
            sys_result = await self.crash_tool.sys(vmcore_path, vmlinux_path)
            if sys_result:
                result['system_info'] = self._parse_system_info(sys_result)
            
            # 分析 crash 类型
            result['crash_type'] = self._analyze_crash_type(
                result.get('call_stack', []),
                result.get('registers', {}),
                bt_result
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse vmcore: {e}")
            result['error_info'] = str(e)
            return result
    
    def _parse_backtrace(self, bt_output: str) -> List[Dict[str, str]]:
        """解析 backtrace 输出"""
        frames = []
        
        # crash bt 输出格式示例：
        # PID: 1234  TASK: ffff888123456780  CPU: 1  COMMAND: "process_name"
        # #0 [ffff888123456000] __schedule at ffffffff81234567
        # #1 [ffff888123456100] schedule at ffffffff81234589
        
        lines = bt_output.split('\n')
        for line in lines:
            line = line.strip()
            
            # 匹配堆栈帧
            match = re.match(r'#(\d+)\s+\[[0-9a-fA-F]+\]\s+(\S+)\s+at\s+([0-9a-fA-F]+)', line)
            if match:
                frames.append({
                    'frame_num': match.group(1),
                    'function': match.group(2),
                    'address': match.group(3)
                })
            else:
                # 尝试简化格式
                match = re.match(r'#(\d+)\s+(\S+)\s+\(', line)
                if match:
                    frames.append({
                        'frame_num': match.group(1),
                        'function': match.group(2),
                        'address': ''
                    })
        
        return frames
    
    def _parse_registers(self, reg_output: str) -> Dict[str, str]:
        """解析寄存器输出"""
        registers = {}
        
        # x86_64 寄存器格式
        # rax: 0000000000000000  rbx: 0000000000000000
        for line in reg_output.split('\n'):
            for match in re.finditer(r'(\w+):\s+([0-9a-fA-F]+)', line):
                reg_name = match.group(1)
                reg_value = match.group(2)
                registers[reg_name] = reg_value
        
        return registers
    
    def _parse_modules(self, mod_output: str) -> List[Dict[str, str]]:
        """解析模块信息"""
        modules = []
        
        lines = mod_output.split('\n')
        for line in lines:
            line = line.strip()
            # 解析模块行
            parts = line.split()
            if len(parts) >= 3:
                modules.append({
                    'name': parts[0],
                    'address': parts[1] if len(parts) > 1 else '',
                    'size': parts[2] if len(parts) > 2 else ''
                })
        
        return modules
    
    def _parse_system_info(self, sys_output: str) -> Dict[str, str]:
        """解析系统信息"""
        info = {}
        
        for line in sys_output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip()] = value.strip()
        
        return info
    
    def _analyze_crash_type(
        self,
        call_stack: List[Dict],
        registers: Dict[str, str],
        raw_output: Optional[str]
    ) -> Optional[str]:
        """分析 crash 类型"""
        raw_lower = (raw_output or '').lower()
        
        # 检查 NULL pointer
        if 'null' in raw_lower or '0x0000000000000000' in raw_lower:
            return "NULL Pointer Dereference"
        
        # 检查 Oops
        if 'oops' in raw_lower:
            return "Kernel Oops"
        
        # 检查 Panic
        if 'panic' in raw_lower:
            return "Kernel Panic"
        
        # 检查页错误
        if 'page fault' in raw_lower:
            return "Page Fault"
        
        # 检查 watchdog
        if 'watchdog' in raw_lower or 'watchdog' in str(call_stack).lower():
            return "Watchdog Timeout"
        
        # 检查 softlockup
        if 'softlockup' in raw_lower:
            return "Soft Lockup"
        
        # 检查 hardlockup
        if 'hardlockup' in raw_lower:
            return "Hard Lockup"
        
        # 检查 BUG
        if 'bug:' in raw_lower:
            return "Kernel BUG"
        
        return "Unknown Crash Type"
