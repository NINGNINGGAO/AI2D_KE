"""
Kernel Log 解析器
解析 kernel log 文件，提取关键信息
"""
import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class CrashType(Enum):
    """Crash 类型"""
    NULL_POINTER = "NULL Pointer Dereference"
    KERNEL_OOPS = "Kernel Oops"
    KERNEL_PANIC = "Kernel Panic"
    PAGE_FAULT = "Page Fault"
    WATCHDOG_TIMEOUT = "Watchdog Timeout"
    SOFT_LOCKUP = "Soft Lockup"
    HARD_LOCKUP = "Hard Lockup"
    BUG = "Kernel BUG"
    WARNING = "Kernel Warning"
    UNKNOWN = "Unknown"


@dataclass
class LogEntry:
    """日志条目"""
    timestamp: Optional[str]
    level: str  # KERN_EMERG, KERN_ALERT, etc.
    message: str
    raw_line: str


@dataclass
class CrashInfo:
    """Crash 信息"""
    crash_type: CrashType
    timestamp: Optional[str]
    cpu: Optional[int]
    process: Optional[str]
    pid: Optional[int]
    call_stack: List[str]
    error_message: str
    raw_lines: List[str]


class KernelLogParser:
    """Kernel Log 解析器"""
    
    # Log level patterns
    LOG_LEVELS = {
        '0': 'EMERG',
        '1': 'ALERT',
        '2': 'CRIT',
        '3': 'ERR',
        '4': 'WARNING',
        '5': 'NOTICE',
        '6': 'INFO',
        '7': 'DEBUG'
    }
    
    # Crash pattern signatures
    CRASH_PATTERNS = {
        CrashType.NULL_POINTER: [
            r'Unable to handle kernel NULL pointer dereference',
            r'null pointer dereference',
            r'Unable to handle kernel paging request at 0000000000000000',
        ],
        CrashType.KERNEL_OOPS: [
            r'Oops:.*\[.*\]',
            r'Oops:',
        ],
        CrashType.KERNEL_PANIC: [
            r'Kernel panic',
            r'---\[ end Kernel panic',
        ],
        CrashType.PAGE_FAULT: [
            r'Unable to handle kernel paging request',
            r'page fault',
        ],
        CrashType.WATCHDOG_TIMEOUT: [
            r'Watchdog detected hard LOCKUP',
            r'hard LOCKUP',
            r'watchdog:.*timed out',
        ],
        CrashType.SOFT_LOCKUP: [
            r'watchdog:.*softlockup',
            r'softlockup: hung tasks',
        ],
        CrashType.HARD_LOCKUP: [
            r'hardlockup',
            r'Hard LOCKUP',
        ],
        CrashType.BUG: [
            r'BUG:.*\[.*\]',
            r'kernel BUG at',
        ],
        CrashType.WARNING: [
            r'WARNING:.*\[.*\]',
            r'------------\[ cut here \]------------',
        ],
    }
    
    def __init__(self):
        pass
    
    async def parse(self, log_path: str) -> Dict[str, Any]:
        """
        解析 kernel log 文件
        
        Args:
            log_path: log 文件路径
            
        Returns:
            解析结果字典
        """
        result = {
            'crash_found': False,
            'crash_info': None,
            'critical_logs': [],
            'summary': None
        }
        
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # 查找 crash
            crash_info = self._find_crash(lines)
            if crash_info:
                result['crash_found'] = True
                result['crash_info'] = {
                    'type': crash_info.crash_type.value,
                    'timestamp': crash_info.timestamp,
                    'cpu': crash_info.cpu,
                    'process': crash_info.process,
                    'pid': crash_info.pid,
                    'call_stack': crash_info.call_stack,
                    'error_message': crash_info.error_message
                }
            
            # 提取关键日志
            critical_logs = self._extract_critical_logs(lines)
            result['critical_logs'] = critical_logs
            
            # 生成摘要
            result['summary'] = self._generate_summary(lines, crash_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse kernel log: {e}")
            result['error'] = str(e)
            return result
    
    def _find_crash(self, lines: List[str]) -> Optional[CrashInfo]:
        """查找 crash 信息"""
        for i, line in enumerate(lines):
            crash_type = self._detect_crash_type(line)
            if crash_type:
                # 找到 crash，提取相关信息
                crash_lines = self._extract_crash_context(lines, i)
                return self._parse_crash_info(crash_type, crash_lines)
        
        return None
    
    def _detect_crash_type(self, line: str) -> Optional[CrashType]:
        """检测 crash 类型"""
        for crash_type, patterns in self.CRASH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return crash_type
        return None
    
    def _extract_crash_context(self, lines: List[str], start_idx: int, context_lines: int = 50) -> List[str]:
        """提取 crash 上下文"""
        end_idx = min(start_idx + context_lines, len(lines))
        return lines[start_idx:end_idx]
    
    def _parse_crash_info(self, crash_type: CrashType, crash_lines: List[str]) -> CrashInfo:
        """解析 crash 详细信息"""
        timestamp = None
        cpu = None
        process = None
        pid = None
        call_stack = []
        error_message = ""
        
        for line in crash_lines:
            line = line.strip()
            
            # 提取时间戳
            if not timestamp:
                ts_match = re.match(r'\[\s*([\d.]+)\s*\]', line)
                if ts_match:
                    timestamp = ts_match.group(1)
            
            # 提取 CPU 和进程信息
            if 'CPU:' in line or 'cpu' in line.lower():
                cpu_match = re.search(r'CPU[:\s]+(\d+)', line)
                if cpu_match:
                    cpu = int(cpu_match.group(1))
            
            if 'PID:' in line or 'pid' in line.lower():
                pid_match = re.search(r'PID[:\s]+(\d+)', line)
                if pid_match:
                    pid = int(pid_match.group(1))
            
            if 'Comm:' in line or 'comm:' in line.lower():
                comm_match = re.search(r'[Cc]omm[:\s]+(\S+)', line)
                if comm_match:
                    process = comm_match.group(1)
            
            # 提取调用栈
            if line.startswith('[') and (']' in line or '::' in line):
                # 可能是调用栈
                if ']' in line or any(c in line for c in ['__', 'sys_', 'do_']):
                    call_stack.append(line)
            
            # 提取错误信息
            if any(keyword in line.lower() for keyword in ['error', 'fault', 'unable', 'oops']):
                if len(error_message) < 500:  # 限制长度
                    error_message += line + "\\n"
        
        # 限制调用栈长度
        call_stack = call_stack[:20]
        
        return CrashInfo(
            crash_type=crash_type,
            timestamp=timestamp,
            cpu=cpu,
            process=process,
            pid=pid,
            call_stack=call_stack,
            error_message=error_message.strip(),
            raw_lines=crash_lines
        )
    
    def _extract_critical_logs(self, lines: List[str], max_entries: int = 50) -> List[Dict]:
        """提取关键日志条目"""
        critical = []
        
        critical_patterns = [
            r'EMERG',
            r'ALERT',
            r'CRIT',
            r'ERR',
            r'Unable to handle',
            r'Oops',
            r'panic',
            r'BUG',
            r'WARNING.*cut here',
            r'Call trace',
            r'stack',
            r'exception',
            r'fault',
        ]
        
        for line in lines:
            for pattern in critical_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    critical.append({
                        'level': 'CRITICAL',
                        'message': line.strip()[:500]  # 限制长度
                    })
                    if len(critical) >= max_entries:
                        return critical
                    break
        
        return critical
    
    def _generate_summary(self, lines: List[str], crash_info: Optional[CrashInfo]) -> str:
        """生成日志摘要"""
        total_lines = len(lines)
        
        if crash_info:
            summary = f"Found {crash_info.crash_type.value}"
            if crash_info.process:
                summary += f" in process '{crash_info.process}'"
            if crash_info.cpu is not None:
                summary += f" on CPU {crash_info.cpu}"
            summary += f". Total log lines: {total_lines}"
            return summary
        else:
            return f"No crash detected. Total log lines: {total_lines}"
