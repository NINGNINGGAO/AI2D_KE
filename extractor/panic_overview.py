"""
增强的 Panic 概述提取器
提供详细的崩溃概述信息
"""
import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PanicOverview:
    """Panic 概述数据结构"""
    # 时间信息
    crash_time: Optional[str] = None
    uptime: Optional[str] = None
    
    # 内核版本信息
    kernel_version: Optional[str] = None
    kernel_release: Optional[str] = None
    
    # 崩溃类型
    crash_type: Optional[str] = None
    crash_subtype: Optional[str] = None
    
    # 崩溃场景
    crash_scenario: Optional[str] = None
    crash_context: Optional[str] = None
    
    # 可能的模块
    suspected_module: Optional[str] = None
    involved_modules: List[str] = None
    
    # 进程信息
    process_name: Optional[str] = None
    pid: Optional[int] = None
    tid: Optional[int] = None
    
    # CPU信息
    cpu_id: Optional[int] = None
    cpu_count: Optional[int] = None
    
    # 硬件/平台信息
    machine_type: Optional[str] = None
    platform: Optional[str] = None
    
    # 错误详情
    error_code: Optional[str] = None
    fault_address: Optional[str] = None
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.involved_modules is None:
            self.involved_modules = []
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PanicOverviewExtractor:
    """从 crash dump 中提取详细的 panic 概述"""
    
    def __init__(self, crash_tool, gdb_tool):
        self.crash_tool = crash_tool
        self.gdb_tool = gdb_tool
    
    async def extract(self, vmcore_path: str, vmlinux_path: str, 
                      log_analysis: Optional[Dict] = None) -> PanicOverview:
        """
        提取完整的 panic 概述
        
        Args:
            vmcore_path: vmcore 文件路径
            vmlinux_path: vmlinux 文件路径
            log_analysis: 可选的日志分析结果
            
        Returns:
            PanicOverview 对象
        """
        overview = PanicOverview()
        
        # 并行获取各种信息
        sys_info = await self._get_system_info(vmcore_path, vmlinux_path)
        task_info = await self._get_task_info(vmcore_path, vmlinux_path)
        machine_info = await self._get_machine_info(vmcore_path, vmlinux_path)
        crash_details = await self._get_crash_details(vmcore_path, vmlinux_path)
        module_info = await self._get_module_info(vmcore_path, vmlinux_path)
        
        # 填充概述
        overview.kernel_version = sys_info.get('kernel_version')
        overview.kernel_release = sys_info.get('kernel_release')
        overview.uptime = sys_info.get('uptime')
        overview.cpu_count = sys_info.get('cpu_count')
        
        overview.process_name = task_info.get('process_name')
        overview.pid = task_info.get('pid')
        overview.tid = task_info.get('tid')
        overview.cpu_id = task_info.get('cpu')
        
        overview.machine_type = machine_info.get('machine')
        overview.platform = machine_info.get('platform')
        
        overview.crash_type = crash_details.get('crash_type')
        overview.crash_subtype = crash_details.get('subtype')
        overview.error_code = crash_details.get('error_code')
        overview.fault_address = crash_details.get('fault_address')
        overview.error_message = crash_details.get('error_message')
        
        overview.involved_modules = module_info.get('modules', [])
        overview.suspected_module = module_info.get('suspected_module')
        
        # 从日志分析补充信息
        if log_analysis:
            self._enrich_from_logs(overview, log_analysis)
        
        # 分析崩溃场景
        overview.crash_scenario = self._analyze_crash_scenario(overview, crash_details)
        overview.crash_context = self._analyze_crash_context(overview, crash_details)
        
        # 解析崩溃时间
        overview.crash_time = self._parse_crash_time(sys_info, log_analysis)
        
        return overview
    
    async def _get_system_info(self, vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]:
        """获取系统信息"""
        info = {}
        
        # 使用 sys 命令
        result = await self.crash_tool.get_sys_info(vmcore_path, vmlinux_path)
        if result.success:
            output = result.output
            
            # 解析内核版本
            version_match = re.search(r'VERSION:\s*(.+)', output)
            if version_match:
                info['kernel_version'] = version_match.group(1).strip()
            
            # 解析 release
            release_match = re.search(r'RELEASE:\s*(.+)', output)
            if release_match:
                info['kernel_release'] = release_match.group(1).strip()
            
            # 解析 uptime
            uptime_match = re.search(r'UPTIME:\s*(.+)', output)
            if uptime_match:
                info['uptime'] = uptime_match.group(1).strip()
            
            # 解析 CPU 数量
            cpus_match = re.search(r'CPUS:\s*(\d+)', output)
            if cpus_match:
                info['cpu_count'] = int(cpus_match.group(1))
        
        return info
    
    async def _get_task_info(self, vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]:
        """获取当前任务信息"""
        info = {}
        
        # 使用 bt -c 获取当前 CPU 的 backtrace 以获取任务信息
        result = await self.crash_tool.execute(vmcore_path, 'bt -c', vmlinux_path)
        if result.success:
            output = result.output
            
            # 解析 PID
            pid_match = re.search(r'PID:\s*(\d+)', output)
            if pid_match:
                info['pid'] = int(pid_match.group(1))
            
            # 解析 TASK 地址
            task_match = re.search(r'TASK:\s*(0x[0-9a-fA-F]+)', output)
            if task_match:
                task_addr = task_match.group(1)
                # 获取详细的任务信息
                task_result = await self.crash_tool.get_task_info(vmcore_path, task_addr, vmlinux_path)
                if task_result.success:
                    task_output = task_result.output
                    
                    # 解析线程名
                    comm_match = re.search(r'comm:\s*(\S+)', task_output)
                    if comm_match:
                        info['process_name'] = comm_match.group(1).strip()
                    
                    # 解析 TID
                    tid_match = re.search(r'pid:\s*(\d+)', task_output)
                    if tid_match:
                        info['tid'] = int(tid_match.group(1))
            
            # 解析 CPU
            cpu_match = re.search(r'CPU:\s*(\d+)', output)
            if cpu_match:
                info['cpu'] = int(cpu_match.group(1))
            
            # 如果无法从 task 获取进程名，从 COMMAND 行获取
            if not info.get('process_name'):
                cmd_match = re.search(r'COMMAND:\s*"([^"]+)"', output)
                if cmd_match:
                    info['process_name'] = cmd_match.group(1)
        
        return info
    
    async def _get_machine_info(self, vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]:
        """获取机器/平台信息"""
        info = {}
        
        # 使用 mach 命令
        result = await self.crash_tool.execute(vmcore_path, 'mach', vmlinux_path)
        if result.success:
            output = result.output
            
            # 解析机器类型
            machine_match = re.search(r'MACHINE:\s*(.+)', output)
            if machine_match:
                info['machine'] = machine_match.group(1).strip()
            
            # 解析内存大小
            mem_match = re.search(r'MEMSIZE:\s*(.+)', output)
            if mem_match:
                info['memory_size'] = mem_match.group(1).strip()
        
        return info
    
    async def _get_crash_details(self, vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]:
        """获取崩溃详情"""
        details = {}
        
        # 获取 log 中的 panic 信息
        result = await self.crash_tool.get_log(vmcore_path, vmlinux_path)
        if result.success:
            log_output = result.output
            
            # 检测崩溃类型
            crash_type, subtype = self._detect_crash_type(log_output)
            details['crash_type'] = crash_type
            details['subtype'] = subtype
            
            # 解析错误码
            error_code = self._parse_error_code(log_output)
            if error_code:
                details['error_code'] = error_code
            
            # 解析错误地址
            fault_addr = self._parse_fault_address(log_output)
            if fault_addr:
                details['fault_address'] = fault_addr
            
            # 提取错误消息
            error_msg = self._extract_error_message(log_output)
            if error_msg:
                details['error_message'] = error_msg
        
        return details
    
    async def _get_module_info(self, vmcore_path: str, vmlinux_path: str) -> Dict[str, Any]:
        """获取模块信息并识别可疑模块"""
        info = {'modules': [], 'suspected_module': None}
        
        # 获取模块列表
        result = await self.crash_tool.get_modules(vmcore_path, vmlinux_path)
        if result.success:
            modules = self._parse_modules(result.output)
            info['modules'] = [m['name'] for m in modules if m.get('name')]
            
            # 获取 backtrace 来确定可疑模块
            bt_result = await self.crash_tool.get_backtrace(vmcore_path, vmlinux_path, all_cpus=False)
            if bt_result.success:
                suspected = self._identify_suspected_module(bt_result.output, modules)
                info['suspected_module'] = suspected
        
        return info
    
    def _enrich_from_logs(self, overview: PanicOverview, log_analysis: Dict):
        """从日志分析中补充信息"""
        crash_info = log_analysis.get('crash_info', {})
        
        if not overview.process_name:
            overview.process_name = crash_info.get('process')
        
        if not overview.pid:
            overview.pid = crash_info.get('pid')
        
        if not overview.crash_time:
            overview.crash_time = crash_info.get('timestamp')
        
        if not overview.crash_type:
            overview.crash_type = crash_info.get('type')
        
        if not overview.cpu_id:
            overview.cpu_id = crash_info.get('cpu')
    
    def _detect_crash_type(self, log_output: str) -> tuple:
        """检测崩溃类型和子类型"""
        log_lower = log_output.lower()
        
        # NULL pointer
        if 'null' in log_lower or 'unable to handle kernel null pointer' in log_lower:
            return 'NULL Pointer Dereference', 'invalid_memory_access'
        
        # Page fault
        if 'page fault' in log_lower:
            if 'write' in log_lower:
                return 'Page Fault', 'write_fault'
            elif 'read' in log_lower:
                return 'Page Fault', 'read_fault'
            return 'Page Fault', 'unknown'
        
        # Oops
        if 'oops' in log_lower:
            return 'Kernel Oops', 'general_protection_fault'
        
        # Panic
        if 'panic' in log_lower:
            return 'Kernel Panic', 'fatal_error'
        
        # Watchdog
        if 'watchdog' in log_lower:
            if 'softlockup' in log_lower:
                return 'Watchdog Timeout', 'softlockup'
            elif 'hardlockup' in log_lower:
                return 'Watchdog Timeout', 'hardlockup'
            return 'Watchdog Timeout', 'unknown'
        
        # BUG
        if 'bug:' in log_lower:
            return 'Kernel BUG', 'assertion_failure'
        
        # Data abort / Prefetch abort (ARM)
        if 'data abort' in log_lower:
            return 'Data Abort', 'memory_access_error'
        if 'prefetch abort' in log_lower:
            return 'Prefetch Abort', 'instruction_fetch_error'
        
        return 'Unknown', 'unknown'
    
    def _parse_error_code(self, log_output: str) -> Optional[str]:
        """解析错误码"""
        # ARM64 ESR
        esr_match = re.search(r'ESR\s*=\s*(0x[0-9a-fA-F]+)', log_output, re.IGNORECASE)
        if esr_match:
            return f"ESR: {esr_match.group(1)}"
        
        # x86_64 error code
        err_match = re.search(r'error_code\s*[=:]\s*(0x[0-9a-fA-F]+)', log_output, re.IGNORECASE)
        if err_match:
            return f"Error Code: {err_match.group(1)}"
        
        return None
    
    def _parse_fault_address(self, log_output: str) -> Optional[str]:
        """解析错误地址"""
        # FAR (Fault Address Register) for ARM
        far_match = re.search(r'FAR\s*=\s*(0x[0-9a-fA-F]+)', log_output, re.IGNORECASE)
        if far_match:
            return far_match.group(1)
        
        # CR2 for x86
        cr2_match = re.search(r'CR2:\s*(0x[0-9a-fA-F]+)', log_output, re.IGNORECASE)
        if cr2_match:
            return cr2_match.group(1)
        
        # Generic "unable to handle kernel * access at"
        access_match = re.search(r'unable to handle kernel \w+ access at\s+(0x[0-9a-fA-F]+)', 
                                  log_output, re.IGNORECASE)
        if access_match:
            return access_match.group(1)
        
        return None
    
    def _extract_error_message(self, log_output: str) -> Optional[str]:
        """提取错误消息"""
        # 查找 oops/panic 消息
        patterns = [
            r'Unable to handle[\s\S]*?(?=\n\n|\Z)',
            r'kernel BUG at[\s\S]*?(?=\n\n|\Z)',
            r'Oops[\s\S]*?(?=\n\n|\Z)',
            r'watchdog:.*?(?=\n|$)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log_output, re.IGNORECASE | re.MULTILINE)
            if match:
                msg = match.group(0).strip()
                # 限制长度
                if len(msg) > 500:
                    msg = msg[:500] + '...'
                return msg
        
        return None
    
    def _parse_modules(self, mod_output: str) -> List[Dict[str, str]]:
        """解析模块列表"""
        modules = []
        for line in mod_output.split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                modules.append({
                    'name': parts[0],
                    'address': parts[1],
                    'size': parts[2]
                })
        return modules
    
    def _identify_suspected_module(self, bt_output: str, modules: List[Dict]) -> Optional[str]:
        """从 backtrace 识别可疑模块"""
        module_names = {m['name'] for m in modules}
        
        for line in bt_output.split('\n'):
            for mod_name in module_names:
                # 检查 backtrace 中是否包含模块函数
                if mod_name.replace('_', '') in line.replace('_', '').lower():
                    return mod_name
        
        return None
    
    def _analyze_crash_scenario(self, overview: PanicOverview, crash_details: Dict) -> str:
        """分析崩溃场景"""
        scenarios = []
        
        crash_type = overview.crash_type or 'Unknown'
        process = overview.process_name or 'unknown'
        
        # 基于进程类型分析
        if process in ['swapper', 'migration', 'rcu', 'ksoftirqd']:
            scenarios.append(f"Kernel thread '{process}' crashed during system operation")
        elif process in ['init', 'systemd']:
            scenarios.append("System init process crashed - may indicate early boot issue")
        elif process and 'irq' in process.lower():
            scenarios.append(f"Interrupt handler ({process}) crashed")
        elif process and 'work' in process.lower():
            scenarios.append(f"Workqueue handler ({process}) crashed")
        else:
            scenarios.append(f"Process '{process}' triggered {crash_type}")
        
        # 基于崩溃类型分析
        if 'NULL Pointer' in crash_type:
            scenarios.append("Possible NULL pointer dereference - check initialization paths")
        elif 'Page Fault' in crash_type:
            scenarios.append("Memory access violation - check bounds and pointer validity")
        elif 'Watchdog' in crash_type:
            scenarios.append("System unresponsive - check for infinite loops or deadlocks")
        elif 'Oops' in crash_type:
            scenarios.append("Kernel internal error - check for code bugs or memory corruption")
        
        return '; '.join(scenarios)
    
    def _analyze_crash_context(self, overview: PanicOverview, crash_details: Dict) -> str:
        """分析崩溃上下文"""
        contexts = []
        
        # 基于 CPU ID 分析
        if overview.cpu_id is not None:
            if overview.cpu_count and overview.cpu_id >= overview.cpu_count:
                contexts.append(f"Invalid CPU ID ({overview.cpu_id}) - possible corruption")
            else:
                contexts.append(f"Crashed on CPU {overview.cpu_id}")
        
        # 基于模块分析
        if overview.suspected_module:
            contexts.append(f"Involves module: {overview.suspected_module}")
        
        # 基于地址分析
        fault_addr = overview.fault_address
        if fault_addr:
            addr_int = int(fault_addr, 16)
            if addr_int < 0x1000:
                contexts.append("Accessing very low address - likely NULL pointer issue")
            elif addr_int > 0xFFFF000000000000:  # Kernel space check for 64-bit
                contexts.append("Accessing kernel virtual address")
            elif 0x0000000000000000 <= addr_int < 0x00007FFFFFFFFFFF:
                contexts.append("Accessing userspace address from kernel context")
        
        return '; '.join(contexts)
    
    def _parse_crash_time(self, sys_info: Dict, log_analysis: Optional[Dict]) -> Optional[str]:
        """解析崩溃时间"""
        # 优先从日志分析获取
        if log_analysis and log_analysis.get('crash_info', {}).get('timestamp'):
            return log_analysis['crash_info']['timestamp']
        
        return None
