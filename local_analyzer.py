"""
本地 Kernel Crash Dump 分析器
支持直接从本地目录分析 crash dump，无需 Jira 下载
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class CrashBasicInfo:
    """Crash 基本信息"""
    crash_id: str
    exception_class: str
    exception_time: str
    uptime: str
    pc: str
    lr: str
    process_name: str
    pid: int
    parent_process: str
    parent_pid: int
    kernel_version: str = ""
    platform: str = ""
    build_info: str = ""
    wdt_status: int = 0
    exception_type: int = 0


@dataclass
class StackFrame:
    """调用栈帧"""
    address: str
    symbol: str
    offset: str
    module: str = "vmlinux"
    source_file: str = ""
    line_number: int = 0


@dataclass
class CPUState:
    """CPU 状态"""
    cpu_id: int
    process: Optional[str]
    pid: Optional[int]
    stack_trace: List[StackFrame]
    registers: Dict[str, str] = field(default_factory=dict)


@dataclass
class CrashAnalysis:
    """完整的 Crash 分析结果"""
    basic_info: CrashBasicInfo
    backtrace: List[StackFrame]
    cpu_states: Dict[int, CPUState]
    critical_logs: List[str]
    root_cause_analysis: str = ""
    affected_modules: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class LocalCrashDumpAnalyzer:
    """本地 Crash Dump 分析器"""
    
    def __init__(self, dump_dir: str):
        self.dump_dir = Path(dump_dir)
        self.symbols_dir = self.dump_dir / "symbols"
        self.vmlinux_path = self.symbols_dir / "vmlinux"
        
    def analyze(self) -> CrashAnalysis:
        """执行完整分析"""
        logger.info(f"开始分析 crash dump: {self.dump_dir}")
        
        # 1. 解析基本信息
        basic_info = self._parse_basic_info()
        
        # 2. 解析调用栈
        backtrace = self._parse_backtrace()
        
        # 3. 解析各 CPU 状态
        cpu_states = self._parse_cpu_states()
        
        # 4. 提取关键日志
        critical_logs = self._extract_critical_logs()
        
        # 5. 生成根因分析
        root_cause = self._analyze_root_cause(basic_info, backtrace, cpu_states)
        
        # 6. 识别受影响模块
        affected_modules = self._identify_modules(backtrace)
        
        # 7. 生成修复建议
        recommendations = self._generate_recommendations(basic_info, root_cause)
        
        return CrashAnalysis(
            basic_info=basic_info,
            backtrace=backtrace,
            cpu_states=cpu_states,
            critical_logs=critical_logs,
            root_cause_analysis=root_cause,
            affected_modules=affected_modules,
            recommendations=recommendations
        )
    
    def _parse_basic_info(self) -> CrashBasicInfo:
        """解析 __exp_main.txt 获取基本信息"""
        exp_main_file = self.dump_dir / "__exp_main.txt"
        
        info = {
            'crash_id': self.dump_dir.name,
            'exception_class': 'Unknown',
            'exception_time': '',
            'uptime': '',
            'pc': '',
            'lr': '',
            'process_name': '',
            'pid': 0,
            'parent_process': '',
            'parent_pid': 0,
            'kernel_version': '',
            'platform': '',
            'build_info': ''
        }
        
        if not exp_main_file.exists():
            logger.warning(f"未找到 {exp_main_file}")
            return CrashBasicInfo(**info)
        
        content = exp_main_file.read_text(encoding='utf-8', errors='ignore')
        
        # 解析 Exception Class
        match = re.search(r'Exception Class:\s*(\w+)', content)
        if match:
            info['exception_class'] = match.group(1)
        
        # 解析时间
        match = re.search(r'Exception Log Time:\[(.+?)\]\s*\[(.+?)\]', content)
        if match:
            info['exception_time'] = match.group(1)
            info['uptime'] = match.group(2)
        
        # 解析 PC
        match = re.search(r'PC is at \[<(.+?)>\]\s*(.+)', content)
        if match:
            info['pc'] = f"[{match.group(1)}] {match.group(2)}"
        
        # 解析 LR
        match = re.search(r'LR is at \[<(.+?)>\]\s*(.+)', content)
        if match:
            info['lr'] = f"[{match.group(1)}] {match.group(2)}"
        
        # 解析进程信息
        match = re.search(r'Current Executing Process:\s*\[(.+?),\s*(\d+)\]\[(.+?),\s*(\d+)\]', content)
        if match:
            info['process_name'] = match.group(1)
            info['pid'] = int(match.group(2))
            info['parent_process'] = match.group(3)
            info['parent_pid'] = int(match.group(4))
        
        # 解析 Build Info
        match = re.search(r"Build Info:\s*'(.+?)'", content)
        if match:
            info['build_info'] = match.group(1)
            # 提取平台信息
            platform_match = re.search(r'(mt\d+)', info['build_info'], re.IGNORECASE)
            if platform_match:
                info['platform'] = platform_match.group(1).upper()
        
        # 从 SYS_REBOOT_REASON 获取 WDT 信息
        reboot_reason_file = self.dump_dir / "SYS_REBOOT_REASON"
        if reboot_reason_file.exists():
            reboot_content = reboot_reason_file.read_text(encoding='utf-8', errors='ignore')
            wdt_match = re.search(r'WDT status:\s*(\d+)', reboot_content)
            if wdt_match:
                info['wdt_status'] = int(wdt_match.group(1))
            exc_type_match = re.search(r'exception type:\s*(\d+)', reboot_content)
            if exc_type_match:
                info['exception_type'] = int(exc_type_match.group(1))
        
        # 从 kernel log 获取版本信息
        kernel_log_file = self.dump_dir / "SYS_KERNEL_LOG"
        if kernel_log_file.exists():
            kernel_content = kernel_log_file.read_text(encoding='utf-8', errors='ignore')
            version_match = re.search(r'Linux version\s+(.+)', kernel_content)
            if version_match:
                info['kernel_version'] = version_match.group(1)
        
        return CrashBasicInfo(**info)
    
    def _parse_backtrace(self) -> List[StackFrame]:
        """解析调用栈"""
        exp_main_file = self.dump_dir / "__exp_main.txt"
        if not exp_main_file.exists():
            return []
        
        content = exp_main_file.read_text(encoding='utf-8', errors='ignore')
        frames = []
        
        # 查找 Backtrace 部分
        bt_match = re.search(r'Backtrace:(.+?)(?:\n\n|\Z)', content, re.DOTALL)
        if bt_match:
            bt_content = bt_match.group(1)
            
            # 解析每一帧
            for line in bt_content.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # 匹配格式: [<address>] symbol+offset/size
                match = re.search(r'\[<(.+?)>\]\s*(.+)', line)
                if match:
                    address = match.group(1)
                    symbol_info = match.group(2).strip()
                    
                    # 解析符号和偏移
                    symbol_match = re.match(r'(\S+)([+-]0x[0-9a-f]+)?(/0x[0-9a-f]+)?', symbol_info)
                    if symbol_match:
                        symbol = symbol_match.group(1)
                        offset = symbol_match.group(2) or ""
                    else:
                        symbol = symbol_info
                        offset = ""
                    
                    frames.append(StackFrame(
                        address=address,
                        symbol=symbol,
                        offset=offset
                    ))
        
        return frames
    
    def _parse_cpu_states(self) -> Dict[int, CPUState]:
        """解析各 CPU 状态"""
        # 从 MRDUMP_TOOL_RESULT 或已有的解析文件获取
        cpu_states = {}
        
        # 尝试从 out.json 读取
        out_json = self.dump_dir / "out.json"
        if out_json.exists():
            try:
                data = json.loads(out_json.read_text(encoding='utf-8', errors='ignore'))
                # 这里可以根据实际 JSON 结构解析
            except:
                pass
        
        return cpu_states
    
    def _extract_critical_logs(self) -> List[str]:
        """提取关键日志"""
        kernel_log_file = self.dump_dir / "SYS_KERNEL_LOG"
        if not kernel_log_file.exists():
            return []
        
        content = kernel_log_file.read_text(encoding='utf-8', errors='ignore')
        lines = content.split('\n')
        
        critical_patterns = [
            r'BUG:',
            r'WARNING:',
            r'Oops:',
            r'panic',
            r'Unable to handle',
            r'hard LOCKUP',
            r'softlockup',
            r'Call trace',
        ]
        
        critical_logs = []
        for line in lines:
            for pattern in critical_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    critical_logs.append(line.strip())
                    break
        
        # 限制数量，保留最新的
        return critical_logs[-100:] if len(critical_logs) > 100 else critical_logs
    
    def _analyze_root_cause(self, basic_info: CrashBasicInfo, 
                           backtrace: List[StackFrame],
                           cpu_states: Dict[int, CPUState]) -> str:
        """分析根因"""
        analysis_parts = []
        
        # 根据异常类型分析
        if basic_info.exception_type == 2:
            analysis_parts.append("异常类型为 Watchdog Timeout (WDT status: 2)，表示发生了硬件看门狗超时。")
        
        # 分析 PC 位置
        if basic_info.pc:
            if 'pick_next_task_fair' in basic_info.pc:
                analysis_parts.append("PC 指向调度器函数 pick_next_task_fair()，这是一个 CFS 调度器函数。")
                analysis_parts.append("崩溃发生在进程调度过程中，可能原因包括：")
                analysis_parts.append("- 调度器数据结构损坏")
                analysis_parts.append("- 内存访问越界导致调度队列损坏")
                analysis_parts.append("- 内核模块干扰了调度器正常操作")
            elif '__queue_work' in basic_info.pc:
                analysis_parts.append("PC 指向工作队列函数 __queue_work()，这是内核工作队列机制的核心函数。")
                analysis_parts.append("崩溃发生在工作队列处理过程中，可能原因包括：")
                analysis_parts.append("- 工作队列数据结构损坏")
                analysis_parts.append("- 工作项回调函数出现问题")
                analysis_parts.append("- 并发访问导致的数据竞争")
        
        # 分析进程类型
        if 'kworker' in basic_info.process_name:
            analysis_parts.append(f"崩溃发生在内核工作线程 {basic_info.process_name} 中，这是一个内核态线程。")
        
        return "\n".join(analysis_parts)
    
    def _identify_modules(self, backtrace: List[StackFrame]) -> List[str]:
        """识别涉及的模块"""
        modules = set()
        
        for frame in backtrace:
            # 从符号名推断模块
            if any(x in frame.symbol for x in ['scheduler', 'workqueue', 'sched']):
                modules.add("kernel/sched")
            elif 'timer' in frame.symbol:
                modules.add("kernel/time")
            elif 'irq' in frame.symbol or 'gic' in frame.symbol:
                modules.add("kernel/irq")
            elif 'mm' in frame.symbol or 'page' in frame.symbol:
                modules.add("kernel/mm")
        
        # 检查 SYS_MODULES_INFO
        modules_file = self.dump_dir / "SYS_MODULES_INFO"
        if modules_file.exists():
            content = modules_file.read_text(encoding='utf-8', errors='ignore')
            # 解析已加载的内核模块
            for line in content.split('\n'):
                if '.ko' in line:
                    match = re.search(r'(\w+)\.ko', line)
                    if match:
                        modules.add(match.group(1) + ".ko")
        
        return list(modules)
    
    def _generate_recommendations(self, basic_info: CrashBasicInfo, 
                                  root_cause: str) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        # 通用建议
        recommendations.append("1. 检查 kernel log 中崩溃前的警告信息，寻找潜在问题线索")
        recommendations.append("2. 确认 vmlinux 符号文件与运行内核版本完全匹配")
        
        # 根据具体崩溃类型
        if 'pick_next_task_fair' in basic_info.pc:
            recommendations.append("3. 检查是否有内核模块修改了调度器相关数据结构")
            recommendations.append("4. 使用 Kernel Address Sanitizer (KASAN) 重新编译内核以检测内存越界")
            recommendations.append("5. 检查是否存在自旋锁或互斥锁的死锁情况")
        elif '__queue_work' in basic_info.pc:
            recommendations.append("3. 检查工作队列回调函数是否正确初始化")
            recommendations.append("4. 验证延迟工作的定时器是否正确设置")
            recommendations.append("5. 检查是否存在工作队列的重复提交或竞态条件")
        
        if basic_info.exception_type == 2:
            recommendations.append("6. 分析看门狗超时前的系统状态，检查是否有无限循环或死锁")
            recommendations.append("7. 考虑增加看门狗超时时间以收集更多信息")
        
        return recommendations


class AnalysisReportGenerator:
    """分析报告生成器"""
    
    def __init__(self, analysis: CrashAnalysis):
        self.analysis = analysis
    
    def generate_markdown(self) -> str:
        """生成 Markdown 格式的分析报告"""
        lines = []
        
        # 标题
        lines.append(f"# Kernel Crash Analysis Report")
        lines.append(f"## {self.analysis.basic_info.crash_id}")
        lines.append("")
        
        # 基本信息
        lines.append("## 基本信息")
        lines.append("")
        lines.append("| 项目 | 值 |")
        lines.append("|------|-----|")
        info = self.analysis.basic_info
        lines.append(f"| Crash ID | {info.crash_id} |")
        lines.append(f"| 异常类型 | {info.exception_class} |")
        lines.append(f"| 异常时间 | {info.exception_time} |")
        lines.append(f"| 系统运行时间 | {info.uptime} |")
        lines.append(f"| 平台 | {info.platform} |")
        lines.append(f"| WDT Status | {info.wdt_status} |")
        lines.append(f"| Exception Type | {info.exception_type} |")
        lines.append("")
        
        # 进程信息
        lines.append("## 进程信息")
        lines.append("")
        lines.append(f"- **当前进程**: {info.process_name} (PID: {info.pid})")
        lines.append(f"- **父进程**: {info.parent_process} (PID: {info.parent_pid})")
        lines.append("")
        
        # 崩溃位置
        lines.append("## 崩溃位置")
        lines.append("")
        lines.append(f"- **PC (程序计数器)**: {info.pc}")
        lines.append(f"- **LR (链接寄存器)**: {info.lr}")
        lines.append("")
        
        # 调用栈
        lines.append("## 调用栈 (Backtrace)")
        lines.append("")
        lines.append("```")
        for i, frame in enumerate(self.analysis.backtrace, 1):
            lines.append(f"#{i:2d} [{frame.address}] {frame.symbol}{frame.offset}")
        lines.append("```")
        lines.append("")
        
        # 根因分析
        lines.append("## 根因分析")
        lines.append("")
        lines.append(self.analysis.root_cause_analysis)
        lines.append("")
        
        # 涉及模块
        if self.analysis.affected_modules:
            lines.append("## 涉及模块")
            lines.append("")
            for module in self.analysis.affected_modules:
                lines.append(f"- {module}")
            lines.append("")
        
        # 关键日志
        if self.analysis.critical_logs:
            lines.append("## 关键日志片段")
            lines.append("")
            lines.append("```")
            for log in self.analysis.critical_logs[-30:]:  # 只显示最后30条
                lines.append(log)
            lines.append("```")
            lines.append("")
        
        # 修复建议
        lines.append("## 修复建议")
        lines.append("")
        for rec in self.analysis.recommendations:
            lines.append(rec)
        lines.append("")
        
        # 构建信息
        lines.append("## 构建信息")
        lines.append("")
        lines.append(f"```\n{info.build_info}\n```")
        lines.append("")
        
        # 内核版本
        if info.kernel_version:
            lines.append("## 内核版本")
            lines.append("")
            lines.append(f"```\n{info.kernel_version}\n```")
            lines.append("")
        
        # 页脚
        lines.append("---")
        lines.append(f"*Report generated by ke-analyzer on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return '\n'.join(lines)
    
    def save_report(self, output_path: str):
        """保存报告到文件"""
        report = self.generate_markdown()
        Path(output_path).write_text(report, encoding='utf-8')
        logger.info(f"报告已保存到: {output_path}")


async def analyze_crash_dump(dump_dir: str, output_dir: str):
    """分析单个 crash dump 并生成报告"""
    analyzer = LocalCrashDumpAnalyzer(dump_dir)
    analysis = analyzer.analyze()
    
    generator = AnalysisReportGenerator(analysis)
    
    # 确保输出目录存在
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # 生成输出文件名
    crash_id = Path(dump_dir).name
    output_file = Path(output_dir) / f"report_{crash_id}.md"
    
    generator.save_report(str(output_file))
    
    return analysis, str(output_file)


async def main():
    """主函数"""
    import sys
    
    # 设置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 默认分析两个 crash dump 目录
    base_dir = Path("/home/agogin/.openclaw/workspace/ke-analyzer")
    crash_dirs = [
        base_dir / "db.fatal.00.KE.dbg.DEC",
        base_dir / "db.fatal.01.KE.dbg.DEC",
    ]
    output_dir = base_dir / "analysis_reports"
    
    # 分析每个 crash dump
    for crash_dir in crash_dirs:
        if crash_dir.exists():
            logger.info(f"\n{'='*60}")
            logger.info(f"分析: {crash_dir.name}")
            logger.info(f"{'='*60}")
            
            try:
                analysis, report_path = await analyze_crash_dump(
                    str(crash_dir),
                    str(output_dir)
                )
                
                logger.info(f"\n基本信息:")
                logger.info(f"  - 异常类型: {analysis.basic_info.exception_class}")
                logger.info(f"  - 进程: {analysis.basic_info.process_name}")
                logger.info(f"  - PC: {analysis.basic_info.pc}")
                logger.info(f"\n报告已生成: {report_path}")
                
            except Exception as e:
                logger.error(f"分析失败: {e}")
                import traceback
                traceback.print_exc()
        else:
            logger.warning(f"目录不存在: {crash_dir}")
    
    logger.info(f"\n{'='*60}")
    logger.info("分析完成")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
