"""
Context Builder - 构建 AI 分析所需的上下文
"""
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class ContextBuilder:
    """上下文构建器"""
    
    def build(
        self,
        issue_summary: str,
        issue_description: str,
        extracted_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        构建完整的分析上下文 - 增强版
        
        Args:
            issue_summary: Issue 标题
            issue_description: Issue 描述
            extracted_info: 提取的信息（从 vmcore 和 log 解析器）
            
        Returns:
            完整的上下文字典
        """
        context = {
            'issue_info': {
                'summary': issue_summary,
                'description': issue_description
            },
            'crash_analysis': self._build_crash_analysis(extracted_info),
            'call_stack': self._extract_call_stack(extracted_info),
            'modules': self._extract_modules(extracted_info),
            'registers': self._extract_registers(extracted_info),
            'system_info': self._extract_system_info(extracted_info),
            'assembly_analysis': self._extract_assembly_analysis(extracted_info),
            # 新增：增强分析结果
            'panic_overview': self._extract_panic_overview(extracted_info),
            'stack_analysis': self._extract_stack_analysis(extracted_info),
            'register_analysis': self._extract_register_analysis(extracted_info),
            'raw_context_blocks': self._build_context_blocks(extracted_info)
        }
        
        return context
    
    def _build_crash_analysis(self, extracted_info: Dict) -> Dict[str, Any]:
        """构建 crash 分析信息"""
        analysis = {
            'crash_type': None,
            'timestamp': None,
            'cpu': None,
            'process': None,
            'pid': None,
            'error_details': None
        }
        
        # 从 log 分析中提取
        log_analysis = extracted_info.get('log_analysis', {})
        if log_analysis.get('crash_info'):
            crash_info = log_analysis['crash_info']
            analysis['crash_type'] = crash_info.get('type')
            analysis['timestamp'] = crash_info.get('timestamp')
            analysis['cpu'] = crash_info.get('cpu')
            analysis['process'] = crash_info.get('process')
            analysis['pid'] = crash_info.get('pid')
            analysis['error_details'] = crash_info.get('error_message')
        
        # 从 vmcore 分析中提取
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        if vmcore_analysis.get('crash_type'):
            analysis['crash_type'] = vmcore_analysis['crash_type']
        
        return analysis
    
    def _extract_call_stack(self, extracted_info: Dict) -> List[Dict[str, str]]:
        """提取调用栈"""
        call_stack = []
        
        # 从 vmcore 分析中提取
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        if vmcore_analysis.get('call_stack'):
            call_stack = vmcore_analysis['call_stack']
        
        # 从 log 分析中补充
        if not call_stack:
            log_analysis = extracted_info.get('log_analysis', {})
            if log_analysis.get('crash_info', {}).get('call_stack'):
                raw_stack = log_analysis['crash_info']['call_stack']
                call_stack = [{'frame': i, 'function': line} for i, line in enumerate(raw_stack)]
        
        return call_stack
    
    def _extract_modules(self, extracted_info: Dict) -> List[Dict[str, str]]:
        """提取涉及的模块"""
        modules = []
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        if vmcore_analysis.get('modules'):
            modules = vmcore_analysis['modules']
        
        return modules
    
    def _extract_registers(self, extracted_info: Dict) -> Dict[str, str]:
        """提取寄存器信息"""
        registers = {}
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        if vmcore_analysis.get('registers'):
            registers = vmcore_analysis['registers']
        
        return registers
    
    def _extract_system_info(self, extracted_info: Dict) -> Dict[str, str]:
        """提取系统信息"""
        sys_info = {}
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        if vmcore_analysis.get('system_info'):
            sys_info = vmcore_analysis['system_info']
        
        return sys_info

    def _extract_panic_overview(self, extracted_info: Dict) -> Dict[str, Any]:
        """提取 Panic 概述"""
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        return vmcore_analysis.get('panic_overview', {})

    def _extract_stack_analysis(self, extracted_info: Dict) -> Dict[str, Any]:
        """提取调用栈分析"""
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        return vmcore_analysis.get('stack_analysis', {})

    def _extract_register_analysis(self, extracted_info: Dict) -> Dict[str, Any]:
        """提取寄存器分析"""
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        return vmcore_analysis.get('register_analysis', {})

    def _extract_assembly_analysis(self, extracted_info: Dict) -> Dict[str, Any]:
        """提取汇编层次分析结果"""
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        asm_analysis = vmcore_analysis.get('assembly_analysis', {})
        
        if not asm_analysis or not asm_analysis.get('performed'):
            return {
                'performed': False,
                'reason': asm_analysis.get('error', 'No assembly analysis performed')
            }
        
        return {
            'performed': True,
            'crash_pc': asm_analysis.get('crash_pc'),
            'anomaly_count': len(asm_analysis.get('anomalies', [])),
            'anomalies': asm_analysis.get('anomalies', []),
            'suspicious_patterns': asm_analysis.get('suspicious_patterns', []),
            'recommendations': asm_analysis.get('recommendations', []),
            'bitflip_detected': 'bitflip_detection' in asm_analysis,
            'bitflip_details': asm_analysis.get('bitflip_detection'),
            'function_analyses_summary': [
                {
                    'function': fa.get('function'),
                    'suspicious_count': len(fa.get('analysis', {}).get('anomalies', []))
                }
                for fa in asm_analysis.get('function_analyses', [])
            ]
        }
    
    def _build_context_blocks(self, extracted_info: Dict) -> List[Dict[str, str]]:
        """
        构建 Context Blocks 用于 Memory MCP - 增强版
        
        将关键信息分割成多个 blocks，便于 AI 按需检索
        """
        blocks = []
        
        # Block 1: Panic 概述（新增）
        blocks.append({
            'block_id': 'panic_overview',
            'type': 'overview',
            'content': self._format_panic_overview(extracted_info)
        })
        
        # Block 2: Issue 基本信息
        blocks.append({
            'block_id': 'issue_info',
            'type': 'metadata',
            'content': self._format_issue_info(extracted_info)
        })
        
        # Block 3: Crash 类型和错误信息
        blocks.append({
            'block_id': 'crash_info',
            'type': 'error',
            'content': self._format_crash_info(extracted_info)
        })
        
        # Block 4: 调用栈分析（增强）
        blocks.append({
            'block_id': 'call_stack',
            'type': 'stacktrace',
            'content': self._format_call_stack(extracted_info)
        })
        
        # Block 5: 调用栈深度分析（新增）
        blocks.append({
            'block_id': 'stack_analysis',
            'type': 'analysis',
            'content': self._format_stack_analysis(extracted_info)
        })
        
        # Block 6: 关键日志
        blocks.append({
            'block_id': 'critical_logs',
            'type': 'logs',
            'content': self._format_critical_logs(extracted_info)
        })
        
        # Block 7: 寄存器分析（新增）
        blocks.append({
            'block_id': 'register_analysis',
            'type': 'registers',
            'content': self._format_register_analysis(extracted_info)
        })
        
        # Block 8: 系统信息
        blocks.append({
            'block_id': 'system_info',
            'type': 'system',
            'content': self._format_system_info(extracted_info)
        })
        
        # Block 9: 汇编分析
        blocks.append({
            'block_id': 'assembly_analysis',
            'type': 'assembly',
            'content': self._format_assembly_analysis(extracted_info)
        })
        
        return blocks
    
    def _format_panic_overview(self, extracted_info: Dict) -> str:
        """格式化 Panic 概述"""
        lines = []
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        overview = vmcore_analysis.get('panic_overview', {})
        
        if not overview or 'error' in overview:
            return "Panic overview not available"
        
        lines.append("=" * 60)
        lines.append("PANIC OVERVIEW")
        lines.append("=" * 60)
        
        # 基本信息
        lines.append(f"\nCrash Type: {overview.get('crash_type', 'Unknown')}")
        if overview.get('crash_subtype'):
            lines.append(f"Subtype: {overview['crash_subtype']}")
        
        # 时间信息
        if overview.get('crash_time'):
            lines.append(f"\nCrash Time: {overview['crash_time']}")
        if overview.get('uptime'):
            lines.append(f"System Uptime: {overview['uptime']}")
        
        # 内核版本
        if overview.get('kernel_version'):
            lines.append(f"\nKernel Version: {overview['kernel_version']}")
        if overview.get('kernel_release'):
            lines.append(f"Release: {overview['kernel_release']}")
        
        # 崩溃场景
        if overview.get('crash_scenario'):
            lines.append(f"\nCrash Scenario: {overview['crash_scenario']}")
        if overview.get('crash_context'):
            lines.append(f"Context: {overview['crash_context']}")
        
        # 进程信息
        if overview.get('process_name'):
            lines.append(f"\nProcess: {overview['process_name']}")
        if overview.get('pid'):
            lines.append(f"PID: {overview['pid']}")
        if overview.get('cpu_id') is not None:
            lines.append(f"CPU: {overview['cpu_id']}")
        
        # 模块信息
        if overview.get('suspected_module'):
            lines.append(f"\nSuspected Module: {overview['suspected_module']}")
        if overview.get('involved_modules'):
            lines.append(f"Involved Modules: {', '.join(overview['involved_modules'][:10])}")
        
        # 错误详情
        if overview.get('fault_address'):
            lines.append(f"\nFault Address: {overview['fault_address']}")
        if overview.get('error_code'):
            lines.append(f"Error Code: {overview['error_code']}")
        
        lines.append("\n" + "=" * 60)
        
        return "\n".join(lines)

    def _format_issue_info(self, extracted_info: Dict) -> str:
        """格式化 Issue 信息"""
        lines = []
        
        log_analysis = extracted_info.get('log_analysis', {})
        if log_analysis.get('crash_info'):
            crash = log_analysis['crash_info']
            lines.append(f"Crash Type: {crash.get('type', 'Unknown')}")
            lines.append(f"Timestamp: {crash.get('timestamp', 'Unknown')}")
            lines.append(f"CPU: {crash.get('cpu', 'Unknown')}")
            lines.append(f"Process: {crash.get('process', 'Unknown')}")
            lines.append(f"PID: {crash.get('pid', 'Unknown')}")
        
        return "\n".join(lines) if lines else "No issue info available"
    
    def _format_crash_info(self, extracted_info: Dict) -> str:
        """格式化 Crash 信息"""
        lines = []
        
        log_analysis = extracted_info.get('log_analysis', {})
        if log_analysis.get('crash_info', {}).get('error_message'):
            lines.append("Error Details:")
            lines.append(log_analysis['crash_info']['error_message'])
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        if vmcore_analysis.get('crash_type'):
            lines.append(f"Crash Type (from vmcore): {vmcore_analysis['crash_type']}")
        
        return "\\n".join(lines) if lines else "No crash info available"
    
    def _format_call_stack(self, extracted_info: Dict) -> str:
        """格式化调用栈"""
        lines = []
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        stack_analysis = vmcore_analysis.get('stack_analysis', {})
        
        # 使用增强的调用栈分析
        if stack_analysis and 'frames' in stack_analysis:
            lines.append("Call Stack (Enhanced Analysis):")
            lines.append("")
            
            for frame in stack_analysis['frames'][:15]:  # 限制显示15帧
                func = frame.get('function_name', 'unknown')
                idx = frame.get('frame_number', 0)
                addr = frame.get('address', '')
                module = frame.get('module', '')
                subsystem = frame.get('subsystem', '')
                
                line = f"  #{idx} {func}"
                if addr:
                    line += f" [{addr}]"
                if module:
                    line += f" ({module})"
                if subsystem:
                    line += f" [{subsystem}]"
                
                lines.append(line)
        
        # 回退到基本调用栈
        elif vmcore_analysis.get('call_stack'):
            lines.append("Call Stack (from vmcore):")
            for frame in vmcore_analysis['call_stack']:
                if isinstance(frame, dict):
                    func = frame.get('function', 'unknown')
                    addr = frame.get('address', '')
                    lines.append(f"  {func} {addr}")
                else:
                    lines.append(f"  {frame}")
        
        log_analysis = extracted_info.get('log_analysis', {})
        if log_analysis.get('crash_info', {}).get('call_stack'):
            if not vmcore_analysis.get('call_stack') and not stack_analysis.get('frames'):
                lines.append("Call Stack (from logs):")
                for line in log_analysis['crash_info']['call_stack']:
                    lines.append(f"  {line}")
        
        return "\n".join(lines) if lines else "No call stack available"

    def _format_stack_analysis(self, extracted_info: Dict) -> str:
        """格式化调用栈深度分析"""
        lines = []
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        stack_analysis = vmcore_analysis.get('stack_analysis', {})
        
        if not stack_analysis or 'error' in stack_analysis:
            return "Stack analysis not available"
        
        lines.append("=" * 60)
        lines.append("CALL STACK ANALYSIS")
        lines.append("=" * 60)
        
        # 执行上下文
        if stack_analysis.get('execution_context'):
            lines.append(f"\nExecution Context: {stack_analysis['execution_context']}")
        
        # 调用链
        if stack_analysis.get('call_chains'):
            lines.append("\nCall Chains:")
            for chain in stack_analysis['call_chains'][:5]:
                caller = chain.get('caller', 'unknown')
                callee = chain.get('callee', 'unknown')
                call_type = chain.get('call_type', 'direct')
                context = chain.get('context', '')
                
                line = f"  {caller} -> {callee} ({call_type})"
                if context:
                    line += f" [{context}]"
                lines.append(line)
        
        # 子系统路径
        if stack_analysis.get('subsystem_trace'):
            lines.append(f"\nSubsystem Trace: {' -> '.join(stack_analysis['subsystem_trace'])}")
        
        # 可疑模式
        if stack_analysis.get('suspicious_patterns'):
            lines.append("\nSuspicious Patterns:")
            for pattern in stack_analysis['suspicious_patterns'][:5]:
                severity = pattern.get('severity', 'low').upper()
                ptype = pattern.get('type', 'unknown')
                desc = pattern.get('description', '')
                lines.append(f"  [{severity}] {ptype}: {desc}")
        
        # 可能的场景
        if stack_analysis.get('likely_scenarios'):
            lines.append("\nLikely Scenarios:")
            for i, scenario in enumerate(stack_analysis['likely_scenarios'][:5], 1):
                lines.append(f"  {i}. {scenario}")
        
        lines.append("\n" + "=" * 60)
        
        return "\n".join(lines)
    
    def _format_critical_logs(self, extracted_info: Dict) -> str:
        """格式化关键日志"""
        lines = []
        
        log_analysis = extracted_info.get('log_analysis', {})
        if log_analysis.get('critical_logs'):
            lines.append("Critical Log Entries:")
            for entry in log_analysis['critical_logs'][:20]:  # 限制条目数
                lines.append(entry.get('message', ''))
        
        return "\\n".join(lines) if lines else "No critical logs available"
    
    def _format_register_analysis(self, extracted_info: Dict) -> str:
        """格式化寄存器分析"""
        lines = []

        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        reg_analysis = vmcore_analysis.get('register_analysis', {})

        if not reg_analysis or 'error' in reg_analysis:
            # 尝试使用 register_analysis_report
            if vmcore_analysis.get('register_analysis_report'):
                return vmcore_analysis['register_analysis_report']
            return "Register analysis not available"

        lines.append("=" * 60)
        lines.append("REGISTER ANALYSIS")
        lines.append("=" * 60)

        # 当前寄存器状态
        if reg_analysis.get('current_registers'):
            lines.append("\nCurrent Registers:")
            for reg_name, reg_info in list(reg_analysis['current_registers'].items())[:15]:
                value = reg_info.get('value', 'N/A')
                flags = []
                if reg_info.get('is_null'):
                    flags.append("NULL")
                if reg_info.get('is_kernel_addr'):
                    flags.append("KERNEL")
                if reg_info.get('is_user_addr'):
                    flags.append("USER")

                flag_str = f" [{', '.join(flags)}]" if flags else ""
                lines.append(f"  {reg_name.upper():4s}: {value}{flag_str}")

        # 关键崩溃信息
        if reg_analysis.get('crash_pc') or reg_analysis.get('faulting_address'):
            lines.append("\nCritical Information:")
            if reg_analysis.get('crash_pc'):
                lines.append(f"  Crash PC: {reg_analysis['crash_pc']}")
            if reg_analysis.get('faulting_address'):
                lines.append(f"  Faulting Address: {reg_analysis['faulting_address']}")

        # 可疑寄存器
        if reg_analysis.get('suspicious_registers'):
            lines.append("\nSuspicious Registers:")
            for susp in reg_analysis['suspicious_registers'][:5]:
                reg = susp.get('register', 'unknown')
                issue = susp.get('issue', '')
                severity = susp.get('severity', 'low').upper()
                lines.append(f"  [{severity}] {reg}: {issue}")

        # 寄存器链
        if reg_analysis.get('register_chain'):
            lines.append("\nRegister Chain Analysis:")
            for entry in reg_analysis['register_chain'][:5]:
                if 'register' in entry:
                    mark = "⚠️ " if entry.get('is_suspicious') else "  "
                    lines.append(f"  {mark}{entry.get('register')} = {entry.get('value')}")
                else:
                    lines.append(f"    {entry.get('description', '')}")

        # 根因推断
        lines.append("\nRoot Cause Analysis:")
        if reg_analysis.get('likely_fault_source'):
            lines.append(f"  Likely Source: {reg_analysis['likely_fault_source']}")
        if reg_analysis.get('root_cause_function'):
            lines.append(f"  Suspected Function: {reg_analysis['root_cause_function']}")

        lines.append("\n" + "=" * 60)

        return "\n".join(lines)

    def _format_system_info(self, extracted_info: Dict) -> str:
        """格式化系统信息"""
        lines = []

        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        if vmcore_analysis.get('system_info'):
            lines.append("System Information:")
            for key, value in vmcore_analysis['system_info'].items():
                lines.append(f"  {key}: {value}")
        
        if vmcore_analysis.get('modules'):
            lines.append(f"\nLoaded Modules ({len(vmcore_analysis['modules'])}):")
            for mod in vmcore_analysis['modules'][:10]:  # 限制显示数量
                if isinstance(mod, dict):
                    lines.append(f"  {mod.get('name', 'unknown')}")
                else:
                    lines.append(f"  {mod}")
        
        if vmcore_analysis.get('registers'):
            lines.append("\nKey Registers:")
            for reg, val in list(vmcore_analysis['registers'].items())[:10]:
                lines.append(f"  {reg}: {val}")
        
        return "\n".join(lines) if lines else "No system info available"

    def _format_assembly_analysis(self, extracted_info: Dict) -> str:
        """格式化汇编分析信息"""
        lines = []
        
        vmcore_analysis = extracted_info.get('vmcore_analysis', {})
        asm_analysis = vmcore_analysis.get('assembly_analysis', {})
        
        if not asm_analysis or not asm_analysis.get('performed'):
            return "No assembly analysis available"
        
        lines.append("Assembly-Level Analysis:")
        lines.append(f"  Crash PC: {asm_analysis.get('crash_pc', 'Unknown')}")
        lines.append(f"  Anomalies Found: {len(asm_analysis.get('anomalies', []))}")
        
        # 位翻转检测
        if 'bitflip_detection' in asm_analysis:
            bitflip = asm_analysis['bitflip_detection']
            lines.append(f"\n  Bitflip Detection:")
            lines.append(f"    Original: {bitflip.get('original_value')}")
            lines.append(f"    Flipped: {bitflip.get('flipped_value')}")
            lines.append(f"    Bit Position: {bitflip.get('bit_position')}")
            lines.append(f"    Confidence: {bitflip.get('confidence')}")
        
        # 异常详情
        anomalies = asm_analysis.get('anomalies', [])
        if anomalies:
            lines.append(f"\n  Detected Anomalies:")
            for i, anomaly in enumerate(anomalies[:5], 1):  # 只显示前5个
                lines.append(f"    {i}. [{anomaly.get('severity')}] {anomaly.get('type')}")
                lines.append(f"       {anomaly.get('description', '')}")
                if 'function' in anomaly:
                    lines.append(f"       Function: {anomaly['function']}")
        
        # 可疑模式
        patterns = asm_analysis.get('suspicious_patterns', [])
        if patterns:
            lines.append(f"\n  Suspicious Patterns:")
            for pattern in patterns[:3]:
                lines.append(f"    - {pattern.get('function')}: {pattern.get('finding')}")
        
        # 分析建议
        recommendations = asm_analysis.get('recommendations', [])
        if recommendations:
            lines.append(f"\n  Recommendations:")
            for rec in recommendations[:3]:
                lines.append(f"    - {rec}")
        
        return "\n".join(lines)
