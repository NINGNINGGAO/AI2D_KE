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
        构建完整的分析上下文
        
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
        构建 Context Blocks 用于 Memory MCP
        
        将关键信息分割成多个 blocks，便于 AI 按需检索
        """
        blocks = []
        
        # Block 1: Issue 基本信息
        blocks.append({
            'block_id': 'issue_info',
            'type': 'metadata',
            'content': self._format_issue_info(extracted_info)
        })
        
        # Block 2: Crash 类型和错误信息
        blocks.append({
            'block_id': 'crash_info',
            'type': 'error',
            'content': self._format_crash_info(extracted_info)
        })
        
        # Block 3: 调用栈
        blocks.append({
            'block_id': 'call_stack',
            'type': 'stacktrace',
            'content': self._format_call_stack(extracted_info)
        })
        
        # Block 4: 关键日志
        blocks.append({
            'block_id': 'critical_logs',
            'type': 'logs',
            'content': self._format_critical_logs(extracted_info)
        })
        
        # Block 5: 系统信息
        blocks.append({
            'block_id': 'system_info',
            'type': 'system',
            'content': self._format_system_info(extracted_info)
        })
        
        # Block 6: 汇编分析
        blocks.append({
            'block_id': 'assembly_analysis',
            'type': 'assembly',
            'content': self._format_assembly_analysis(extracted_info)
        })
        
        return blocks
    
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
        
        return "\\n".join(lines) if lines else "No issue info available"
    
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
        if vmcore_analysis.get('call_stack'):
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
            if not vmcore_analysis.get('call_stack'):
                lines.append("Call Stack (from logs):")
                for line in log_analysis['crash_info']['call_stack']:
                    lines.append(f"  {line}")
        
        return "\\n".join(lines) if lines else "No call stack available"
    
    def _format_critical_logs(self, extracted_info: Dict) -> str:
        """格式化关键日志"""
        lines = []
        
        log_analysis = extracted_info.get('log_analysis', {})
        if log_analysis.get('critical_logs'):
            lines.append("Critical Log Entries:")
            for entry in log_analysis['critical_logs'][:20]:  # 限制条目数
                lines.append(entry.get('message', ''))
        
        return "\\n".join(lines) if lines else "No critical logs available"
    
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
