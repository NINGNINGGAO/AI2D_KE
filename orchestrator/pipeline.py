"""
分析流程管道
协调完整的 KE 分析流程
"""
import os
import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path

from orchestrator.config import get_settings
from orchestrator.state_manager import state_manager, AnalysisStatus
from extractor.vmcore_parser import VmcoredParser
from extractor.log_parser import KernelLogParser
from extractor.context_builder import ContextBuilder
from agent.analyzer import CrashAnalyzer
from jira.client import JiraClient

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """分析流程管道"""
    
    def __init__(self):
        self.settings = get_settings()
        self.vmcore_parser = VmcoredParser()
        self.log_parser = KernelLogParser()
        self.context_builder = ContextBuilder()
        self.analyzer = CrashAnalyzer()
        self.jira_client = JiraClient()
    
    async def run(self, task_id: str):
        """
        运行完整的分析流程
        
        Args:
            task_id: 任务ID
        """
        logger.info(f"Starting analysis pipeline for task {task_id}")
        
        try:
            # 1. 更新任务状态为处理中
            await state_manager.update_task_status(task_id, AnalysisStatus.PARSING)
            
            # 2. 获取任务信息
            task = await state_manager.get_task(task_id)
            if not task:
                raise ValueError(f"Task {task_id} not found")
            
            # 3. 下载附件
            await state_manager.update_task_status(task_id, AnalysisStatus.DOWNLOADING)
            download_result = await self._download_attachments(task)
            
            if not download_result.get('vmcore'):
                logger.warning(f"Task {task_id}: No vmcore found, skipping")
                await state_manager.update_task_status(task_id, AnalysisStatus.SKIPPED)
                return
            
            # 4. 解析日志（如果存在）
            log_analysis = None
            if download_result.get('kern_log'):
                logger.info(f"Task {task_id}: Parsing kernel log...")
                log_analysis = await self.log_parser.parse(download_result['kern_log'])
            
            # 5. 解析 vmcore - 使用增强版
            await state_manager.update_task_status(task_id, AnalysisStatus.PARSING)
            vmcore_path = download_result['vmcore']
            vmlinux_path = download_result.get('vmlinux')
            
            if not vmlinux_path:
                # 尝试从配置或缓存中获取 vmlinux
                vmlinux_path = await self._find_vmlinux(task, vmcore_path)
            
            logger.info(f"Task {task_id}: Parsing vmcore with enhanced analysis...")
            vmcore_analysis = await self.vmcore_parser.parse(
                vmcore_path, vmlinux_path, log_analysis
            )
            
            # 6. 构建分析上下文
            logger.info(f"Task {task_id}: Building analysis context...")
            extracted_info = {
                'vmcore_analysis': vmcore_analysis,
                'log_analysis': log_analysis
            }
            
            context = self.context_builder.build(
                issue_summary=task.summary,
                issue_description=task.description,
                extracted_info=extracted_info
            )
            
            # 添加上下文元数据
            context['issue_key'] = task.issue_key
            context['task_id'] = task_id
            
            # 7. AI 分析
            await state_manager.update_task_status(task_id, AnalysisStatus.ANALYZING)
            logger.info(f"Task {task_id}: Running AI analysis...")
            analysis_result = await self.analyzer.analyze(context)
            
            # 8. 生成报告
            await state_manager.update_task_status(task_id, AnalysisStatus.REPORTING)
            logger.info(f"Task {task_id}: Generating report...")
            report = await self.analyzer.generate_report(context, analysis_result)
            
            # 9. 更新 Jira
            await state_manager.update_task_status(task_id, AnalysisStatus.UPDATING_JIRA)
            logger.info(f"Task {task_id}: Updating Jira...")
            await self._update_jira(task, analysis_result, report, context)
            
            # 10. 完成任务
            await state_manager.update_task_status(task_id, AnalysisStatus.COMPLETED)
            logger.info(f"Task {task_id}: Analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Task {task_id}: Analysis failed: {e}")
            await state_manager.update_task_status(
                task_id, 
                AnalysisStatus.FAILED,
                error_message=str(e)
            )
            raise
    
    async def _download_attachments(self, task) -> Dict[str, Optional[str]]:
        """
        下载附件到本地
        
        Returns:
            下载后的文件路径字典
        """
        result = {
            'vmcore': None,
            'vmlinux': None,
            'kern_log': None
        }
        
        attachments = task.attachments
        
        # 创建下载目录
        download_dir = Path(self.settings.DOWNLOAD_DIR) / task.task_id
        download_dir.mkdir(parents=True, exist_ok=True)
        
        # 下载 vmcore
        if attachments.get('vmcore'):
            vmcore_url = attachments['vmcore']['url']
            vmcore_path = download_dir / attachments['vmcore']['filename']
            # TODO: 实现实际的下载逻辑
            # await self._download_file(vmcore_url, vmcore_path)
            result['vmcore'] = str(vmcore_path)
        
        # 下载 vmlinux
        if attachments.get('vmlinux'):
            vmlinux_url = attachments['vmlinux']['url']
            vmlinux_path = download_dir / attachments['vmlinux']['filename']
            # await self._download_file(vmlinux_url, vmlinux_path)
            result['vmlinux'] = str(vmlinux_path)
        
        # 下载日志
        if attachments.get('kern_log'):
            log_url = attachments['kern_log']['url']
            log_path = download_dir / attachments['kern_log']['filename']
            # await self._download_file(log_url, log_path)
            result['kern_log'] = str(log_path)
        
        return result
    
    async def _find_vmlinux(self, task, vmcore_path: str) -> Optional[str]:
        """
        尝试找到匹配的 vmlinux 文件
        
        可以通过以下方式：
        1. 从 vmcore 中提取内核版本
        2. 查找本地缓存
        3. 从远程仓库下载
        """
        # TODO: 实现 vmlinux 查找逻辑
        # 临时返回 None，让解析器处理
        return None
    
    async def _update_jira(self, task, analysis_result: Dict, report: str, 
                           context: Dict[str, Any]):
        """
        更新 Jira Issue
        
        包括：
        1. 添加分析评论
        2. 更新自定义字段
        3. 添加标签
        """
        try:
            issue_key = task.issue_key
            
            # 构建评论内容
            comment = self._build_jira_comment(analysis_result, report, context)
            
            # 添加评论
            await self.jira_client.add_comment(issue_key, comment)
            
            # 更新标签
            labels = self._generate_labels(analysis_result)
            await self.jira_client.update_labels(issue_key, labels)
            
            logger.info(f"Updated Jira issue {issue_key}")
            
        except Exception as e:
            logger.error(f"Failed to update Jira: {e}")
            raise
    
    def _build_jira_comment(self, analysis_result: Dict, report: str,
                            context: Dict[str, Any]) -> str:
        """构建 Jira 评论内容"""
        lines = []
        
        lines.append("h2. KE Analyzer - 自动分析结果\n")
        
        # Panic 概述
        panic_overview = context.get('panic_overview', {})
        if panic_overview and 'error' not in panic_overview:
            lines.append("h3. Panic 概述")
            lines.append(f"* 崩溃类型: {panic_overview.get('crash_type', 'Unknown')}")
            if panic_overview.get('kernel_version'):
                lines.append(f"* 内核版本: {panic_overview['kernel_version']}")
            if panic_overview.get('crash_scenario'):
                lines.append(f"* 崩溃场景: {panic_overview['crash_scenario']}")
            if panic_overview.get('suspected_module'):
                lines.append(f"* 可疑模块: {panic_overview['suspected_module']}")
            lines.append("")
        
        # 根因分析
        lines.append("h3. 根因分析")
        lines.append(analysis_result.get('root_cause', '无法确定根因'))
        lines.append("")
        
        # 严重性
        severity = analysis_result.get('severity', 'Unknown')
        lines.append(f"h3. 严重性: {severity}")
        lines.append("")
        
        # 调用栈分析
        stack_analysis = context.get('stack_analysis', {})
        if stack_analysis and 'error' not in stack_analysis:
            lines.append("h3. 调用栈分析")
            if stack_analysis.get('likely_scenarios'):
                lines.append("可能场景:")
                for scenario in stack_analysis['likely_scenarios'][:3]:
                    lines.append(f"* {scenario}")
            lines.append("")
        
        # 寄存器分析
        register_analysis = context.get('register_analysis', {})
        if register_analysis and 'error' not in register_analysis:
            lines.append("h3. 寄存器分析")
            if register_analysis.get('likely_fault_source'):
                lines.append(f"故障源: {register_analysis['likely_fault_source']}")
            if register_analysis.get('root_cause_function'):
                lines.append(f"可疑函数: {register_analysis['root_cause_function']}")
            lines.append("")
        
        # 修复建议
        lines.append("h3. 修复建议")
        lines.append(analysis_result.get('fix_suggestion', '暂无修复建议'))
        lines.append("")
        
        # 详细报告
        lines.append("h3. 详细分析报告")
        lines.append("{code}")
        lines.append(report)
        lines.append("{code}")
        
        return "\n".join(lines)
    
    def _generate_labels(self, analysis_result: Dict) -> list:
        """生成 Jira 标签"""
        labels = ['ke-analyzed']
        
        # 根据严重性添加标签
        severity = analysis_result.get('severity', '').lower()
        if severity:
            labels.append(f'severity-{severity}')
        
        # 根据根因添加标签
        root_cause = analysis_result.get('root_cause', '').lower()
        if 'null' in root_cause:
            labels.append('null-pointer')
        elif 'race' in root_cause or 'lock' in root_cause:
            labels.append('race-condition')
        elif 'memory' in root_cause:
            labels.append('memory-issue')
        elif 'watchdog' in root_cause or 'lockup' in root_cause:
            labels.append('watchdog')
        
        return labels
