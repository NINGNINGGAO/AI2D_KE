"""
Jira Webhook 处理模块
"""
import json
import logging
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from orchestrator.config import get_settings
from orchestrator.state_manager import state_manager, AnalysisStatus

logger = logging.getLogger(__name__)


class JiraWebhookHandler:
    """Jira Webhook 处理器"""
    
    def __init__(self):
        self.settings = get_settings()
    
    async def handle_issue_created(self, payload: Dict[str, Any]) -> Optional[str]:
        """
        处理 Issue 创建事件
        
        Returns:
            task_id: 创建的任务ID，如果没有附件则返回 None
        """
        try:
            issue = payload.get('issue', {})
            issue_key = issue.get('key')
            issue_id = issue.get('id')
            fields = issue.get('fields', {})
            
            summary = fields.get('summary', '')
            description = fields.get('description', '') or ''
            
            # 检查是否是 KE 类型问题
            if not self._is_kernel_crash_issue(summary, description):
                logger.info(f"Issue {issue_key} is not a kernel crash issue, skipping")
                return None
            
            # 检查附件
            attachments = fields.get('attachment', [])
            attachment_info = self._extract_attachment_info(attachments)
            
            # 生成任务ID
            task_id = f"{issue_key}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # 创建任务
            task = await state_manager.create_task(
                task_id=task_id,
                issue_key=issue_key,
                issue_id=issue_id,
                summary=summary,
                description=description,
                attachments=attachment_info
            )
            
            if not attachment_info:
                logger.warning(f"Issue {issue_key} has no attachments, marking as skipped")
                await state_manager.update_task_status(task_id, AnalysisStatus.SKIPPED)
                return None
            
            logger.info(f"Created analysis task {task_id} for issue {issue_key}")
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to handle issue created event: {e}")
            raise
    
    async def handle_issue_updated(self, payload: Dict[str, Any]) -> Optional[str]:
        """
        处理 Issue 更新事件
        如果附件被添加，触发新的分析任务
        """
        try:
            issue = payload.get('issue', {})
            issue_key = issue.get('key')
            issue_id = issue.get('id')
            fields = issue.get('fields', {})
            
            # 获取变更项
            changelog = payload.get('changelog', {})
            items = changelog.get('items', [])
            
            # 检查是否是附件相关变更
            attachment_changed = any(
                item.get('field') == 'Attachment' for item in items
            )
            
            if not attachment_changed:
                return None
            
            summary = fields.get('summary', '')
            description = fields.get('description', '') or ''
            
            # 检查是否是 KE 类型问题
            if not self._is_kernel_crash_issue(summary, description):
                return None
            
            # 检查附件
            attachments = fields.get('attachment', [])
            attachment_info = self._extract_attachment_info(attachments)
            
            if not attachment_info:
                return None
            
            # 生成新的任务ID
            task_id = f"{issue_key}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # 创建任务
            task = await state_manager.create_task(
                task_id=task_id,
                issue_key=issue_key,
                issue_id=issue_id,
                summary=summary,
                description=description,
                attachments=attachment_info
            )
            
            logger.info(f"Created new analysis task {task_id} for updated issue {issue_key}")
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to handle issue updated event: {e}")
            raise
    
    def _is_kernel_crash_issue(self, summary: str, description: str) -> bool:
        """
        判断是否是 Kernel Crash 类型问题
        """
        ke_keywords = [
            'kernel crash', 'ke ', 'ke:', 'ke-', 'panic', 'oops',
            'null pointer', 'watchdog', 'softlockup', 'hardlockup',
            '内核崩溃', '空指针', '看门狗', '死锁'
        ]
        
        text = f"{summary} {description}".lower()
        return any(keyword in text for keyword in ke_keywords)
    
    def _extract_attachment_info(self, attachments: list) -> Dict[str, Any]:
        """
        提取附件信息
        """
        info = {
            'vmcore': None,
            'vmlinux': None,
            'kern_log': None,
            'others': []
        }
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            content_url = attachment.get('content')
            size = attachment.get('size', 0)
            
            attachment_data = {
                'filename': filename,
                'url': content_url,
                'size': size
            }
            
            # 识别文件类型
            if 'vmcore' in filename or filename.endswith('.dump'):
                info['vmcore'] = attachment_data
            elif 'vmlinux' in filename or filename.endswith('.elf'):
                info['vmlinux'] = attachment_data
            elif 'kern' in filename or filename.endswith('.log') or filename.endswith('.txt'):
                info['kern_log'] = attachment_data
            else:
                info['others'].append(attachment_data)
        
        return info


# 全局处理器实例
jira_handler = JiraWebhookHandler()
