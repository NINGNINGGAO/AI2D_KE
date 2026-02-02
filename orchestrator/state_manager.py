"""
状态管理模块
管理分析任务的整个生命周期状态
"""
import json
import asyncio
from enum import Enum
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import logging

from orchestrator.config import get_settings

logger = logging.getLogger(__name__)


class AnalysisStatus(Enum):
    """分析状态枚举"""
    PENDING = "pending"           # 等待处理
    DOWNLOADING = "downloading"   # 下载附件中
    EXTRACTING = "extracting"     # 提取信息中
    ANALYZING = "analyzing"       # AI 分析中
    COMPLETED = "completed"       # 分析完成
    FAILED = "failed"             # 分析失败
    SKIPPED = "skipped"           # 跳过（无附件）


@dataclass
class AnalysisTask:
    """分析任务"""
    task_id: str
    issue_key: str
    issue_id: str
    summary: str
    description: str
    status: AnalysisStatus
    created_at: str
    updated_at: str
    attachments: Dict[str, Any]
    downloaded_files: Dict[str, str]
    extracted_info: Dict[str, Any]
    analysis_result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    jira_comment_id: Optional[str] = None


class StateManager:
    """状态管理器"""
    
    def __init__(self):
        self.settings = get_settings()
        self.work_dir = Path(self.settings.WORK_DIR)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._tasks: Dict[str, AnalysisTask] = {}
        self._lock = asyncio.Lock()
        self._state_file = self.work_dir / "state.json"
        self._load_state()
    
    def _load_state(self):
        """从文件加载状态"""
        if self._state_file.exists():
            try:
                with open(self._state_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for task_id, task_data in data.items():
                        task_data['status'] = AnalysisStatus(task_data['status'])
                        self._tasks[task_id] = AnalysisTask(**task_data)
                logger.info(f"Loaded {len(self._tasks)} tasks from state file")
            except Exception as e:
                logger.error(f"Failed to load state: {e}")
    
    async def _save_state(self):
        """保存状态到文件"""
        async with self._lock:
            try:
                data = {}
                for task_id, task in self._tasks.items():
                    task_dict = asdict(task)
                    task_dict['status'] = task.status.value
                    data[task_id] = task_dict
                
                with open(self._state_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            except Exception as e:
                logger.error(f"Failed to save state: {e}")
    
    async def create_task(
        self,
        task_id: str,
        issue_key: str,
        issue_id: str,
        summary: str,
        description: str,
        attachments: Dict[str, Any]
    ) -> AnalysisTask:
        """创建新任务"""
        now = datetime.now().isoformat()
        task = AnalysisTask(
            task_id=task_id,
            issue_key=issue_key,
            issue_id=issue_id,
            summary=summary,
            description=description,
            status=AnalysisStatus.PENDING,
            created_at=now,
            updated_at=now,
            attachments=attachments,
            downloaded_files={},
            extracted_info={}
        )
        
        async with self._lock:
            self._tasks[task_id] = task
        
        await self._save_state()
        logger.info(f"Created task {task_id} for issue {issue_key}")
        return task
    
    async def get_task(self, task_id: str) -> Optional[AnalysisTask]:
        """获取任务"""
        return self._tasks.get(task_id)
    
    async def update_task_status(
        self,
        task_id: str,
        status: AnalysisStatus,
        error_message: Optional[str] = None
    ):
        """更新任务状态"""
        async with self._lock:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                task.status = status
                task.updated_at = datetime.now().isoformat()
                if error_message:
                    task.error_message = error_message
        
        await self._save_state()
        logger.info(f"Updated task {task_id} status to {status.value}")
    
    async def update_downloaded_files(self, task_id: str, files: Dict[str, str]):
        """更新下载的文件"""
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].downloaded_files = files
                self._tasks[task_id].updated_at = datetime.now().isoformat()
        
        await self._save_state()
    
    async def update_extracted_info(self, task_id: str, info: Dict[str, Any]):
        """更新提取的信息"""
        async with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].extracted_info = info
                self._tasks[task_id].updated_at = datetime.now().isoformat()
        
        await self._save_state()
    
    async def update_analysis_result(
        self,
        task_id: str,
        result: Dict[str, Any],
        jira_comment_id: Optional[str] = None
    ):
        """更新分析结果"""
        async with self._lock:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                task.analysis_result = result
                task.jira_comment_id = jira_comment_id
                task.updated_at = datetime.now().isoformat()
        
        await self._save_state()
    
    async def get_all_tasks(self) -> Dict[str, AnalysisTask]:
        """获取所有任务"""
        return self._tasks.copy()
    
    async def get_tasks_by_status(self, status: AnalysisStatus) -> Dict[str, AnalysisTask]:
        """按状态获取任务"""
        return {
            k: v for k, v in self._tasks.items()
            if v.status == status
        }


# 全局状态管理器实例
state_manager = StateManager()
