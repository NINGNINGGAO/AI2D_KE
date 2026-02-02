"""
FastAPI 服务入口
"""
import os
import sys
import logging
from contextlib import asynccontextmanager

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional

from orchestrator.config import get_settings, Settings
from orchestrator.state_manager import state_manager, AnalysisStatus
from orchestrator.jira_handler import jira_handler

# 配置日志
logging.basicConfig(
    level=getattr(logging, get_settings().LOG_LEVEL),
    format=get_settings().LOG_FORMAT
)
logger = logging.getLogger(__name__)


# 请求模型
class JiraWebhookPayload(BaseModel):
    """Jira Webhook 请求体"""
    webhookEvent: str
    issue: Optional[Dict[str, Any]] = None
    changelog: Optional[Dict[str, Any]] = None


class AnalysisResponse(BaseModel):
    """分析响应"""
    task_id: str
    status: str
    message: str


# 生命周期管理
@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    logger.info("Starting KE Analyzer...")
    yield
    logger.info("Shutting down KE Analyzer...")


# 创建 FastAPI 应用
app = FastAPI(
    title="KE Analyzer",
    description="Android Kernel Crash 自动预分析系统",
    version=get_settings().APP_VERSION,
    lifespan=lifespan
)


@app.get("/")
async def root():
    """根路径"""
    return {
        "name": "KE Analyzer",
        "version": get_settings().APP_VERSION,
        "status": "running"
    }


@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy"}


@app.post("/webhook/jira", response_model=AnalysisResponse)
async def jira_webhook(payload: JiraWebhookPayload, background_tasks: BackgroundTasks):
    """
    接收 Jira Webhook
    
    支持的 webhook 事件：
    - jira:issue_created: 创建新问题时触发分析
    - jira:issue_updated: 更新问题时，如果添加了附件则触发分析
    """
    try:
        event_type = payload.webhookEvent
        task_id = None
        
        if event_type == "jira:issue_created":
            task_id = await jira_handler.handle_issue_created(payload.dict())
        elif event_type == "jira:issue_updated":
            task_id = await jira_handler.handle_issue_updated(payload.dict())
        else:
            logger.info(f"Ignoring webhook event: {event_type}")
            return AnalysisResponse(
                task_id="",
                status="ignored",
                message=f"Event type {event_type} not handled"
            )
        
        if task_id:
            # 启动后台分析任务
            background_tasks.add_task(run_analysis_pipeline, task_id)
            return AnalysisResponse(
                task_id=task_id,
                status="accepted",
                message="Analysis task created and queued"
            )
        else:
            return AnalysisResponse(
                task_id="",
                status="skipped",
                message="No analysis needed for this issue"
            )
            
    except Exception as e:
        logger.error(f"Error handling Jira webhook: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/tasks/{task_id}")
async def get_task_status(task_id: str):
    """获取任务状态"""
    task = await state_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return {
        "task_id": task.task_id,
        "issue_key": task.issue_key,
        "status": task.status.value,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
        "error_message": task.error_message
    }


@app.get("/tasks")
async def list_tasks(status: Optional[str] = None):
    """列出所有任务"""
    if status:
        try:
            status_enum = AnalysisStatus(status)
            tasks = await state_manager.get_tasks_by_status(status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    else:
        tasks = await state_manager.get_all_tasks()
    
    return {
        "tasks": [
            {
                "task_id": t.task_id,
                "issue_key": t.issue_key,
                "status": t.status.value,
                "created_at": t.created_at,
                "updated_at": t.updated_at
            }
            for t in tasks.values()
        ]
    }


async def run_analysis_pipeline(task_id: str):
    """
    运行完整的分析流程
    
    这是一个后台任务，执行以下步骤：
    1. 下载附件
    2. 提取关键信息
    3. AI 分析
    4. 更新 Jira
    """
    from orchestrator.pipeline import AnalysisPipeline
    
    pipeline = AnalysisPipeline()
    await pipeline.run(task_id)


if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "orchestrator.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
