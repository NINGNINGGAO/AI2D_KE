"""
Memory MCP (Model Context Protocol) Client
Integrates with Memory MCP for context persistence and retrieval.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import aiohttp

from ..orchestrator.config import get_settings

logger = logging.getLogger(__name__)


class ContextBlock:
    """Represents a context block for Memory MCP."""
    
    def __init__(
        self,
        block_id: str,
        block_type: str,
        content: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.block_id = block_id
        self.block_type = block_type
        self.content = content
        self.metadata = metadata or {}
        self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "block_id": self.block_id,
            "block_type": self.block_type,
            "content": self.content,
            "metadata": self.metadata,
            "created_at": self.created_at
        }


class MemoryMCPClient:
    """Client for Memory MCP integration."""
    
    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.MEMORY_MCP_URL
        self.api_key = self.settings.MEMORY_MCP_API_KEY
        self.session: Optional[aiohttp.ClientSession] = None
        self.enabled = bool(self.base_url)
        
        if not self.enabled:
            logger.warning("Memory MCP not configured, operations will be no-ops")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=60)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    async def register_context(
        self,
        issue_key: str,
        context: Dict[str, Any]
    ) -> bool:
        """Register crash analysis context as a memory block."""
        if not self.enabled:
            return True  # Silently succeed if not configured
        
        try:
            # Create context block
            block = ContextBlock(
                block_id=f"ke-analysis-{issue_key}",
                block_type="kernel_crash_analysis",
                content={
                    "issue_key": issue_key,
                    "crash_type": context.get("crash_type"),
                    "crash_location": context.get("crash_location"),
                    "crash_signature": context.get("crash_signature"),
                    "stack_trace": context.get("stack_trace", []),
                    "affected_modules": context.get("affected_modules", []),
                    "fault_address": context.get("fault_address"),
                    "process_info": {
                        "name": context.get("process_name"),
                        "pid": context.get("pid"),
                        "cpu": context.get("cpu")
                    }
                },
                metadata={
                    "source": "ke-analyzer",
                    "timestamp": datetime.now().isoformat(),
                    "version": "1.0"
                }
            )
            
            # Store in Memory MCP
            success = await self._store_block(block)
            
            if success:
                logger.info(f"Registered context block for {issue_key}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to register context: {e}")
            return False
    
    async def _store_block(self, block: ContextBlock) -> bool:
        """Store a context block in Memory MCP."""
        if not self.base_url:
            return False
        
        url = f"{self.base_url}/api/v1/blocks"
        
        try:
            session = await self._get_session()
            async with session.post(
                url,
                headers=self._get_headers(),
                json=block.to_dict()
            ) as response:
                if response.status in [200, 201]:
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to store block: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error storing block: {e}")
            return False
    
    async def retrieve_similar(
        self,
        crash_signature: str,
        crash_type: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Retrieve similar crash contexts from memory."""
        if not self.enabled:
            return []
        
        try:
            url = f"{self.base_url}/api/v1/blocks/search"
            
            payload = {
                "query": {
                    "block_type": "kernel_crash_analysis",
                    "content": {
                        "crash_signature": crash_signature,
                        "crash_type": crash_type
                    }
                },
                "limit": limit
            }
            
            session = await self._get_session()
            async with session.post(
                url,
                headers=self._get_headers(),
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("blocks", [])
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving similar contexts: {e}")
            return []
    
    async def get_analysis_history(
        self,
        issue_key: str
    ) -> List[Dict[str, Any]]:
        """Get analysis history for an issue."""
        if not self.enabled:
            return []
        
        try:
            url = f"{self.base_url}/api/v1/blocks"
            
            params = {
                "block_type": "kernel_crash_analysis",
                "content.issue_key": issue_key
            }
            
            session = await self._get_session()
            async with session.get(
                url,
                headers=self._get_headers(),
                params=params
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("blocks", [])
                return []
                
        except Exception as e:
            logger.error(f"Error getting analysis history: {e}")
            return []
    
    async def store_analysis_result(
        self,
        issue_key: str,
        analysis_result: Dict[str, Any]
    ) -> bool:
        """Store AI analysis result."""
        if not self.enabled:
            return True
        
        try:
            block = ContextBlock(
                block_id=f"ke-result-{issue_key}",
                block_type="kernel_crash_analysis_result",
                content={
                    "issue_key": issue_key,
                    "analysis": analysis_result.get("analysis"),
                    "root_cause": analysis_result.get("root_cause"),
                    "fix_suggestion": analysis_result.get("fix_suggestion"),
                    "severity": analysis_result.get("severity"),
                    "confidence": analysis_result.get("confidence"),
                    "classification": analysis_result.get("classification")
                },
                metadata={
                    "source": "ke-analyzer",
                    "timestamp": datetime.now().isoformat(),
                    "type": "ai_analysis"
                }
            )
            
            return await self._store_block(block)
            
        except Exception as e:
            logger.error(f"Failed to store analysis result: {e}")
            return False
    
    async def find_related_issues(
        self,
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find related issues based on context similarity."""
        if not self.enabled:
            return []
        
        # Search by crash signature
        similar = await self.retrieve_similar(
            context.get("crash_signature", ""),
            context.get("crash_type", ""),
            limit=10
        )
        
        # Filter and rank results
        related = []
        for block in similar:
            content = block.get("content", {})
            score = self._calculate_similarity(context, content)
            
            if score > 0.5:  # Threshold
                related.append({
                    "issue_key": content.get("issue_key"),
                    "similarity_score": score,
                    "crash_type": content.get("crash_type"),
                    "crash_location": content.get("crash_location")
                })
        
        # Sort by similarity
        related.sort(key=lambda x: x["similarity_score"], reverse=True)
        return related[:5]
    
    def _calculate_similarity(
        self,
        context1: Dict[str, Any],
        context2: Dict[str, Any]
    ) -> float:
        """Calculate similarity score between two contexts."""
        score = 0.0
        
        # Same crash type
        if context1.get("crash_type") == context2.get("crash_type"):
            score += 0.3
        
        # Same crash location
        if context1.get("crash_location") == context2.get("crash_location"):
            score += 0.4
        
        # Similar stack trace
        stack1 = context1.get("stack_trace", [])
        stack2 = context2.get("stack_trace", [])
        if stack1 and stack2:
            common_frames = len(set(stack1) & set(stack2))
            score += min(0.3, common_frames * 0.1)
        
        # Same affected modules
        mods1 = set(context1.get("affected_modules", []))
        mods2 = set(context2.get("affected_modules", []))
        if mods1 and mods2:
            common_mods = len(mods1 & mods2)
            score += min(0.2, common_mods * 0.1)
        
        return min(1.0, score)
    
    async def cleanup_old_blocks(self, days: int = 90) -> bool:
        """Clean up old context blocks."""
        if not self.enabled:
            return True
        
        try:
            url = f"{self.base_url}/api/v1/blocks/cleanup"
            
            payload = {
                "block_types": ["kernel_crash_analysis", "kernel_crash_analysis_result"],
                "older_than_days": days
            }
            
            session = await self._get_session()
            async with session.post(
                url,
                headers=self._get_headers(),
                json=payload
            ) as response:
                if response.status == 200:
                    logger.info(f"Cleaned up old blocks older than {days} days")
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Error cleaning up blocks: {e}")
            return False
    
    async def close(self):
        """Close the client session."""
        if self.session and not self.session.closed:
            await self.session.close()
