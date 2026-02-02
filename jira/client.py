"""
Jira API Client for KE Analyzer
Handles Jira REST API interactions for issue management.
"""

import asyncio
import logging
import os
from typing import Dict, List, Optional, Any, BinaryIO
from pathlib import Path
import aiohttp
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class JiraIssueData:
    """Structured Jira issue data."""
    key: str
    summary: str
    description: str = ""
    issue_type: str = ""
    status: str = ""
    priority: str = ""
    assignee: Optional[str] = None
    reporter: Optional[str] = None
    labels: List[str] = None
    components: List[str] = None
    
    def __post_init__(self):
        if self.labels is None:
            self.labels = []
        if self.components is None:
            self.components = []


@dataclass
class JiraAttachmentInfo:
    """Jira attachment information."""
    id: str
    filename: str
    content_type: str
    size: int
    url: str


class JiraClient:
    """Client for Jira REST API operations."""
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        api_token: Optional[str] = None
    ):
        from ..orchestrator.config import get_settings
        settings = get_settings()
        
        self.base_url = base_url or settings.JIRA_URL
        self.username = username or settings.JIRA_USERNAME
        self.api_token = api_token or settings.JIRA_API_TOKEN
        
        if not self.base_url:
            logger.warning("Jira URL not configured")
        if not self.username or not self.api_token:
            logger.warning("Jira credentials not configured")
        
        self.session: Optional[aiohttp.ClientSession] = None
        self._setup_auth()
    
    def _setup_auth(self):
        """Setup authentication headers."""
        import base64
        
        if self.username and self.api_token:
            credentials = base64.b64encode(
                f"{self.username}:{self.api_token}".encode()
            ).decode()
            self.headers = {
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        else:
            self.headers = {}
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=300)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    def _get_api_url(self, endpoint: str) -> str:
        """Build full API URL."""
        base = self.base_url.rstrip('/')
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        return f"{base}/rest/api/2{endpoint}"
    
    async def get_issue(self, issue_key: str) -> Optional[JiraIssueData]:
        """Get issue details by key."""
        if not self.base_url:
            logger.error("Jira URL not configured")
            return None
        
        url = self._get_api_url(f"/issue/{issue_key}")
        
        try:
            session = await self._get_session()
            async with session.get(url, headers=self.headers) as response:
                if response.status == 404:
                    logger.error(f"Issue {issue_key} not found")
                    return None
                
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"Failed to get issue: {response.status} - {error_text}")
                    return None
                
                data = await response.json()
                return self._parse_issue_data(data)
                
        except Exception as e:
            logger.error(f"Error getting issue {issue_key}: {e}")
            return None
    
    def _parse_issue_data(self, data: Dict) -> JiraIssueData:
        """Parse Jira API response into JiraIssueData."""
        fields = data.get("fields", {})
        
        return JiraIssueData(
            key=data.get("key", ""),
            summary=fields.get("summary", ""),
            description=self._extract_description(fields.get("description")),
            issue_type=fields.get("issuetype", {}).get("name", ""),
            status=fields.get("status", {}).get("name", ""),
            priority=fields.get("priority", {}).get("name", ""),
            assignee=fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
            reporter=fields.get("reporter", {}).get("displayName"),
            labels=fields.get("labels", []),
            components=[c.get("name", "") for c in fields.get("components", [])]
        )
    
    def _extract_description(self, description: Any) -> str:
        """Extract text description from Jira format."""
        if not description:
            return ""
        
        if isinstance(description, str):
            return description
        
        # Handle Atlassian Document Format
        if isinstance(description, dict):
            return self._extract_text_from_adf(description)
        
        return str(description)
    
    def _extract_text_from_adf(self, node: Dict) -> str:
        """Recursively extract text from ADF nodes."""
        texts = []
        
        if "text" in node:
            texts.append(node["text"])
        
        if "content" in node and isinstance(node["content"], list):
            for child in node["content"]:
                texts.append(self._extract_text_from_adf(child))
        
        return " ".join(texts)
    
    async def update_issue(
        self,
        issue_key: str,
        fields: Dict[str, Any]
    ) -> bool:
        """Update issue fields."""
        if not self.base_url:
            return False
        
        url = self._get_api_url(f"/issue/{issue_key}")
        
        payload = {"fields": fields}
        
        try:
            session = await self._get_session()
            async with session.put(url, headers=self.headers, json=payload) as response:
                if response.status == 204:
                    logger.info(f"Updated issue {issue_key}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to update issue: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error updating issue {issue_key}: {e}")
            return False
    
    async def add_comment(
        self,
        issue_key: str,
        comment: str,
        visibility: Optional[Dict] = None
    ) -> bool:
        """Add comment to issue."""
        if not self.base_url:
            return False
        
        url = self._get_api_url(f"/issue/{issue_key}/comment")
        
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": comment
                            }
                        ]
                    }
                ]
            }
        }
        
        # If comment is too long for ADF, use plain text
        if len(comment) > 10000:
            payload = {"body": comment[:10000] + "\n\n[Content truncated...]"}
        
        if visibility:
            payload["visibility"] = visibility
        
        try:
            session = await self._get_session()
            async with session.post(url, headers=self.headers, json=payload) as response:
                if response.status in [200, 201]:
                    logger.info(f"Added comment to {issue_key}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to add comment: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error adding comment to {issue_key}: {e}")
            return False
    
    async def add_label(self, issue_key: str, label: str) -> bool:
        """Add a label to an issue."""
        # First get current labels
        issue = await self.get_issue(issue_key)
        if not issue:
            return False
        
        if label in issue.labels:
            return True  # Already has label
        
        new_labels = issue.labels + [label]
        
        return await self.update_issue(issue_key, {"labels": new_labels})
    
    async def get_attachments(self, issue_key: str) -> List[JiraAttachmentInfo]:
        """Get list of attachments for an issue."""
        if not self.base_url:
            return []
        
        issue = await self.get_issue(issue_key)
        if not issue:
            return []
        
        # Get full issue data with attachments
        url = self._get_api_url(f"/issue/{issue_key}?fields=attachment")
        
        try:
            session = await self._get_session()
            async with session.get(url, headers=self.headers) as response:
                if response.status != 200:
                    return []
                
                data = await response.json()
                attachments = data.get("fields", {}).get("attachment", [])
                
                result = []
                for att in attachments:
                    result.append(JiraAttachmentInfo(
                        id=att.get("id", ""),
                        filename=att.get("filename", ""),
                        content_type=att.get("mimeType", ""),
                        size=att.get("size", 0),
                        url=att.get("content", "")
                    ))
                
                return result
                
        except Exception as e:
            logger.error(f"Error getting attachments for {issue_key}: {e}")
            return []
    
    async def download_attachment(
        self,
        attachment: JiraAttachmentInfo,
        download_dir: str
    ) -> Optional[str]:
        """Download attachment to local directory."""
        if not attachment.url:
            logger.error(f"No URL for attachment {attachment.filename}")
            return None
        
        # Ensure download directory exists
        os.makedirs(download_dir, exist_ok=True)
        
        # Build local file path
        local_path = os.path.join(download_dir, attachment.filename)
        
        # Handle duplicate filenames
        counter = 1
        original_path = local_path
        while os.path.exists(local_path):
            name, ext = os.path.splitext(original_path)
            local_path = f"{name}_{counter}{ext}"
            counter += 1
        
        try:
            session = await self._get_session()
            async with session.get(attachment.url, headers=self.headers) as response:
                if response.status != 200:
                    logger.error(f"Failed to download attachment: {response.status}")
                    return None
                
                with open(local_path, 'wb') as f:
                    while True:
                        chunk = await response.content.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                
                logger.info(f"Downloaded {attachment.filename} to {local_path}")
                return local_path
                
        except Exception as e:
            logger.error(f"Error downloading attachment: {e}")
            return None
    
    async def search_issues(
        self,
        jql: str,
        max_results: int = 50,
        fields: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Search issues using JQL."""
        if not self.base_url:
            return []
        
        url = self._get_api_url("/search")
        
        payload = {
            "jql": jql,
            "maxResults": max_results,
            "fields": fields or ["summary", "status", "priority", "labels"]
        }
        
        try:
            session = await self._get_session()
            async with session.post(url, headers=self.headers, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"Search failed: {response.status} - {error_text}")
                    return []
                
                data = await response.json()
                return data.get("issues", [])
                
        except Exception as e:
            logger.error(f"Error searching issues: {e}")
            return []
    
    async def transition_issue(
        self,
        issue_key: str,
        transition_id: str,
        comment: Optional[str] = None
    ) -> bool:
        """Transition issue to new status."""
        if not self.base_url:
            return False
        
        url = self._get_api_url(f"/issue/{issue_key}/transitions")
        
        payload = {
            "transition": {"id": transition_id}
        }
        
        if comment:
            payload["update"] = {
                "comment": [{"add": {"body": comment}}]
            }
        
        try:
            session = await self._get_session()
            async with session.post(url, headers=self.headers, json=payload) as response:
                if response.status == 204:
                    logger.info(f"Transitioned issue {issue_key}")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Transition failed: {response.status} - {error_text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error transitioning issue {issue_key}: {e}")
            return False
    
    async def get_transitions(self, issue_key: str) -> List[Dict[str, Any]]:
        """Get available transitions for an issue."""
        if not self.base_url:
            return []
        
        url = self._get_api_url(f"/issue/{issue_key}/transitions")
        
        try:
            session = await self._get_session()
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("transitions", [])
                return []
        except Exception as e:
            logger.error(f"Error getting transitions: {e}")
            return []
    
    async def close(self):
        """Close the client session."""
        if self.session and not self.session.closed:
            await self.session.close()
