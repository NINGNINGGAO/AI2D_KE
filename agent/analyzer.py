"""
AI Crash Analyzer using Qwen-Max
Integrates with Alibaba Cloud's Qwen-Max model for intelligent crash analysis.
"""

import json
import logging
import asyncio
from typing import Dict, Any, List, Optional
import aiohttp

from ..orchestrator.config import get_settings
from .prompt_templates import PromptTemplates

logger = logging.getLogger(__name__)


class CrashAnalyzer:
    """AI-powered kernel crash analyzer using Qwen-Max."""
    
    def __init__(self):
        self.settings = get_settings()
        self.prompt_templates = PromptTemplates()
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120)
            )
        return self.session
    
    async def _call_qwen_api(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None
    ) -> str:
        """Call Qwen-Max API."""
        
        if not self.settings.QWEN_API_KEY:
            raise RuntimeError("QWEN_API_KEY not configured")
        
        session = await self._get_session()
        
        headers = {
            "Authorization": f"Bearer {self.settings.QWEN_API_KEY}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })
        
        messages.append({
            "role": "user",
            "content": prompt
        })
        
        payload = {
            "model": self.settings.QWEN_MODEL,
            "input": {
                "messages": messages
            },
            "parameters": {
                "max_tokens": max_tokens or self.settings.QWEN_MAX_TOKENS,
                "temperature": temperature or self.settings.QWEN_TEMPERATURE,
                "result_format": "message"
            }
        }
        
        try:
            async with session.post(
                self.settings.QWEN_API_URL,
                headers=headers,
                json=payload
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"Qwen API error: {response.status} - {error_text}")
                    raise RuntimeError(f"API error: {response.status}")
                
                data = await response.json()
                
                # Extract response content
                if "output" in data and "choices" in data["output"]:
                    return data["output"]["choices"][0]["message"]["content"]
                elif "output" in data and "text" in data["output"]:
                    return data["output"]["text"]
                else:
                    logger.warning(f"Unexpected API response format: {data}")
                    return json.dumps(data)
                    
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error calling Qwen API: {e}")
            raise
        except Exception as e:
            logger.error(f"Error calling Qwen API: {e}")
            raise
    
    async def analyze(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI analysis on crash context."""
        logger.info(f"Starting AI analysis for {context.get('issue_key')}")
        
        try:
            # Get appropriate prompt based on crash type
            crash_type = context.get('crash_type', 'Unknown')
            user_prompt = self.prompt_templates.get_prompt_for_crash_type(crash_type, context)
            system_prompt = self.prompt_templates.crash_analysis_system_prompt()
            
            # Call AI for analysis
            analysis_response = await self._call_qwen_api(
                prompt=user_prompt,
                system_prompt=system_prompt,
                temperature=0.3
            )
            
            # Parse AI response
            analysis_result = self._parse_analysis_response(analysis_response)
            
            # Perform assembly-level analysis if available
            asm_analysis = context.get('assembly_analysis', {})
            if asm_analysis and asm_analysis.get('performed'):
                logger.info("Performing assembly-level deep analysis...")
                asm_prompt = self.prompt_templates.assembly_level_analysis_prompt(context)
                
                asm_response = await self._call_qwen_api(
                    prompt=asm_prompt,
                    system_prompt=system_prompt,
                    temperature=0.2,
                    max_tokens=4096
                )
                
                analysis_result['assembly_analysis'] = asm_response
                
                # If memory corruption detected, get specialized analysis
                if asm_analysis.get('anomaly_count', 0) > 0:
                    mem_prompt = self.prompt_templates.memory_corruption_analysis_prompt(context)
                    mem_response = await self._call_qwen_api(
                        prompt=mem_prompt,
                        system_prompt=system_prompt,
                        temperature=0.2,
                        max_tokens=2048
                    )
                    analysis_result['memory_corruption_analysis'] = mem_response
            
            # Get fix suggestions
            fix_prompt = self.prompt_templates.fix_suggestion_prompt(
                context, analysis_result.get('analysis', '')
            )
            
            fix_response = await self._call_qwen_api(
                prompt=fix_prompt,
                system_prompt=system_prompt,
                temperature=0.2,
                max_tokens=2048
            )
            
            analysis_result['detailed_fix_suggestion'] = fix_response
            
            # Try to classify the crash
            classification = await self._classify_crash(context)
            analysis_result['classification'] = classification
            
            logger.info(f"AI analysis completed for {context.get('issue_key')}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return {
                "analysis": f"AI analysis failed: {str(e)}",
                "root_cause": "Unable to determine due to analysis error",
                "fix_suggestion": "Manual analysis required",
                "severity": "Unknown",
                "confidence": "Low",
                "error": str(e)
            }
    
    def _parse_analysis_response(self, response: str) -> Dict[str, Any]:
        """Parse AI analysis response."""
        result = {
            "analysis": "",
            "root_cause": "",
            "affected_code_path": "",
            "similar_issues": [],
            "fix_suggestion": "",
            "severity": "Medium",
            "confidence": "Medium"
        }
        
        try:
            # Try to parse as JSON
            if response.strip().startswith('{'):
                data = json.loads(response)
                result.update(data)
            else:
                # Extract sections from text response
                result["analysis"] = response
                
                # Try to extract severity
                if "critical" in response.lower():
                    result["severity"] = "Critical"
                elif "high" in response.lower():
                    result["severity"] = "High"
                elif "low" in response.lower():
                    result["severity"] = "Low"
                
                # Try to extract root cause
                if "root cause" in response.lower():
                    lines = response.split('\n')
                    for i, line in enumerate(lines):
                        if "root cause" in line.lower():
                            # Get next few lines
                            result["root_cause"] = '\n'.join(lines[i:i+3])
                            break
        except json.JSONDecodeError:
            # Use raw response as analysis
            result["analysis"] = response
        except Exception as e:
            logger.error(f"Error parsing analysis response: {e}")
            result["analysis"] = response
        
        return result
    
    async def _classify_crash(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Classify crash type using AI."""
        try:
            prompt = self.prompt_templates.crash_classification_prompt(context)
            
            response = await self._call_qwen_api(
                prompt=prompt,
                temperature=0.1,
                max_tokens=500
            )
            
            return {
                "classification": response.strip(),
                "original_type": context.get('crash_type', 'Unknown')
            }
        except Exception as e:
            logger.error(f"Crash classification failed: {e}")
            return {
                "classification": context.get('crash_type', 'Unknown'),
                "error": str(e)
            }
    
    async def find_similar_issues(
        self,
        context: Dict[str, Any],
        historical_issues: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Find similar historical issues."""
        if not historical_issues:
            return []
        
        try:
            prompt = self.prompt_templates.similar_issue_detection_prompt(
                context, historical_issues
            )
            
            response = await self._call_qwen_api(
                prompt=prompt,
                temperature=0.2,
                max_tokens=1024
            )
            
            # Parse similar issues from response
            similar = []
            for issue in historical_issues:
                issue_key = issue.get('key', '')
                if issue_key in response:
                    # Estimate confidence based on mention frequency
                    confidence = min(90, 50 + response.count(issue_key) * 10)
                    similar.append({
                        "issue_key": issue_key,
                        "confidence": confidence,
                        "reason": "Mentioned in similarity analysis"
                    })
            
            # Sort by confidence
            similar.sort(key=lambda x: x['confidence'], reverse=True)
            return similar[:5]  # Return top 5
            
        except Exception as e:
            logger.error(f"Similar issue detection failed: {e}")
            return []
    
    async def generate_report(
        self,
        context: Dict[str, Any],
        analysis_result: Dict[str, Any]
    ) -> str:
        """Generate human-readable analysis report."""
        try:
            prompt = self.prompt_templates.report_generation_prompt(
                analysis_result, context
            )
            
            report = await self._call_qwen_api(
                prompt=prompt,
                temperature=0.4,
                max_tokens=3000
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            # Generate basic report
            return self._generate_basic_report(context, analysis_result)
    
    def _generate_basic_report(
        self,
        context: Dict[str, Any],
        analysis_result: Dict[str, Any]
    ) -> str:
        """Generate basic report without AI."""
        return f"""# Kernel Crash Analysis Report

## Issue Information
- **Issue Key:** {context.get('issue_key', 'N/A')}
- **Crash Type:** {context.get('crash_type', 'Unknown')}
- **Location:** {context.get('crash_location', 'Unknown')}

## AI Analysis
{analysis_result.get('analysis', 'No analysis available')}

## Root Cause
{analysis_result.get('root_cause', 'Unable to determine')}

## Fix Suggestion
{analysis_result.get('fix_suggestion', 'No suggestions available')}

## Technical Details
- **Process:** {context.get('process_name', 'Unknown')} (PID: {context.get('pid', 'N/A')})
- **CPU:** {context.get('cpu', 'N/A')}
- **Fault Address:** {context.get('fault_address', 'Unknown')}

### Stack Trace
```
{chr(10).join(context.get('stack_trace', ['N/A']))}
```

### Affected Modules
{', '.join(context.get('affected_modules', ['Unknown']))}

---
*Generated by KE Analyzer*
"""
    
    async def close(self):
        """Close the analyzer and cleanup resources."""
        if self.session and not self.session.closed:
            await self.session.close()
