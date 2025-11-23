"""
URL Content Inspector Service.

Fetches and analyzes URL content to extract:
- HTTP metadata (status, headers, redirects)
- HTML content (title, meta tags, scripts, forms, iframes)
- External domain references
- Security indicators
"""
import re
import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class UrlInspectorService:
    """
    Async service for fetching and parsing URL content.
    Extracts comprehensive information for frontend tabs.
    """
    
    def __init__(self):
        self.timeout = settings.URL_FETCH_TIMEOUT
        self.max_size = settings.URL_FETCH_MAX_SIZE
        self.follow_redirects = settings.URL_FOLLOW_REDIRECTS
        self.max_redirects = settings.URL_MAX_REDIRECTS
    
    async def inspect_url(self, url: str) -> Dict:
        """
        Fetch and inspect a URL to extract content and metadata.
        
        Returns a dictionary with:
        - http_status, content_type, headers
        - title, meta_description, canonical_url
        - script_count, form_count, iframe_count
        - form_details, external_domains
        - redirect_chain, final_url
        """
        result = {
            "http_status": None,
            "content_type": None,
            "title": None,
            "meta_description": None,
            "canonical_url": None,
            "script_count": 0,
            "form_count": 0,
            "iframe_count": 0,
            "form_details": [],
            "external_domains": [],
            "headers": {},
            "redirect_chain": [],
            "final_url": url,
            "fetch_time_ms": None,
            "error": None
        }
        
        try:
            # Fetch URL with timeout and size limits
            async with httpx.AsyncClient(
                follow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects,
                timeout=self.timeout
            ) as client:
                import time
                start_time = time.time()
                
                response = await client.get(url)
                
                fetch_time = int((time.time() - start_time) * 1000)
                result["fetch_time_ms"] = fetch_time
                
                # Extract basic HTTP info
                result["http_status"] = response.status_code
                result["content_type"] = response.headers.get("content-type", "").split(";")[0]
                result["headers"] = dict(response.headers)
                result["final_url"] = str(response.url)
                
                # Build redirect chain
                if hasattr(response, "history") and response.history:
                    result["redirect_chain"] = [str(r.url) for r in response.history]
                    result["redirect_chain"].append(str(response.url))
                
                # Only parse HTML content
                if "html" in result["content_type"].lower():
                    # Limit content size
                    content = response.text[:self.max_size]
                    
                    # Parse HTML
                    soup = BeautifulSoup(content, "html.parser")
                    
                    # Extract title
                    title_tag = soup.find("title")
                    if title_tag:
                        result["title"] = title_tag.get_text(strip=True)
                    
                    # Extract meta description
                    meta_desc = soup.find("meta", attrs={"name": "description"})
                    if meta_desc and meta_desc.get("content"):
                        result["meta_description"] = meta_desc["content"]
                    
                    # Extract canonical URL
                    canonical = soup.find("link", attrs={"rel": "canonical"})
                    if canonical and canonical.get("href"):
                        result["canonical_url"] = canonical["href"]
                    
                    # Count scripts
                    result["script_count"] = len(soup.find_all("script"))
                    
                    # Count and analyze forms
                    forms = soup.find_all("form")
                    result["form_count"] = len(forms)
                    result["form_details"] = self._analyze_forms(forms, url)
                    
                    # Count iframes
                    result["iframe_count"] = len(soup.find_all("iframe"))
                    
                    # Extract external domains
                    result["external_domains"] = self._extract_external_domains(soup, url)
        
        except httpx.TimeoutException:
            result["error"] = "Request timeout"
            logger.warning(f"Timeout fetching URL: {url}")
        except httpx.HTTPError as e:
            result["error"] = f"HTTP error: {str(e)}"
            logger.warning(f"HTTP error fetching URL {url}: {e}")
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.error(f"Error inspecting URL {url}: {e}", exc_info=True)
        
        return result
    
    def _analyze_forms(self, forms: List, base_url: str) -> List[Dict]:
        """Analyze forms on the page."""
        form_details = []
        base_domain = urlparse(base_url).netloc
        
        for form in forms[:10]:  # Limit to first 10 forms
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            
            # Resolve relative URLs
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url
            
            # Check if external
            action_domain = urlparse(action_url).netloc
            is_external = action_domain != base_domain if action_domain else False
            
            form_details.append({
                "action": action_url,
                "method": method,
                "is_external": is_external
            })
        
        return form_details
    
    def _extract_external_domains(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract unique external domains referenced in the page."""
        base_domain = urlparse(base_url).netloc
        external_domains = set()
        
        # Extract from various tags
        tags_and_attrs = [
            ("script", "src"),
            ("img", "src"),
            ("link", "href"),
            ("iframe", "src"),
            ("a", "href")
        ]
        
        for tag_name, attr in tags_and_attrs:
            for tag in soup.find_all(tag_name):
                url = tag.get(attr)
                if url:
                    # Resolve relative URLs
                    if url.startswith(('http://', 'https://', '//')):
                        if url.startswith('//'):
                            url = 'https:' + url
                        
                        domain = urlparse(url).netloc
                        if domain and domain != base_domain:
                            external_domains.add(domain)
        
        return sorted(list(external_domains))


# Global instance
url_inspector = UrlInspectorService()
