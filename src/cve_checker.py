"""
cve_checker.py

Проверка уязвимостей через Vulners API и других источников.
"""

import logging
import aiohttp
import asyncio
from typing import List, Dict, Optional
from models import CVEVulnerability, SeverityLevel


logger = logging.getLogger(__name__)


class CVEChecker:
    """Проверка CVE уязвимостей"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Инициализация CVE проверяльника
        
        Args:
            api_key: API ключ для Vulners
        """
        self.api_key = api_key
        self.vulners_url = "https://api.vulners.com/v3/search/lucene/"
        self.enabled = bool(api_key)
    
    async def check_service(self, service: str, version: Optional[str] = None) -> List[CVEVulnerability]:
        """
        Проверить сервис на уязвимости
        
        Args:
            service: Название сервиса
            version: Версия сервиса
            
        Returns:
            Список найденных уязвимостей
        """
        if not self.enabled:
            logger.debug("CVE checking disabled")
            return []
        
        try:
            query = f"{service}"
            if version:
                query += f" {version}"
            
            vulns = await self._search_vulners(query)
            return vulns
        
        except Exception as e:
            logger.error(f"Error checking CVE for {service}: {e}")
            return []
    
    async def _search_vulners(self, query: str) -> List[CVEVulnerability]:
        """Поиск в Vulners API"""
        if not self.api_key:
            return []
        
        try:
            params = {
                "query": query,
                "apiKey": self.api_key,
                "limit": 10,
                "type": "cve"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.vulners_url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        vulns = []
                        for search_result in data.get('search', [])[:5]:
                            vuln = CVEVulnerability(
                                cve_id=search_result.get('id', ''),
                                service=query,
                                port=0,
                                severity=self._parse_severity(search_result.get('score', 0)),
                                description=search_result.get('title', ''),
                                cvss_score=search_result.get('score'),
                                published_date=search_result.get('published'),
                            )
                            vulns.append(vuln)
                        
                        return vulns
        
        except Exception as e:
            logger.debug(f"Vulners API error: {e}")
        
        return []
    
    @staticmethod
    def _parse_severity(score: float) -> SeverityLevel:
        """Определить уровень критичности по CVSS"""
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def check_known_vulnerabilities(self, service: str, banner: str) -> List[Dict]:
        """
        Проверить известные уязвимости для сервиса
        Без API - основано на паттернах
        
        Args:
            service: Название сервиса
            banner: Баннер сервиса
            
        Returns:
            Список известных уязвимостей
        """
        known_vulns = {
            'Apache': [
                {'version': '2.0', 'cve': 'CVE-2002-0082', 'desc': 'Buffer overflow'},
                {'version': '2.2', 'cve': 'CVE-2009-1195', 'desc': 'Remote DoS'},
            ],
            'OpenSSH': [
                {'version': '3.x', 'cve': 'CVE-2003-0001', 'desc': 'Information disclosure'},
                {'version': '4.x', 'cve': 'CVE-2008-5161', 'desc': 'Privilege escalation'},
            ],
            'MySQL': [
                {'version': '5.0', 'cve': 'CVE-2006-5436', 'desc': 'Remote DoS'},
            ],
            'PostgreSQL': [
                {'version': '8.0', 'cve': 'CVE-2005-3656', 'desc': 'Integer overflow'},
            ],
        }
        
        vulns = []
        
        if service in known_vulns:
            for vuln_info in known_vulns[service]:
                if vuln_info.get('version') in banner:
                    vulns.append(vuln_info)
        
        return vulns
