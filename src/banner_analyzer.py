"""


Анализ баннеров сервисов для определения типа и версии сервиса.
"""

import logging
import re
from typing import Optional, Dict, Tuple


logger = logging.getLogger(__name__)


class BannerAnalyzer:
    """Анализатор баннеров для определения сервисов"""
    
    # Паттерны для определения сервисов
    PATTERNS = {
        r"Apache(?:/(\d+\.\d+\.\d+))?": ("Apache", "web_server"),
        r"nginx(?:/(\d+\.\d+\.\d+))?": ("Nginx", "web_server"),
        r"Microsoft-IIS/(\d+\.\d+)": ("IIS", "web_server"),
        r"OpenSSH[_\-]?([\d\.p]+)?": ("OpenSSH", "ssh"),
        r"OpenSSL": ("OpenSSL", "crypto"),
        r"MySQL[_\-]Server[_\-]?([\d\.]+)?": ("MySQL", "database"),
        r"PostgreSQL[_\-]?([\d\.]+)?": ("PostgreSQL", "database"),
        r"MongoDB": ("MongoDB", "database"),
        r"Redis[_\-]?([\d\.]+)?": ("Redis", "cache"),
        r"Elasticsearch": ("Elasticsearch", "search"),
        r"Docker": ("Docker", "container"),
        r"FTP[_\-]Server": ("FTP Server", "ftp"),
        r"Telnet[_\-]Server": ("Telnet", "telnet"),
        r"SMTP": ("SMTP", "mail"),
        r"POP3": ("POP3", "mail"),
        r"IMAP": ("IMAP", "mail"),
        r"Jenkins": ("Jenkins", "ci_cd"),
        r"Tomcat[_\-]?([\d\.]+)?": ("Tomcat", "web_server"),
        r"Joomla": ("Joomla", "cms"),
        r"WordPress": ("WordPress", "cms"),
        r"Drupal": ("Drupal", "cms"),
        r"Nextcloud": ("Nextcloud", "file_sync"),
        r"OwnCloud": ("OwnCloud", "file_sync"),
        r"Grafana": ("Grafana", "monitoring"),
        r"Prometheus": ("Prometheus", "monitoring"),
        r"Consul": ("Consul", "service_discovery"),
        r"etcd": ("etcd", "key_value"),
        r"RabbitMQ": ("RabbitMQ", "message_queue"),
        r"Kafka": ("Kafka", "message_queue"),
        r"Cassandra": ("Cassandra", "database"),
        r"CouchDB": ("CouchDB", "database"),
        r"InfluxDB": ("InfluxDB", "database"),
        r"Solr": ("Solr", "search"),
        r"Zookeeper": ("Zookeeper", "orchestration"),
        r"Memcached": ("Memcached", "cache"),
        r"haproxy": ("HAProxy", "load_balancer"),
        r"nginx": ("Nginx", "reverse_proxy"),
        r"Apache[_\-]HTTP": ("Apache", "web_server"),
        r"Jetty": ("Jetty", "web_server"),
        r"Kestrel": ("Kestrel", "web_server"),
        r"Caddy": ("Caddy", "web_server"),
        r"Hyper": ("Hyper", "web_server"),
    }
    
    def analyze(self, banner: str) -> str:
        """
        Анализировать баннер и определить сервис
        
        Args:
            banner: Баннер сервиса
            
        Returns:
            Название определённого сервиса
        """
        if not banner:
            return "Unknown"
        
        banner_normalized = banner.strip()
        
        # Попробовать найти по паттернам
        for pattern, (service_name, service_type) in self.PATTERNS.items():
            match = re.search(pattern, banner_normalized, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                if version:
                    return f"{service_name} {version}"
                return service_name
        
        # Если паттерны не нашли, вернуть первую строку баннера
        first_line = banner_normalized.split('\n')[0]
        return first_line[:50] if first_line else "Unknown"
    
    def get_service_type(self, service_name: str) -> str:
        """
        Получить тип сервиса
        
        Args:
            service_name: Название сервиса
            
        Returns:
            Тип сервиса
        """
        service_lower = service_name.lower()
        
        if "ssh" in service_lower or "openssh" in service_lower:
            return "SSH"
        elif "http" in service_lower or "web" in service_lower or "apache" in service_lower:
            return "Web Server"
        elif "mysql" in service_lower or "postgres" in service_lower or "database" in service_lower:
            return "Database"
        elif "ftp" in service_lower:
            return "FTP"
        elif "smtp" in service_lower or "mail" in service_lower:
            return "Mail"
        elif "redis" in service_lower or "memcached" in service_lower:
            return "Cache"
        elif "mongodb" in service_lower:
            return "MongoDB"
        else:
            return "Unknown"
    
    def is_vulnerable(self, banner: str) -> bool:
        """
        Проверить содержит ли баннер известные уязвимые версии
        
        Args:
            banner: Баннер сервиса
            
        Returns:
            True если потенциально уязвим
        """
        vulnerable_patterns = [
            r"Apache\s+2\.[0-2]",  # Apache 2.0-2.2 потенциально уязвимы
            r"Apache\s+1\.",       # Apache 1.x очень старые
            r"OpenSSH\s+[1-5]\.",  # OpenSSH 1-5 очень старые
            r"nginx\s+0\.",        # Nginx 0.x очень старые
            r"IIS\s+[5-6]",        # IIS 5-6 очень старые
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def extract_version(banner: str) -> Optional[str]:
        """
        Извлечь версию из баннера
        
        Args:
            banner: Баннер сервиса
            
        Returns:
            Версия или None
        """
        version_pattern = r"(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z]\d+)?)"
        match = re.search(version_pattern, banner)
        if match:
            return match.group(1)
        return None
