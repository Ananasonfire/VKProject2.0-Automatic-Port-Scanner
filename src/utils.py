"""
utils.py

Утилиты: логирование, формирование сообщений, валидация IP.
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Any
import socket
import struct
from ipaddress import ip_network, ip_address


# ======================== ЛОГИРОВАНИЕ ========================

def setup_logging(log_file: str = "scan.log", level: int = logging.INFO) -> None:
    """
    Настроить логирование в консоль и файл
    
    Args:
        log_file: Путь к файлу логов
        level: Уровень логирования
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Форматер для консоли (с цветом)
    class ColoredFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': '\033[36m',    # Голубой
            'INFO': '\033[32m',     # Зелёный
            'WARNING': '\033[33m',  # Жёлтый
            'ERROR': '\033[31m',    # Красный
            'CRITICAL': '\033[35m', # Пурпурный
        }
        RESET = '\033[0m'
        
        def format(self, record):
            if record.levelname in self.COLORS:
                record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
            return super().format(record)
    
    # Корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Консоль хендлер (с цветом)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = ColoredFormatter(log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Файловый хендлер
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(log_format)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)


# ======================== IP УТИЛИТЫ ========================

def expand_cidr(cidr: str) -> List[str]:
    """
    Расширить CIDR нотацию в список IP адресов
    
    Args:
        cidr: CIDR диапазон (например, "192.168.1.0/24")
        
    Returns:
        Список IP адресов
    """
    try:
        network = ip_network(cidr, strict=False)
        # Для больших сетей вернуть только сеть (без расширения)
        if network.num_addresses > 256:
            return [cidr]
        return [str(ip) for ip in network.hosts()]
    except Exception as e:
        logging.error(f"Ошибка при парсинге CIDR {cidr}: {e}")
        return [cidr]


def is_valid_ip(ip: str) -> bool:
    """Проверить валидность IP адреса"""
    try:
        ip_address(ip)
        return True
    except Exception:
        return False


# ======================== ФОРМАТИРОВАНИЕ СООБЩЕНИЙ ========================

def format_scan_result(ip: str, port: int, service: str, banner: str) -> str:
    """
    Форматировать результат сканирования для вывода
    
    Returns:
        Форматированная строка
    """
    return f"[{ip}:{port}] {service:15} - {banner[:50]}"


def format_notification_message(
    new_results: List[Dict[str, Any]],
    summary: Dict[str, Any]
) -> str:
    """
    Форматировать сообщение для уведомления
    
    Args:
        new_results: Список новых результатов
        summary: Резюме сканирования
        
    Returns:
        Форматированное сообщение
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    message = f"""
🔍 *Результаты сканирования портов*

⏰ Время: {timestamp}
📊 Найдено новых: {len(new_results)}
⏱️ Длительность: {summary.get('duration', 'N/A')}с
📈 Всего найдено портов: {summary.get('total_ports', 0)}

*Новые открытые порты:*
"""
    
    for result in new_results[:10]:  # Ограничить первыми 10
        message += f"\n• {result['ip']}:{result['port']} - {result['service']}"
    
    if len(new_results) > 10:
        message += f"\n• ... и ещё {len(new_results) - 10}"
    
    message += "\n\n✅ Сканирование завершено успешно"
    
    return message.strip()


def format_cve_notification(cve_data: Dict[str, Any]) -> str:
    """Форматировать уведомление о CVE"""
    message = f"""
⚠️ *ОБНАРУЖЕНА УЯЗВИМОСТЬ*

🎯 Сервис: {cve_data.get('service', 'Unknown')}
🔓 Порт: {cve_data.get('port', 'N/A')}
📌 CVE: {cve_data.get('cve_id', 'N/A')}
⚡ Критичность: {cve_data.get('severity', 'Unknown')}
📝 Описание: {cve_data.get('description', 'N/A')[:200]}
"""
    return message.strip()


# ======================== ФАЙЛОВЫЕ УТИЛИТЫ ========================

def save_json(data: Any, filepath: str) -> bool:
    """Сохранить данные в JSON файл"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return True
    except Exception as e:
        logging.error(f"Ошибка при сохранении JSON: {e}")
        return False


def load_json(filepath: str) -> Dict[str, Any]:
    """Загрузить данные из JSON файла"""
    try:
        if not Path(filepath).exists():
            return {}
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Ошибка при загрузке JSON: {e}")
        return {}


# ======================== ПОРТЫ И СЕРВИСЫ ========================

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
    50070: "Hadoop",
}


def get_service_name(port: int, banner: str = "") -> str:
    """
    Получить название сервиса по порту и баннеру
    
    Args:
        port: Номер порта
        banner: Баннер сервиса (опционально)
        
    Returns:
        Название сервиса
    """
    # Попытаться определить из баннера
    banner_lower = banner.lower() if banner else ""
    
    service_keywords = {
        "apache": "Apache",
        "nginx": "Nginx",
        "microsoft-iis": "IIS",
        "openssh": "OpenSSH",
        "openssl": "OpenSSL",
        "mysql": "MySQL",
        "postgresql": "PostgreSQL",
        "mongodb": "MongoDB",
        "redis": "Redis",
        "elasticsearch": "Elasticsearch",
        "docker": "Docker",
        "jenkins": "Jenkins",
    }
    
    for keyword, service in service_keywords.items():
        if keyword in banner_lower:
            return service
    
    # Вернуть из словаря портов или "Unknown"
    return COMMON_SERVICES.get(port, "Unknown")


# ======================== ВРЕМЕННЫЕ УТИЛИТЫ ========================

def get_timestamp() -> str:
    """Получить текущее время в ISO формате"""
    return datetime.now().isoformat()


def format_duration(seconds: float) -> str:
    """Форматировать длительность в читаемый формат"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


# ======================== СТАТИСТИКА ========================

class ScanStatistics:
    """Класс для сбора статистики сканирования"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.end_time: datetime = None
        self.total_ports_found = 0
        self.new_ports_found = 0
        self.targets_scanned = 0
        self.errors = 0
    def duration_seconds(self) -> float:
        if self.end_time is None:
            return (datetime.now() - self.start_time).total_seconds()
        return (self.end_time - self.start_time).total_seconds()
    
    def finalize(self) -> Dict[str, Any]:
        """Получить финальную статистику"""
        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()
        
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration': duration,
            'duration_formatted': format_duration(duration),
            'total_ports_found': self.total_ports_found,
            'new_ports_found': self.new_ports_found,
            'targets_scanned': self.targets_scanned,
            'errors': self.errors,
        }
