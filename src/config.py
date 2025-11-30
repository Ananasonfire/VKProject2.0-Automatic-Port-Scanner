"""


Модуль для загрузки и валидации конфигурации из YAML файла.
Использует Pydantic для типизации и валидации.
"""

import yaml
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator


logger = logging.getLogger(__name__)


# ======================== PYDANTIC МОДЕЛИ ========================

class ScanConfig(BaseModel):
    """Конфигурация для сканирования"""
    targets: List[str] = Field(default=["192.168.1.0/24"], description="IP/CIDR для сканирования")
    ports: List[int] = Field(default=[21, 22, 80, 443], description="Порты для сканирования")
    rate: int = Field(default=1000, ge=10, description="Пакетов в секунду")
    timeout: int = Field(default=300, ge=30, description="Таймаут в секундах")
    threads: int = Field(default=4, ge=1, description="Количество потоков")

    @validator('targets')
    def validate_targets(cls, v):
        if not v or len(v) == 0:
            raise ValueError("Должно быть хотя бы одна цель для сканирования")
        return v

    @validator('ports')
    def validate_ports(cls, v):
        if not v:
            raise ValueError("Должен быть указан хотя бы один порт")
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f"Порт {port} вне допустимого диапазона (1-65535)")
        return sorted(list(set(v)))  # Удалить дубли, отсортировать


class DatabaseConfig(BaseModel):
    """Конфигурация хранилища"""
    type: str = Field(default="sqlite", description="Тип: sqlite или json")
    path: str = Field(default="scan_history.db", description="Путь к БД/файлу")

    @validator('type')
    def validate_type(cls, v):
        if v not in ["sqlite", "json"]:
            raise ValueError("Тип БД должен быть 'sqlite' или 'json'")
        return v


class ScheduleConfig(BaseModel):
    """Конфигурация расписания"""
    enabled: bool = Field(default=True, description="Включить периодичность")
    cron: str = Field(default="0 */4 * * *", description="Cron выражение")


class TelegramNotifyConfig(BaseModel):
    """Конфигурация Telegram уведомлений"""
    enabled: bool = Field(default=False)
    token: Optional[str] = Field(default=None)
    chat_id: Optional[str] = Field(default=None)

    @validator('token', 'chat_id', pre=True, always=True)
    def validate_if_enabled(cls, v, values):
        if values.get('enabled') and not v:
            raise ValueError("Token и chat_id обязательны при включённом Telegram")
        return v


class EmailNotifyConfig(BaseModel):
    """Конфигурация Email уведомлений"""
    enabled: bool = Field(default=False)
    smtp_server: Optional[str] = Field(default=None)
    smtp_port: Optional[int] = Field(default=None)
    sender_email: Optional[str] = Field(default=None)
    sender_password: Optional[str] = Field(default=None)
    recipient: Optional[str] = Field(default=None)


class DiscordNotifyConfig(BaseModel):
    """Конфигурация Discord уведомлений"""
    enabled: bool = Field(default=False)
    webhook_url: Optional[str] = Field(default=None)


class NotificationsConfig(BaseModel):
    """Конфигурация всех каналов уведомлений"""
    telegram: TelegramNotifyConfig = Field(default_factory=TelegramNotifyConfig)
    email: EmailNotifyConfig = Field(default_factory=EmailNotifyConfig)
    discord: DiscordNotifyConfig = Field(default_factory=DiscordNotifyConfig)


class CVECheckConfig(BaseModel):
    """Конфигурация проверки CVE"""
    enabled: bool = Field(default=False, description="Включить проверку CVE")
    api_key: Optional[str] = Field(default=None, description="Vulners API ключ")


class DashboardConfig(BaseModel):
    """Конфигурация веб-дашборда"""
    enabled: bool = Field(default=True)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=5000, ge=1, le=65535)
    debug: bool = Field(default=False)


class AppConfig(BaseModel):
    """Главная конфигурация приложения"""
    scan: ScanConfig = Field(default_factory=ScanConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    cve_check: CVECheckConfig = Field(default_factory=CVECheckConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)

    class Config:
        validate_assignment = True


# ======================== ЗАГРУЗЧИК КОНФИГУРАЦИИ ========================

class ConfigManager:
    """Менеджер конфигурации с кешированием"""
    
    _instance: Optional['ConfigManager'] = None
    _config: Optional[AppConfig] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance
    
    @classmethod
    def load(cls, config_path: str = "config.yaml") -> AppConfig:
        """
        Загрузить конфигурацию из YAML файла
        
        Args:
            config_path: Путь к файлу конфигурации
            
        Returns:
            AppConfig: Объект конфигурации
        """
        manager = cls()
        
        if manager._config is not None:
            logger.debug("Возвращение кешированной конфигурации")
            return manager._config
        
        config_file = Path(config_path)
        
        if not config_file.exists():
            logger.warning(f"Файл {config_path} не найден. Используется конфигурация по умолчанию.")
            manager._config = AppConfig()
            return manager._config
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                raw_config = yaml.safe_load(f) or {}
            
            logger.debug(f"Загружена конфигурация из {config_path}")
            manager._config = AppConfig(**raw_config)
            
        except yaml.YAMLError as e:
            logger.error(f"Ошибка парсинга YAML: {e}")
            raise
        except ValueError as e:
            logger.error(f"Ошибка валидации конфигурации: {e}")
            raise
        
        logger.info("Конфигурация успешно загружена и валидирована")
        return manager._config
    
    @classmethod
    def get(cls) -> AppConfig:
        """Получить загруженную конфигурацию"""
        manager = cls()
        if manager._config is None:
            raise RuntimeError("Конфигурация не загружена. Вызовите load() сначала.")
        return manager._config
    
    @classmethod
    def reset(cls):
        """Очистить кеш (для тестирования)"""
        cls._instance = None
        cls._config = None


# ======================== УТИЛИТЫ ========================

def print_config_info(config: AppConfig) -> None:
    """Вывести информацию о конфигурации"""
    print("\n" + "="*60)
    print("КОНФИГУРАЦИЯ СКАНЕРА")
    print("="*60)
    print(f"\n📍 СКАНИРОВАНИЕ:")
    print(f"   Цели: {', '.join(config.scan.targets)}")
    print(f"   Порты: {config.scan.ports[:5]}{'...' if len(config.scan.ports) > 5 else ''}")
    print(f"   Скорость: {config.scan.rate} пак/сек")
    print(f"   Потоки: {config.scan.threads}")
    
    print(f"\n💾 БАЗА ДАННЫХ:")
    print(f"   Тип: {config.database.type}")
    print(f"   Путь: {config.database.path}")
    
    print(f"\n📅 РАСПИСАНИЕ:")
    print(f"   Включено: {'✓' if config.schedule.enabled else '✗'}")
    print(f"   Cron: {config.schedule.cron}")
    
    print(f"\n📢 УВЕДОМЛЕНИЯ:")
    print(f"   Telegram: {'✓' if config.notifications.telegram.enabled else '✗'}")
    print(f"   Email: {'✓' if config.notifications.email.enabled else '✗'}")
    print(f"   Discord: {'✓' if config.notifications.discord.enabled else '✗'}")
    
    print(f"\n🔍 ПРОВЕРКИ:")
    print(f"   CVE: {'✓' if config.cve_check.enabled else '✗'}")
    print(f"   Дашборд: {'✓' if config.dashboard.enabled else '✗'}")
    print("="*60 + "\n")
