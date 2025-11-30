"""


Модели данных для сканирования, уведомлений и результатов.
Использует Pydantic для типизации и валидации.
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


# ======================== ENUMS ========================

class ScanStatus(str, Enum):
    """Статус сканирования"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    """Уровень критичности"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationStatus(str, Enum):
    """Статус отправки уведомления"""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


# ======================== ОСНОВНЫЕ МОДЕЛИ ========================

class ScanResult(BaseModel):
    """Результат сканирования одного портаrn"""
    ip: str = Field(..., description="IP адрес")
    port: int = Field(..., ge=1, le=65535, description="Номер порта")
    service: Optional[str] = Field(default=None, description="Название сервиса")
    banner: Optional[str] = Field(default=None, description="Баннер сервиса")
    is_new: bool = Field(default=True, description="Новый ли результат")
    timestamp: datetime = Field(default_factory=datetime.now, description="Время обнаружения")
    scan_id: Optional[str] = Field(default=None, description="ID сканирования")
    
    class Config:
        use_enum_values = True


class ScanSession(BaseModel):
    """Сессия сканирования"""
    id: str = Field(..., description="Уникальный ID сканирования")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = Field(default=None)
    targets: List[str] = Field(default_factory=list, description="Сканируемые цели")
    results: List[ScanResult] = Field(default_factory=list, description="Результаты")
    total_results: int = Field(default=0)
    new_results: int = Field(default=0)
    errors: List[str] = Field(default_factory=list)
    
    def duration_seconds(self) -> Optional[float]:
        """Длительность в секундах"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    class Config:
        use_enum_values = True


class CVEVulnerability(BaseModel):
    """Уязвимость CVE"""
    cve_id: str = Field(..., description="CVE ID")
    service: str = Field(..., description="Затронутый сервис")
    port: int = Field(..., description="Порт")
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM)
    description: str = Field(..., description="Описание уязвимости")
    cvss_score: Optional[float] = Field(default=None, ge=0, le=10)
    published_date: Optional[str] = Field(default=None)
    
    class Config:
        use_enum_values = True


class Notification(BaseModel):
    """Уведомление"""
    id: str = Field(..., description="Уникальный ID уведомления")
    channel: str = Field(..., description="Канал (telegram, email, discord)")
    message: str = Field(..., description="Текст сообщения")
    status: NotificationStatus = Field(default=NotificationStatus.PENDING)
    created_at: datetime = Field(default_factory=datetime.now)
    sent_at: Optional[datetime] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    related_scan_id: Optional[str] = Field(default=None)
    
    class Config:
        use_enum_values = True


# ======================== DTO (DATA TRANSFER OBJECTS) ========================

class ScanResultDTO(BaseModel):
    """DTO для передачи результата сканирования"""
    ip: str
    port: int
    service: str
    banner: Optional[str]
    is_new: bool
    timestamp: str


class ScanStatisticsDTO(BaseModel):
    """DTO для статистики сканирования"""
    scan_id: str
    status: str
    duration_seconds: Optional[float]
    total_results: int
    new_results: int
    targets_count: int
    errors_count: int


class HistoryItemDTO(BaseModel):
    """DTO для элемента истории"""
    scan_id: str
    timestamp: str
    targets: List[str]
    total_results: int
    new_results: int
    status: str
