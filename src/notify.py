"""


Система уведомлений: Telegram, Email, Discord.
"""

import logging
import asyncio
import aiohttp
import smtplib
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from models import Notification, NotificationStatus


logger = logging.getLogger(__name__)


# ======================== БАЗОВЫЙ КЛАСС ========================

class BaseNotifier(ABC):
    """Базовый класс для уведомителей"""
    
    @abstractmethod
    async def send(self, message: str) -> bool:
        """Отправить уведомление"""
        pass
    
    @abstractmethod
    def is_enabled(self) -> bool:
        """Включен ли этот уведомитель"""
        pass


# ======================== TELEGRAM ========================

class TelegramNotifier(BaseNotifier):
    """Уведомитель через Telegram Bot API"""
    
    def __init__(self, token: str, chat_id: str):
        """
        Инициализация Telegram уведомителя
        
        Args:
            token: Bot API токен
            chat_id: ID чата для уведомлений
        """
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{token}"
        self._enabled = bool(token and chat_id)
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    async def send(self, message: str) -> bool:
        """Отправить сообщение в Telegram"""
        if not self.is_enabled():
            logger.warning("Telegram notifier not enabled")
            return False
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/sendMessage",
                    json={"chat_id": self.chat_id, "text": message, "parse_mode": "Markdown"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info("Telegram notification sent successfully")
                        return True
                    else:
                        error = await response.text()
                        logger.error(f"Telegram API error: {error}")
                        return False
        
        except Exception as e:
            logger.error(f"Failed to send Telegram notification: {e}")
            return False


# ======================== EMAIL ========================

class EmailNotifier(BaseNotifier):
    """Уведомитель через Email (SMTP)"""
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        sender_email: str,
        sender_password: str,
        recipient: str
    ):
        """
        Инициализация Email уведомителя
        
        Args:
            smtp_server: SMTP сервер
            smtp_port: SMTP порт
            sender_email: Email отправителя
            sender_password: Пароль отправителя
            recipient: Email получателя
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipient = recipient
        self._enabled = all([smtp_server, smtp_port, sender_email, sender_password, recipient])
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    async def send(self, message: str) -> bool:
        """Отправить email"""
        if not self.is_enabled():
            logger.warning("Email notifier not enabled")
            return False
        
        try:
            # Запустить в отдельном потоке чтобы не блокировать асинхронный код
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._send_sync, message)
            return result
        
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False
    
    def _send_sync(self, message: str) -> bool:
        """Синхронная отправка email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = self.recipient
            msg['Subject'] = "🔍 Port Scan Alert"
            
            # Преобразовать markdown в HTML для email
            html_message = message.replace('*', '<b>').replace('*', '</b>')
            html_message = html_message.replace('\n', '<br>')
            
            msg.attach(MIMEText(html_message, 'html'))
            
            # Отправить
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            logger.info("Email notification sent successfully")
            return True
        
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            return False


# ======================== DISCORD ========================

class DiscordNotifier(BaseNotifier):
    """Уведомитель через Discord Webhook"""
    
    def __init__(self, webhook_url: str):
        """
        Инициализация Discord уведомителя
        
        Args:
            webhook_url: Discord webhook URL
        """
        self.webhook_url = webhook_url
        self._enabled = bool(webhook_url)
    
    def is_enabled(self) -> bool:
        return self._enabled
    
    async def send(self, message: str) -> bool:
        """Отправить сообщение в Discord"""
        if not self.is_enabled():
            logger.warning("Discord notifier not enabled")
            return False
        
        try:
            # Преобразовать markdown для Discord (markdown немного другой)
            payload = {
                "content": message,
                "username": "Port Scanner Bot"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status in [200, 204]:
                        logger.info("Discord notification sent successfully")
                        return True
                    else:
                        error = await response.text()
                        logger.error(f"Discord API error: {error}")
                        return False
        
        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")
            return False


# ======================== МЕНЕДЖЕР УВЕДОМЛЕНИЙ ========================

class NotificationManager:
    """Менеджер для управления всеми каналами уведомлений"""
    
    def __init__(self):
        """Инициализация менеджера"""
        self.notifiers: List[BaseNotifier] = []
    
    def add_notifier(self, notifier: BaseNotifier) -> None:
        """Добавить уведомитель"""
        if notifier.is_enabled():
            self.notifiers.append(notifier)
            logger.info(f"Added notifier: {notifier.__class__.__name__}")
    
    async def notify_all(self, message: str) -> int:
        """
        Отправить уведомление всем включённым каналам
        
        Args:
            message: Сообщение
            
        Returns:
            Количество успешно отправленных уведомлений
        """
        if not self.notifiers:
            logger.warning("No notifiers configured")
            return 0
        
        logger.info(f"Sending notification to {len(self.notifiers)} channels")
        
        tasks = [notifier.send(message) for notifier in self.notifiers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is True)
        logger.info(f"Notifications sent: {success_count}/{len(self.notifiers)} successful")
        
        return success_count
    
    async def notify_async(self, message: str) -> None:
        """Асинхронно отправить уведомление (не ждать результата)"""
        asyncio.create_task(self.notify_all(message))


# ======================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ========================

def create_notification_manager(config: dict) -> NotificationManager:
    """
    Создать менеджер уведомлений на основе конфигурации
    
    Args:
        config: Словарь с конфигурацией уведомлений
        
    Returns:
        NotificationManager с настроенными каналами
    """
    manager = NotificationManager()
    
    # Telegram
    if config.get('telegram', {}).get('enabled'):
        telegram = TelegramNotifier(
            token=config['telegram'].get('token', ''),
            chat_id=config['telegram'].get('chat_id', '')
        )
        manager.add_notifier(telegram)
    
    # Email
    if config.get('email', {}).get('enabled'):
        email = EmailNotifier(
            smtp_server=config['email'].get('smtp_server', ''),
            smtp_port=config['email'].get('smtp_port', 587),
            sender_email=config['email'].get('sender_email', ''),
            sender_password=config['email'].get('sender_password', ''),
            recipient=config['email'].get('recipient', '')
        )
        manager.add_notifier(email)
    
    # Discord
    if config.get('discord', {}).get('enabled'):
        discord = DiscordNotifier(
            webhook_url=config['discord'].get('webhook_url', '')
        )
        manager.add_notifier(discord)
    
    return manager
