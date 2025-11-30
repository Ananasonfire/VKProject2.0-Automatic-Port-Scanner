"""
main.py

Главная точка запуска приложения.
Управляет сканированием, уведомлениями и периодическим запуском.
"""

import logging
import asyncio
import argparse
import sys
from datetime import datetime
from pathlib import Path

# Добавить текущий каталог в sys.path
sys.path.insert(0, str(Path(__file__).parent))

from config import ConfigManager, print_config_info
from scanner import MasscanScanner
from storage import create_storage
from notify import create_notification_manager
from utils import setup_logging, format_notification_message, ScanStatistics,format_duration
from models import ScanStatus


logger = logging.getLogger(__name__)


class PortScannerApplication:
    """Главное приложение для сканирования портов"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Инициализация приложения
        
        Args:
            config_path: Путь к файлу конфигурации
        """
        # Загрузить конфигурацию
        self.config = ConfigManager.load(config_path)
        
        # Инициализировать компоненты
        self.scanner = MasscanScanner(
            rate=self.config.scan.rate,
            timeout=self.config.scan.timeout
        )
        
        self.storage = create_storage(
            self.config.database.type,
            self.config.database.path
        )
        
        self.notifier = create_notification_manager(
            self.config.notifications.model_dump()
        )
        
        logger.info("Application initialized successfully")
    
    async def run_scan(self) -> bool:
        """
        Запустить одно сканирование
        
        Returns:
            True если успешно, False если ошибка
        """
        try:
            logger.info("=" * 60)
            logger.info("STARTING SCAN SESSION")
            logger.info("=" * 60)
            
            stats = ScanStatistics()
            
            # Запустить Masscan асинхронно
            session = await self.scanner.scan_async(
                targets=self.config.scan.targets,
                ports=self.config.scan.ports,
                get_banners=True
            )
            
            if session.status == ScanStatus.FAILED:
                logger.error(f"Scan failed: {', '.join(session.errors)}")
                return False
            
            # Сохранить результаты в БД
            self.storage.save_scan_session(session)
            
            # Подсчитать новые результаты
            new_results = [r for r in session.results if r.is_new]
            session.new_results = len(new_results)
            session.total_results = len(session.results)
            
            # Обновить в БД
            self.storage.save_scan_session(session)
            
            # Получить статистику
            stats.finalize()
            stats.total_ports_found = len(session.results)
            stats.new_ports_found = len(new_results)
            stats.targets_scanned = len(self.config.scan.targets)
            summary = stats.finalize()

            logger.info(f"Scan completed in {summary['duration_formatted']}")
            logger.info(f"Total ports found: {stats.total_ports_found}")
            logger.info(f"New ports found: {stats.new_ports_found}")
            
            # Отправить уведомления если найдены новые портыassertEqual
            if new_results:
                logger.info(f"Notifying about {len(new_results)} new discoveries...")
                
                message = format_notification_message(
                    [
                        {
                            'ip': r.ip,
                            'port': r.port,
                            'service': r.service or 'Unknown'
                        }
                        for r in new_results
                    ],
                    {
                        'duration': int(session.duration_seconds() or 0),
                        'total_ports': stats.total_ports_found,
                    }
                )
                
                await self.notifier.notify_all(message)
            else:
                logger.info("No new discoveries in this scan")
            
            # Вывести результаты
            logger.info("=" * 60)
            logger.info("TOP DISCOVERIES:")
            for result in sorted(session.results, key=lambda x: x.port)[:10]:
                logger.info(
                    f"  {result.ip}:{result.port:5d} | {result.service:15} | "
                    f"{result.banner[:40] if result.banner else 'N/A'}"
                )
            logger.info("=" * 60)
            
            return True
        
        except Exception as e:
            logger.error(f"Error during scan: {e}", exc_info=True)
            return False
    
    def run_once(self) -> None:
        """Запустить одно сканирование и выйти"""
        logger.info("Mode: Single scan")
        
        # Запустить асинхронное сканирование
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        success = loop.run_until_complete(self.run_scan())
        sys.exit(0 if success else 1)
    
    def run_scheduler(self) -> None:
        """Запустить с периодическим сканированием"""
        logger.info("Mode: Scheduled scanning")
        
        if not self.config.schedule.enabled:
            logger.error("Schedule is disabled in config")
            return
        
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.triggers.cron import CronTrigger
            
            scheduler = BackgroundScheduler()
            
            # Добавить работу по расписанию
            def scan_job():
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                
                loop.run_until_complete(self.run_scan())
            
            scheduler.add_job(
                scan_job,
                CronTrigger.from_crontab(self.config.schedule.cron),
                id='port_scan_job',
                name='Port Scanner'
            )
            
            logger.info(f"Scheduler started with cron: {self.config.schedule.cron}")
            logger.info("Press Ctrl+C to stop")
            
            scheduler.start()
            
            # Держать приложение в памяти
            while True:
                pass
        
        except ImportError:
            logger.error("APScheduler not installed. Install with: pip install APScheduler")
            sys.exit(1)
        except KeyboardInterrupt:
            logger.info("Scheduler stopped by user")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Scheduler error: {e}", exc_info=True)
            sys.exit(1)


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description="Automatic Port Scanner with Masscan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --once                 # Run single scan
  python main.py --scheduler            # Run with scheduler
  python main.py --config custom.yaml   # Use custom config
        """
    )
    
    parser.add_argument(
        '--once',
        action='store_true',
        help='Run single scan and exit'
    )
    
    parser.add_argument(
        '--scheduler',
        action='store_true',
        help='Run with periodic scanning'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to config file (default: config.yaml)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Настроить логирование
    log_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(log_file='scan.log', level=log_level)
    
    logger.info("╔══════════════════════════════════════════════════════════╗")
    logger.info("║          AUTOMATIC PORT SCANNER - MASSCAN v1.0          ║")
    logger.info("╚══════════════════════════════════════════════════════════╝")
    
    try:
        # Создать приложение
        app = PortScannerApplication(config_path=args.config)
        
        # Вывести конфигурацию
        print_config_info(app.config)
        
        # Запустить в нужном режиме
        if args.once:
            app.run_once()
        elif args.scheduler:
            app.run_scheduler()
        else:
            # По умолчанию - одно сканирование
            app.run_once()
    
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
