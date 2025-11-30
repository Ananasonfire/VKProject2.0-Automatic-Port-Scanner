"""


Модуль для управления Masscan сканированием.
Запускает процесс Masscan, парсит результаты, анализирует баннеры.
"""

import subprocess
import json
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import asyncio
import socket
from models import ScanResult, ScanSession, ScanStatus
from banner_analyzer import BannerAnalyzer
from utils import get_service_name


logger = logging.getLogger(__name__)


class MasscanScanner:
    """
    Обёртка для Masscan сканера
    """
    
    def __init__(self, rate: int = 1000, timeout: int = 300):
        """
        Инициализация сканера
        
        Args:
            rate: Пакетов в секунду
            timeout: Таймаут сканирования
        """
        self.rate = rate
        self.timeout = timeout
        self.banner_analyzer = BannerAnalyzer()
        self._verify_masscan_installed()
    
    @staticmethod
    def _verify_masscan_installed() -> bool:
        """Проверить, что команда masscan существует в PATH."""
        import shutil

        path = shutil.which("masscan")
        if path:
            logger.info(f"Masscan найден по пути: {path}")
            return True

        logger.error("Команда 'masscan' не найдена в PATH")
        raise RuntimeError("Masscan не найден в системе")


    
    async def scan_async(
        self,
        targets: List[str],
        ports: List[int],
        get_banners: bool = True
    ) -> ScanSession:
        """
        Асинхронное сканирование целей
        
        Args:
            targets: Список IP/CIDR для сканирования
            ports: Список портов
            get_banners: Получать ли баннеры (требует привилегий)
            
        Returns:
            ScanSession с результатами
        """
        session = ScanSession(
            id=str(uuid.uuid4()),
            targets=targets,
            status=ScanStatus.RUNNING,
        )
        
        try:
            logger.info(f"Начало сканирования: {', '.join(targets)}")
            logger.info(f"Портов для сканирования: {len(ports)}")
            
            # Запустить Masscan
            results = await self._run_masscan(targets, ports)
            session.results = results
            
            # Попытаться получить баннеры если требуется
            if get_banners and results:
                logger.info(f"Получение баннеров для {len(results)} портов...")
                results = await self._get_banners_async(results)
                session.results = results
            
            session.total_results = len(results)
            session.status = ScanStatus.COMPLETED
            session.end_time = datetime.now()
            
            logger.info(f"Сканирование завершено. Найдено портов: {len(results)}")
            
        except Exception as e:
            logger.error(f"Ошибка при сканировании: {e}", exc_info=True)
            session.status = ScanStatus.FAILED
            session.errors.append(str(e))
            session.end_time = datetime.now()
        
        return session
    
    async def _run_masscan(
        self,
        targets: List[str],
        ports: List[int]
    ) -> List[ScanResult]:
        """
        Запустить Masscan с параметрами
        
        Args:
            targets: Цели для сканирования
            ports: Порты для сканирования
            
        Returns:
            Список результатов сканирования
        """
        output_file = f"/tmp/masscan_output_{uuid.uuid4()}.json"
        
        # Формировать команду Masscan
        port_str = ",".join(str(p) for p in ports)
        target_str = " ".join(targets)
        
        cmd = [
            "masscan",
            target_str,
            "-p", port_str,
            "--rate", str(self.rate),
            "-oJ", output_file,
            "--wait", "5",  # Ждать завершения
        ]
        
        try:
            logger.debug(f"Запуск команды: {' '.join(cmd)}")
            
            # Запустить с повышенными привилегиями если необходимо
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Masscan ошибка: {error_msg}")
                raise RuntimeError(f"Masscan failed: {error_msg}")
            
            # Парсить результаты
            return self._parse_masscan_output(output_file)
            
        except asyncio.TimeoutError:
            logger.error(f"Массcan таймаут ({self.timeout}s)")
            raise
        except Exception as e:
            logger.error(f"Ошибка запуска Masscan: {e}")
            raise
        finally:
            # Удалить временный файл
            try:
                Path(output_file).unlink(missing_ok=True)
            except Exception:
                pass
    
    def _parse_masscan_output(self, output_file: str) -> List[ScanResult]:
        """
        Парсить JSON вывод Masscan
        
        Args:
            output_file: Путь к файлу вывода
            
        Returns:
            Список результатов
        """
        results = []
        
        try:
            if not Path(output_file).exists():
                logger.warning(f"Файл {output_file} не найден")
                return results
            
            with open(output_file, 'r') as f:
                raw_data = f.read()
            
            # Парсить JSON
            for line in raw_data.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    
                    # Извлечь IP и порты
                    for host_data in data.get('host', []):
                        ip = host_data['addr'][0]['addr']
                        
                        for port_data in host_data.get('ports', []):
                            port = port_data['port'][0]['portid']
                            service = get_service_name(port)
                            
                            result = ScanResult(
                                ip=ip,
                                port=port,
                                service=service,
                                banner=None,  # Будет заполнено позже
                                timestamp=datetime.now(),
                            )
                            results.append(result)
                
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.warning(f"Ошибка при парсинге строки: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Ошибка при парсинге вывода: {e}")
        
        return results
    
    async def _get_banners_async(
        self,
        results: List[ScanResult]
    ) -> List[ScanResult]:
        """
        Получить баннеры для всех найденных портов (асинхронно)
        
        Args:
            results: Список результатов сканирования
            
        Returns:
            Список результатов с баннерами
        """
        tasks = [
            self._get_banner_for_port(result)
            for result in results
        ]
        
        updated_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in updated_results if r and not isinstance(r, Exception)]
    
    async def _get_banner_for_port(self, result: ScanResult) -> Optional[ScanResult]:
        """
        Получить баннер одного порта (асинхронно)
        
        Args:
            result: Результат сканирования
            
        Returns:
            Результат с баннером
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(result.ip, result.port),
                timeout=3
            )
            
            # Отправить HTTP запрос или просто ждать баннера
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
            # Прочитать ответ
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            result.banner = banner.decode('utf-8', errors='ignore')[:200]
            
            # Анализировать баннер
            service = self.banner_analyzer.analyze(result.banner)
            result.service = service
            
            writer.close()
            await writer.wait_closed()
            
        except asyncio.TimeoutError:
            pass  # Таймаут - оставить результат без баннера
        except ConnectionRefusedError:
            pass
        except Exception as e:
            logger.debug(f"Ошибка при получении баннера {result.ip}:{result.port}: {e}")
        
        return result
    
    def scan_sync(
        self,
        targets: List[str],
        ports: List[int],
        get_banners: bool = True
    ) -> ScanSession:
        """
        Синхронное сканирование (обёртка над асинхронной версией)
        
        Args:
            targets: Список IP/CIDR для сканирования
            ports: Список портов
            get_banners: Получать ли баннеры
            
        Returns:
            ScanSession с результатами
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.scan_async(targets, ports, get_banners)
        )
