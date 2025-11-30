"""


Модуль для хранения результатов сканирования.
Поддерживает SQLite и JSON.
"""

import sqlite3
import json
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from models import ScanResult, ScanSession


logger = logging.getLogger(__name__)


# ======================== АБСТРАКТНЫЙ КЛАСС ========================

class BaseStorage(ABC):
    """Базовый класс для хранилища"""
    
    @abstractmethod
    def save_scan_session(self, session: ScanSession) -> bool:
        """Сохранить сессию сканирования"""
        pass
    
    @abstractmethod
    def get_scan_session(self, scan_id: str) -> Optional[ScanSession]:
        """Получить сессию сканирования"""
        pass
    
    @abstractmethod
    def get_scan_history(self, limit: int = 100) -> List[ScanSession]:
        """Получить историю сканирований"""
        pass
    
    @abstractmethod
    def check_is_new_result(self, result: ScanResult) -> bool:
        """Проверить новый ли результат"""
        pass
    
    @abstractmethod
    def get_all_results(self) -> List[ScanResult]:
        """Получить все результаты"""
        pass
    
    @abstractmethod
    def delete_old_results(self, days: int = 30) -> int:
        """Удалить результаты старше N дней"""
        pass
    
    @abstractmethod
    def get_statistics(self) -> Dict:
        """Получить статистику"""
        pass


# ======================== SQLite ХРАНИЛИЩЕ ========================

class SQLiteStorage(BaseStorage):
    """Хранилище на SQLite БД"""
    
    def __init__(self, db_path: str = "scan_history.db"):
        """
        Инициализация SQLite хранилища
        
        Args:
            db_path: Путь к БД файлу
        """
        self.db_path = db_path
        self._init_db()
        logger.info(f"SQLite хранилище инициализировано: {db_path}")
    
    def _get_connection(self) -> sqlite3.Connection:
        """Получить подключение к БД"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self) -> None:
        """Инициализировать таблицы БД"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Таблица сканирований
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    targets TEXT NOT NULL,
                    total_results INTEGER DEFAULT 0,
                    new_results INTEGER DEFAULT 0,
                    errors TEXT
                )
            """)
            
            # Таблица результатов
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service TEXT,
                    banner TEXT,
                    is_new INTEGER DEFAULT 1,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_sessions(id),
                    UNIQUE(ip, port)
                )
            """)
            
            # Индексы для производительности
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_port ON scan_results(ip, port)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_id ON scan_results(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_results(timestamp)")
            
            conn.commit()
            logger.debug("Таблицы БД созданы успешно")
        
        except sqlite3.OperationalError as e:
            logger.error(f"Ошибка инициализации БД: {e}")
        finally:
            conn.close()
    
    def save_scan_session(self, session: ScanSession) -> bool:
        """Сохранить сессию сканирования"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Сохранить сессию
            cursor.execute("""
                INSERT OR REPLACE INTO scan_sessions
                (id, status, start_time, end_time, targets, total_results, new_results, errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.id,
                session.status.value,
                session.start_time.isoformat(),
                session.end_time.isoformat() if session.end_time else None,
                json.dumps(session.targets),
                session.total_results,
                session.new_results,
                json.dumps(session.errors) if session.errors else None
            ))
            
            # Сохранить результаты
            for result in session.results:
                result_id = str(uuid.uuid4())
                
                try:
                    cursor.execute("""
                        INSERT INTO scan_results
                        (id, scan_id, ip, port, service, banner, is_new, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        result_id,
                        session.id,
                        result.ip,
                        result.port,
                        result.service,
                        result.banner,
                        1 if result.is_new else 0,
                        result.timestamp.isoformat()
                    ))
                except sqlite3.IntegrityError:
                    # Результат уже существует
                    result.is_new = False
                    logger.debug(f"Результат уже существует: {result.ip}:{result.port}")
            
            conn.commit()
            logger.info(f"Сессия {session.id} сохранена в БД")
            return True
        
        except Exception as e:
            logger.error(f"Ошибка при сохранении сессии: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def get_scan_session(self, scan_id: str) -> Optional[ScanSession]:
        """Получить сессию сканирования"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Получить сессию
            cursor.execute("SELECT * FROM scan_sessions WHERE id = ?", (scan_id,))
            session_row = cursor.fetchone()
            
            if not session_row:
                return None
            
            session = ScanSession(
                id=session_row['id'],
                status=session_row['status'],
                start_time=datetime.fromisoformat(session_row['start_time']),
                end_time=datetime.fromisoformat(session_row['end_time']) if session_row['end_time'] else None,
                targets=json.loads(session_row['targets']),
                total_results=session_row['total_results'],
                new_results=session_row['new_results'],
                errors=json.loads(session_row['errors']) if session_row['errors'] else [],
            )
            
            # Получить результаты
            cursor.execute("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
            for row in cursor.fetchall():
                result = ScanResult(
                    ip=row['ip'],
                    port=row['port'],
                    service=row['service'],
                    banner=row['banner'],
                    is_new=bool(row['is_new']),
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    scan_id=row['scan_id'],
                )
                session.results.append(result)
            
            return session
        
        except Exception as e:
            logger.error(f"Ошибка при получении сессии: {e}")
            return None
        finally:
            conn.close()
    
    def get_scan_history(self, limit: int = 100) -> List[ScanSession]:
        """Получить последние сканирования"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id FROM scan_sessions
                ORDER BY start_time DESC
                LIMIT ?
            """, (limit,))
            
            sessions = []
            for row in cursor.fetchall():
                session = self.get_scan_session(row['id'])
                if session:
                    sessions.append(session)
            
            return sessions
        
        except Exception as e:
            logger.error(f"Ошибка при получении истории: {e}")
            return []
        finally:
            conn.close()
    
    def check_is_new_result(self, result: ScanResult) -> bool:
        """Проверить новый ли результат"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT COUNT(*) as count FROM scan_results
                WHERE ip = ? AND port = ?
            """, (result.ip, result.port))
            
            row = cursor.fetchone()
            return row['count'] == 0
        
        except Exception as e:
            logger.error(f"Ошибка при проверке новизны: {e}")
            return True
        finally:
            conn.close()
    
    def get_all_results(self) -> List[ScanResult]:
        """Получить все результаты"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM scan_results ORDER BY timestamp DESC")
            
            results = []
            for row in cursor.fetchall():
                result = ScanResult(
                    ip=row['ip'],
                    port=row['port'],
                    service=row['service'],
                    banner=row['banner'],
                    is_new=bool(row['is_new']),
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    scan_id=row['scan_id'],
                )
                results.append(result)
            
            return results
        
        except Exception as e:
            logger.error(f"Ошибка при получении всех результатов: {e}")
            return []
        finally:
            conn.close()
    
    def delete_old_results(self, days: int = 30) -> int:
        """Удалить результаты старше N дней"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            from datetime import timedelta
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            cursor.execute(
                "DELETE FROM scan_results WHERE timestamp < ?",
                (cutoff_date,)
            )
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            logger.info(f"Удалено {deleted_count} результатов старше {days} дней")
            return deleted_count
        
        except Exception as e:
            logger.error(f"Ошибка при удалении: {e}")
            conn.rollback()
            return 0
        finally:
            conn.close()
    
    def get_statistics(self) -> Dict:
        """Получить статистику"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Всего результатов
            cursor.execute("SELECT COUNT(*) as count FROM scan_results")
            total_results = cursor.fetchone()['count']
            
            # Уникальных хостов
            cursor.execute("SELECT COUNT(DISTINCT ip) as count FROM scan_results")
            unique_hosts = cursor.fetchone()['count']
            
            # Всего портов
            cursor.execute("SELECT COUNT(*) as count FROM scan_sessions WHERE status = 'completed'")
            total_scans = cursor.fetchone()['count']
            
            # Популярные порты
            cursor.execute("""
                SELECT port, COUNT(*) as count FROM scan_results
                GROUP BY port
                ORDER BY count DESC
                LIMIT 10
            """)
            
            popular_ports = {row['port']: row['count'] for row in cursor.fetchall()}
            
            return {
                'total_results': total_results,
                'unique_hosts': unique_hosts,
                'total_scans': total_scans,
                'popular_ports': popular_ports,
            }
        
        except Exception as e:
            logger.error(f"Ошибка при получении статистики: {e}")
            return {}
        finally:
            conn.close()


# ======================== JSON ХРАНИЛИЩЕ ========================

class JSONStorage(BaseStorage):
    """Хранилище на JSON файлах"""
    
    def __init__(self, file_path: str = "scan_history.json"):
        """
        Инициализация JSON хранилища
        
        Args:
            file_path: Путь к JSON файлу
        """
        self.file_path = file_path
        self._init_file()
        logger.info(f"JSON хранилище инициализировано: {file_path}")
    
    def _init_file(self) -> None:
        """Инициализировать JSON файл"""
        if not Path(self.file_path).exists():
            initial_data = {'sessions': [], 'results': []}
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=2, ensure_ascii=False)
    
    def _load_data(self) -> Dict:
        """Загрузить данные из файла"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Ошибка при загрузке JSON: {e}")
            return {'sessions': [], 'results': []}
    
    def _save_data(self, data: Dict) -> bool:
        """Сохранить данные в файл"""
        try:
            with open(self.file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            return True
        except Exception as e:
            logger.error(f"Ошибка при сохранении JSON: {e}")
            return False
    
    def save_scan_session(self, session: ScanSession) -> bool:
        """Сохранить сессию"""
        data = self._load_data()
        
        session_dict = {
            'id': session.id,
            'status': session.status.value,
            'start_time': session.start_time.isoformat(),
            'end_time': session.end_time.isoformat() if session.end_time else None,
            'targets': session.targets,
            'total_results': session.total_results,
            'new_results': session.new_results,
        }
        
        # Удалить старую версию если существует
        data['sessions'] = [s for s in data['sessions'] if s['id'] != session.id]
        data['sessions'].append(session_dict)
        
        # Добавить результаты
        for result in session.results:
            result_dict = {
                'ip': result.ip,
                'port': result.port,
                'service': result.service,
                'banner': result.banner,
                'is_new': result.is_new,
                'timestamp': result.timestamp.isoformat(),
                'scan_id': session.id,
            }
            
            # Проверить дубликаты
            exists = any(
                r['ip'] == result.ip and r['port'] == result.port
                for r in data['results']
            )
            
            if not exists:
                data['results'].append(result_dict)
        
        return self._save_data(data)
    
    def get_scan_session(self, scan_id: str) -> Optional[ScanSession]:
        """Получить сессию"""
        data = self._load_data()
        
        for session_dict in data['sessions']:
            if session_dict['id'] == scan_id:
                session = ScanSession(
                    id=session_dict['id'],
                    status=session_dict['status'],
                    start_time=datetime.fromisoformat(session_dict['start_time']),
                    end_time=datetime.fromisoformat(session_dict['end_time']) if session_dict.get('end_time') else None,
                    targets=session_dict['targets'],
                    total_results=session_dict['total_results'],
                    new_results=session_dict['new_results'],
                )
                
                for result_dict in data['results']:
                    if result_dict['scan_id'] == scan_id:
                        result = ScanResult(
                            ip=result_dict['ip'],
                            port=result_dict['port'],
                            service=result_dict.get('service'),
                            banner=result_dict.get('banner'),
                            is_new=result_dict['is_new'],
                            timestamp=datetime.fromisoformat(result_dict['timestamp']),
                            scan_id=result_dict['scan_id'],
                        )
                        session.results.append(result)
                
                return session
        
        return None
    
    def get_scan_history(self, limit: int = 100) -> List[ScanSession]:
        """Получить историю"""
        data = self._load_data()
        sessions = []
        
        for session_dict in sorted(
            data['sessions'],
            key=lambda x: x['start_time'],
            reverse=True
        )[:limit]:
            session = self.get_scan_session(session_dict['id'])
            if session:
                sessions.append(session)
        
        return sessions
    
    def check_is_new_result(self, result: ScanResult) -> bool:
        """Проверить новый ли результат"""
        data = self._load_data()
        
        for r in data['results']:
            if r['ip'] == result.ip and r['port'] == result.port:
                return False
        
        return True
    
    def get_all_results(self) -> List[ScanResult]:
        """Получить все результаты"""
        data = self._load_data()
        results = []
        
        for result_dict in data['results']:
            result = ScanResult(
                ip=result_dict['ip'],
                port=result_dict['port'],
                service=result_dict.get('service'),
                banner=result_dict.get('banner'),
                is_new=result_dict['is_new'],
                timestamp=datetime.fromisoformat(result_dict['timestamp']),
                scan_id=result_dict['scan_id'],
            )
            results.append(result)
        
        return results
    
    def delete_old_results(self, days: int = 30) -> int:
        """Удалить старые результаты"""
        from datetime import timedelta
        
        data = self._load_data()
        cutoff_date = datetime.now() - timedelta(days=days)
        
        original_count = len(data['results'])
        data['results'] = [
            r for r in data['results']
            if datetime.fromisoformat(r['timestamp']) > cutoff_date
        ]
        
        deleted_count = original_count - len(data['results'])
        self._save_data(data)
        
        logger.info(f"Удалено {deleted_count} результатов старше {days} дней")
        return deleted_count
    
    def get_statistics(self) -> Dict:
        """Получить статистику"""
        data = self._load_data()
        
        total_results = len(data['results'])
        unique_hosts = len(set(r['ip'] for r in data['results']))
        
        port_counts = {}
        for r in data['results']:
            port = r['port']
            port_counts[port] = port_counts.get(port, 0) + 1
        
        popular_ports = dict(sorted(
            port_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])
        
        return {
            'total_results': total_results,
            'unique_hosts': unique_hosts,
            'total_scans': len(data['sessions']),
            'popular_ports': popular_ports,
        }


# ======================== ФАБРИКА ========================

def create_storage(storage_type: str, path: str) -> BaseStorage:
    """
    Создать хранилище нужного типа
    
    Args:
        storage_type: Тип ("sqlite" или "json")
        path: Путь к файлу
        
    Returns:
        Экземпляр хранилища
    """
    if storage_type == "sqlite":
        return SQLiteStorage(path)
    elif storage_type == "json":
        return JSONStorage(path)
    else:
        raise ValueError(f"Неизвестный тип хранилища: {storage_type}")
