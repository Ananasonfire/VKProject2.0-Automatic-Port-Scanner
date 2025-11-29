## АРХИТЕКТУРА ПРОЕКТА И ОПИСАНИЕ МОДУЛЕЙ

### 📁 Структура проекта

```
port-scanner/
├── config.yaml              # Конфигурационный файл (РЕДАКТИРОВАТЬ)
├── requirements.txt         # Зависимости Python
├── README.md               # Главная документация
├── INSTALLATION.md         # Руководство по установке
├── ARCHITECTURE.md         # Этот файл
│
├── main.py                 # 🎯 Точка входа приложения
├── config.py               # ⚙️ Загрузка и валидация конфигурации
├── models.py               # 📦 Pydantic модели данных
├── utils.py                # 🛠️ Утилиты (логирование, форматирование)
│
├── scanner.py              # 📡 Управление Masscan сканированием
├── storage.py              # 💾 Хранилище (SQLite/JSON)
├── banner_analyzer.py      # 🔍 Анализ баннеров сервисов
├── notify.py               # 📢 Система уведомлений (Telegram/Email/Discord)
├── cve_checker.py          # ⚠️ Проверка уязвимостей CVE
│
├── dashboard.py            # 🎨 Веб-дашборд (Flask)
│
├── scan_history.db         # 📊 БД с результатами (создаётся автоматически)
├── scan.log                # 📋 Логи приложения (создаётся автоматически)
└── .gitignore              # Git игнор-файл
```

### 🔄 Поток данных

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CONFIG.PY - Загрузка конфигурации                            │
│    ↓ Читает config.yaml и валидирует все параметры (Pydantic)  │
├─────────────────────────────────────────────────────────────────┤
│ 2. MAIN.PY - Инициализация приложения                           │
│    ↓ Создаёт экземпляры Scanner, Storage, Notifier             │
├─────────────────────────────────────────────────────────────────┤
│ 3. SCANNER.PY - Запуск Masscan сканирования                     │
│    ↓ Запускает async сканирование целей                        │
│    ↓ Парсит результаты Masscan (JSON)                          │
│    ↓ Получает баннеры асинхронно (asyncio)                     │
├─────────────────────────────────────────────────────────────────┤
│ 4. BANNER_ANALYZER.PY - Анализ баннеров                         │
│    ↓ Определяет тип и версию сервиса из баннера                │
├─────────────────────────────────────────────────────────────────┤
│ 5. STORAGE.PY - Сохранение результатов                          │
│    ↓ Сравнивает с историей (выявляет новые порты)             │
│    ↓ Сохраняет в SQLite/JSON базу                              │
├─────────────────────────────────────────────────────────────────┤
│ 6. CVE_CHECKER.PY - Проверка уязвимостей (опционально)         │
│    ↓ Для новых сервисов ищет CVE в Vulners API                │
├─────────────────────────────────────────────────────────────────┤
│ 7. NOTIFY.PY - Отправка уведомлений                             │
│    ↓ Формирует сообщение о новых открытых портах               │
│    ↓ Отправляет в Telegram/Email/Discord асинхронно            │
├─────────────────────────────────────────────────────────────────┤
│ 8. DASHBOARD.PY - Веб-интерфейс (опционально)                  │
│    ↓ REST API для получения статистики и истории               │
│    ↓ Визуализация в браузере                                   │
└─────────────────────────────────────────────────────────────────┘
```

### 📄 Подробное описание каждого модуля

#### **config.py** ⚙️
**Задача:** Загрузка и валидация конфигурации

**Основные классы:**
- `AppConfig` - главная конфигурация (Pydantic модель)
- `ScanConfig` - параметры сканирования
- `DatabaseConfig` - выбор хранилища (SQLite/JSON)
- `ScheduleConfig` - периодичность сканирования
- `NotificationsConfig` - каналы оповещений
- `ConfigManager` - синглтон для кеширования конфигурации

**Валидация:**
- IP адреса и CIDR нотация
- Диапазоны портов (1-65535)
- Cron выражения
- Обязательные поля для активных каналов

**Использование:**
```python
from config import ConfigManager
config = ConfigManager.load('config.yaml')
print(config.scan.targets)  # ['192.168.1.0/24']
```

---

#### **models.py** 📦
**Задача:** Определение типов и структур данных

**Основные модели:**
- `ScanResult` - одно обнаруженное соединение (IP:port:service)
- `ScanSession` - сессия сканирования (N результатов)
- `CVEVulnerability` - найденная уязвимость
- `Notification` - отправленное уведомление

**Enums:**
- `ScanStatus` - состояние сканирования (pending, running, completed, failed)
- `SeverityLevel` - критичность CVE (low, medium, high, critical)
- `NotificationStatus` - статус отправки (pending, sent, failed)

**Использование:**
```python
from models import ScanResult, ScanStatus
result = ScanResult(ip='192.168.1.5', port=22, service='SSH')
```

---

#### **scanner.py** 📡
**Задача:** Управление Masscan сканированием

**Основной класс:**
- `MasscanScanner` - обёртка для Masscan

**Методы:**
- `scan_async(targets, ports)` - асинхронное сканирование
- `scan_sync(targets, ports)` - синхронное сканирование
- `_run_masscan()` - запуск процесса Masscan
- `_parse_masscan_output()` - парсинг JSON вывода
- `_get_banners_async()` - получение баннеров асинхронно
- `_get_banner_for_port()` - получение одного баннера

**Процесс:**
1. Проверка установки Masscan
2. Формирование команды сканирования
3. Запуск в subprocess с asyncio
4. Парсинг JSON результатов
5. Асинхронное получение баннеров (max 10 одновременно)
6. Анализ баннеров через BannerAnalyzer

**Использование:**
```python
from scanner import MasscanScanner
scanner = MasscanScanner(rate=1000, timeout=300)
session = await scanner.scan_async(['192.168.1.0/24'], [22, 80, 443])
```

---

#### **banner_analyzer.py** 🔍
**Задача:** Определение типа сервиса по баннеру

**Основной класс:**
- `BannerAnalyzer` - анализатор баннеров

**Методы:**
- `analyze(banner)` - определить сервис по баннеру
- `get_service_type(service_name)` - получить категорию сервиса
- `is_vulnerable(banner)` - проверить на известные уязвимости
- `extract_version(banner)` - извлечь версию

**Паттерны распознавания:**
- Apache, Nginx, IIS (веб-серверы)
- MySQL, PostgreSQL, MongoDB (БД)
- OpenSSH, FTP, Telnet (сетевые сервисы)
- Docker, Jenkins, Elasticsearch и др.

**Пример:**
```python
analyzer = BannerAnalyzer()
service = analyzer.analyze("Apache/2.4.41 (Ubuntu)")  # "Apache 2.4.41"
```

---

#### **storage.py** 💾
**Задача:** Хранение и сравнение результатов сканирования

**Абстрактный класс:**
- `BaseStorage` - интерфейс для хранилищ

**Реализации:**
- `SQLiteStorage` - хранение в SQLite БД (быстро, надёжно)
- `JSONStorage` - хранение в JSON файле (простой, портативный)

**Методы:**
- `save_scan_session(session)` - сохранить сессию
- `get_scan_session(scan_id)` - получить сессию
- `get_scan_history(limit)` - история сканирований
- `check_is_new_result(result)` - новый ли результат?
- `get_all_results()` - все результаты
- `delete_old_results(days)` - очистить старые
- `get_statistics()` - статистика

**SQLite БД структура:**
```sql
scan_sessions (id, status, start_time, end_time, targets, total_results, new_results)
scan_results (id, scan_id, ip, port, service, banner, is_new, timestamp)
```

**Использование:**
```python
from storage import create_storage
storage = create_storage('sqlite', 'scan_history.db')
storage.save_scan_session(session)
new_results = [r for r in session.results if r.is_new]
```

---

#### **notify.py** 📢
**Задача:** Отправка уведомлений о новых открытых портах

**Базовый класс:**
- `BaseNotifier` - интерфейс для уведомителей

**Реализации:**
- `TelegramNotifier` - отправка в Telegram Bot API
- `EmailNotifier` - отправка по SMTP
- `DiscordNotifier` - отправка в Discord Webhook

**Менеджер:**
- `NotificationManager` - управление всеми каналами

**Методы:**
- `send(message)` - отправить сообщение
- `is_enabled()` - включен ли канал?
- `notify_all(message)` - отправить во все каналы

**Асинхронность:**
- Все отправки выполняются асинхронно (asyncio.gather)
- Не блокирует основной процесс сканирования

**Использование:**
```python
from notify import create_notification_manager
manager = create_notification_manager(config.notifications.dict())
await manager.notify_all("🎯 Найдены новые открытые порты!")
```

---

#### **cve_checker.py** ⚠️
**Задача:** Проверка известных уязвимостей

**Основной класс:**
- `CVEChecker` - проверка CVE

**Методы:**
- `check_service(service, version)` - проверить сервис
- `_search_vulners(query)` - запрос в Vulners API
- `check_known_vulnerabilities(service, banner)` - локальная БД уязвимостей

**Источники:**
- Vulners API (если ключ есть)
- Встроенная БД известных уязвимостей

**Использование:**
```python
from cve_checker import CVEChecker
checker = CVEChecker(api_key='vulners_key')
vulns = await checker.check_service('Apache', '2.2.0')
```

---

#### **dashboard.py** 🎨
**Задача:** Веб-интерфейс для мониторинга

**Фреймворк:** Flask (лёгкий, встроенный в Python)

**Маршруты:**
- `/` - главная страница с дашбордом
- `/api/stats` - статистика (JSON)
- `/api/results` - последние результаты (JSON)
- `/api/history` - история сканирований (JSON)
- `/api/scan` - запустить сканирование (POST)

**Функционал:**
- Real-time статистика
- Таблица открытых портов
- История сканирований
- Кнопка запуска сканирования
- Красивый UI (современный дизайн)

**Использование:**
```bash
python dashboard.py
# Перейти на http://127.0.0.1:5000
```

---

#### **main.py** 🎯
**Задача:** Главное приложение и точка входа

**Основной класс:**
- `PortScannerApplication` - главное приложение

**Методы:**
- `run_scan()` - запустить одно сканирование
- `run_once()` - режим одного запуска
- `run_scheduler()` - режим с периодичностью

**Процесс выполнения:**
1. Загрузить конфигурацию
2. Инициализировать компоненты (Scanner, Storage, Notifier)
3. Запустить Masscan асинхронно
4. Сохранить результаты в хранилище
5. Выявить новые портыassertIn
6. Отправить уведомления
7. Повторить по расписанию (если включено)

**CLI аргументы:**
- `--once` - одно сканирование
- `--scheduler` - периодичность
- `--config <path>` - путь к конфигу
- `--debug` - расширенное логирование

**Использование:**
```bash
python main.py --once              # Одно сканирование
python main.py --scheduler         # С расписанием
python main.py --config my.yaml    # Свой конфиг
```

---

#### **utils.py** 🛠️
**Задача:** Вспомогательные функции

**Функции:**
- `setup_logging()` - настройка логирования (консоль + файл)
- `expand_cidr()` - расширить CIDR в список IP
- `is_valid_ip()` - проверить валидность IP
- `format_notification_message()` - форматировать сообщение
- `format_duration()` - форматировать время

**Классы:**
- `ScanStatistics` - сбор статистики сканирования

**Логирование:**
- Цветной вывод в консоль
- Запись в файл scan.log
- Разные уровни: DEBUG, INFO, WARNING, ERROR

---

### 🔐 Безопасность

**Что учтено:**
1. **Валидация входных данных** - все параметры проверяются Pydantic
2. **SQL инъекции** - используются параметризованные запросы
3. **Асинхронность** - не блокирует основной процесс
4. **Таймауты** - на все сетевые операции
5. **Логирование** - всех ошибок и операций
6. **Приватные данные** - токены не логируются, хранятся в config.yaml

---

### ⚡ Производительность

**Оптимизации:**
1. **Асинхронность (asyncio)** - получение баннеров параллельно
2. **Кеширование конфигурации** - один раз при старте
3. **Индексы БД** - на часто используемых колонках
4. **Партионирование** - на массивы для asyncio.gather()
5. **Таймауты** - избежать зависаний

**Примерная производительность:**
- Masscan: 1000+ пакетов/сек
- Получение баннеров: 10-20 одновременно
- Сохранение в БД: ~1000 результатов/сек

---

### 📚 Расширение функционала

#### Добавить новый канал уведомлений

```python
# В notify.py:
class SlackNotifier(BaseNotifier):
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    async def send(self, message: str) -> bool:
        # Реализация
        pass
    
    def is_enabled(self) -> bool:
        return bool(self.webhook_url)
```

#### Добавить новый тип хранилища

```python
# В storage.py:
class PostgreSQLStorage(BaseStorage):
    def __init__(self, connection_string: str):
        # Инициализация
        pass
    
    def save_scan_session(self, session):
        # Реализация
        pass
```

---

### 🧪 Тестирование

```bash
# Тест конфигурации
python -c "from config import ConfigManager; ConfigManager.load('config.yaml')"

# Тест Masscan
masscan --version

# Тест хранилища
python -c "from storage import create_storage; s = create_storage('sqlite', 'test.db')"

# Тест уведомлений (без отправки)
python -c "from notify import create_notification_manager; m = create_notification_manager({})"
```

---

## Заключение

Проект спроектирован как **модульный, расширяемый и продакшн-готовый** решение:

✅ **Модульность** - каждый компонент отвечает за одну задачу  
✅ **Типизация** - Pydantic для безопасности типов  
✅ **Асинхронность** - высокая производительность  
✅ **Конфигурируемость** - всё через YAML без правок кода  
✅ **Логирование** - для отладки и мониторинга  
✅ **Тестируемость** - лёгко добавлять новые компоненты  
✅ **Документированность** - подробные комментарии и docstring'и  

Этот проект демонстрирует профессиональный подход к разработке сетевых утилит на Python.
