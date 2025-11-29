# Automatic Port Scanner with Masscan

Автоматический многопоточный сканер портов на базе Masscan с мониторингом, хранением истории и уведомлениями в мессенджеры/email.

## Возможности

✅ Многопоточное сканирование IP-адресов с помощью Masscan  
✅ Определение открытых портов и анализ баннеров  
✅ Сравнение результатов с историей (определение новых угроз)  
✅ Уведомления в Telegram, Discord, Email  
✅ Гибкая система хранения (SQLite или JSON)  
✅ Периодическое сканирование по расписанию (cron-формат)  
✅ Веб-дашборд для мониторинга  
✅ Проверка CVE через Vulners API (опционально)  
✅ Нативная поддержка асинхронности и многопоточности  
✅ Полная конфигурация через YAML без редактирования кода  

## Требования

- **Python 3.11+**
- **Masscan** (установить: `sudo apt install masscan` или `brew install masscan`)
- **Nmap** (опционально, для глубоких проверок)

## Установка и запуск

### 1. Клонирование и подготовка

```bash
# Создать виртуальное окружение
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# или
venv\Scripts\activate  # Windows

# Установить зависимости
pip install -r requirements.txt
```

### 2. Настройка конфигурации

Отредактируйте файл `config.yaml`:

```yaml
# Диапазоны для сканирования
scan:
  targets:
    - "192.168.1.0/24"
    - "8.8.8.8"
  ports: [21, 22, 80, 443, 3306, 5432, 6379, 27017]
  rate: 1000  # пакетов в секунду
  timeout: 300

# Система хранения результатов
database:
  type: "sqlite"  # "sqlite" или "json"
  path: "scan_history.db"

# Периодичность запуска (cron формат)
schedule:
  enabled: true
  cron: "0 */4 * * *"  # каждые 4 часа

# Каналы уведомлений
notifications:
  telegram:
    enabled: true
    token: "YOUR_BOT_TOKEN"
    chat_id: "YOUR_CHAT_ID"
  
  email:
    enabled: false
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    sender_email: "your_email@gmail.com"
    sender_password: "your_app_password"
    recipient: "recipient@example.com"
  
  discord:
    enabled: false
    webhook_url: "https://discord.com/api/webhooks/..."

# CVE проверки
cve_check:
  enabled: false
  api_key: "VULNERS_API_KEY"
  
# Веб-дашборд
dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 5000
  debug: true
```

### 3. Получение токенов/ключей

#### Telegram Bot Token
1. Чат с [@BotFather](https://t.me/botfather) в Telegram
2. Выполнить `/newbot` и получить токен
3. Добавить бота в группу/чат и получить `chat_id` (можно через [@userinfobot](https://t.me/userinfobot))

#### Gmail/Email
- Включить двухфакторную аутентификацию
- Создать пароль приложения в [аккаунте Google](https://myaccount.google.com/apppasswords)

#### Discord Webhook
- Прав администратора в серверу → Параметры → Веб-хуки → Создать

### 4. Запуск

```bash
# Один раз (тестирование)
python src/main.py --once

# С периодическим сканированием (фоновый режим)
python src/main.py --scheduler

# Веб-дашборд (отдельно)
python src/dashboard.py
```

## Структура проекта

```
.
├── src/
│   ├── main.py                 # Точка запуска
│   ├── config.py               # Загрузка конфигурации
│   ├── scanner.py              # Управление Masscan
│   ├── storage.py              # БД/файловое хранилище
│   ├── notify.py               # Система уведомлений
│   ├── banner_analyzer.py      # Анализ баннеров сервисов
│   ├── cve_checker.py          # Проверка уязвимостей
│   ├── dashboard.py            # Веб-интерфейс
│   └── utils.py                # Утилиты
├── config.yaml                 # Конфигурация
├── requirements.txt            # Зависимости
├── README.md                   # Документация
└── scan_history.db            # БД (создается автоматически)
```

## Примеры использования

### Базовое сканирование

```bash
python src/main.py --once
```

Результат:
```
[INFO] Запуск Masscan для целей: ['192.168.1.0/24']
[INFO] Сканирование завершено за 45 сек
[INFO] Найдено 12 новых открытых портов
[NOTIFY] Отправлено 12 уведомлений в Telegram
```

### С планировщиком

```bash
python src/main.py --scheduler
```

Сканирование будет запускаться автоматически согласно расписанию.

### Веб-дашборд

```bash
python src/dashboard.py
# Перейти на http://127.0.0.1:5000
```

## API Дашборда

- `GET /api/results` - последние результаты
- `GET /api/history` - история сканирований
- `GET /api/stats` - статистика
- `POST /api/scan` - запустить сканирование немедленно
- `GET /api/logs` - логи последнего сканирования

## Логирование

Логи записываются в консоль и в файл `scan.log`.

Уровни логирования:
- `DEBUG` - детальная информация
- `INFO` - обычные события
- `WARNING` - потенциальные проблемы
- `ERROR` - ошибки

## Устранение неполадок

### Masscan не найден
```bash
# Linux
sudo apt install masscan

# macOS
brew install masscan

# Проверить установку
masscan --version
```

### Ошибка разрешений при сканировании
```bash
# Masscan требует прав администратора/суперпользователя
sudo python src/main.py --once
```

### Уведомления не отправляются
- Проверить интернет-соединение
- Проверить токены в конфиге (не должны содержать пробелы)
- Включить логирование с `debug: true`
- Проверить логи: `tail -f scan.log`

## Расширение функционала

### Добавление нового канала уведомлений

1. Создать класс в `src/notify.py`:
```python
class YourNotifier(BaseNotifier):
    async def send(self, message: str) -> bool:
        # Реализация
        pass
```

2. Зарегистрировать в `NotificationManager`



