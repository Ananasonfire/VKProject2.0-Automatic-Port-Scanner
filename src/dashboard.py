"""
dashboard.py

Веб-дашборд для мониторинга результатов сканирования.
Использует Flask и REST API.
"""

import logging
from flask import Flask, render_template_string, jsonify, request
from pathlib import Path
import sys
from datetime import datetime

# Добавить текущий каталог в sys.path
sys.path.insert(0, str(Path(__file__).parent))

from config import ConfigManager
from storage import create_storage
from models import ScanStatus


logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Инициализировать хранилище
config = ConfigManager.load('config.yaml')
storage = create_storage(config.database.type, config.database.path)


# ======================== HTML ШАБЛОН ========================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scanner Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #00d4ff;
            padding-bottom: 20px;
        }
        
        header h1 {
            font-size: 2.5em;
            color: #00d4ff;
            margin-bottom: 5px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.05);
            border: 2px solid #00d4ff;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            background: rgba(0,212,255,0.1);
            transform: translateY(-5px);
        }
        
        .stat-card h3 {
            color: #00d4ff;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            opacity: 0.8;
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff88;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(255,255,255,0.02);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 8px 32px rgba(0,212,255,0.1);
        }
        
        table th {
            background: rgba(0,212,255,0.1);
            border-bottom: 2px solid #00d4ff;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #00d4ff;
        }
        
        table td {
            padding: 12px 15px;
            border-bottom: 1px solid rgba(0,212,255,0.1);
        }
        
        table tr:hover {
            background: rgba(0,212,255,0.05);
        }
        
        .service-badge {
            display: inline-block;
            background: rgba(0,255,136,0.2);
            color: #00ff88;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
            border: 1px solid #00ff88;
        }
        
        .port-number {
            font-family: 'Courier New', monospace;
            font-weight: bold;
            color: #00d4ff;
        }
        
        .section-title {
            font-size: 1.5em;
            color: #00d4ff;
            margin: 30px 0 20px 0;
            border-left: 4px solid #00ff88;
            padding-left: 10px;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #00d4ff;
        }
        
        .button {
            display: inline-block;
            background: linear-gradient(135deg, #00d4ff 0%, #00ff88 100%);
            color: #1e1e2e;
            padding: 12px 24px;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            font-weight: 600;
            margin: 10px 5px;
            transition: all 0.3s ease;
        }
        
        .button:hover {
            transform: scale(1.05);
            box-shadow: 0 0 20px rgba(0,212,255,0.5);
        }
        
        .error {
            background: rgba(255,0,0,0.1);
            border: 2px solid #ff4444;
            color: #ff8888;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        
        .empty {
            text-align: center;
            padding: 40px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Port Scanner Dashboard</h1>
            <p>Real-time Network Reconnaissance</p>
        </header>
        
        <div class="stats-grid" id="stats">
            <div class="loading">Loading statistics...</div>
        </div>
        
        <div>
            <button class="button" onclick="refreshStats()">🔄 Refresh Stats</button>
            <button class="button" onclick="startScan()">▶️ Start Scan</button>
        </div>
        
        <h2 class="section-title">📊 Scan History</h2>
        <div id="history">
            <div class="loading">Loading history...</div>
        </div>
        
        <h2 class="section-title">🎯 Latest Discoveries</h2>
        <div id="results">
            <div class="loading">Loading results...</div>
        </div>
    </div>
    
    <script>
        async function refreshStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                const statsHtml = `
                    <div class="stat-card">
                        <h3>Total Ports Found</h3>
                        <div class="value">${data.total_results}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Unique Hosts</h3>
                        <div class="value">${data.unique_hosts}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Total Scans</h3>
                        <div class="value">${data.total_scans}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Top Port</h3>
                        <div class="value">${Object.keys(data.popular_ports)[0] || 'N/A'}</div>
                    </div>
                `;
                
                document.getElementById('stats').innerHTML = statsHtml;
            } catch (error) {
                console.error('Error loading stats:', error);
                document.getElementById('stats').innerHTML = 
                    '<div class="error">Failed to load statistics</div>';
            }
        }
        
        async function refreshResults() {
            try {
                const response = await fetch('/api/results?limit=10');
                const data = await response.json();
                
                if (!data.results || data.results.length === 0) {
                    document.getElementById('results').innerHTML = 
                        '<div class="empty">No results yet</div>';
                    return;
                }
                
                let html = '<table>';
                html += '<tr><th>IP Address</th><th>Port</th><th>Service</th><th>Banner</th></tr>';
                
                data.results.forEach(result => {
                    html += `<tr>
                        <td>${result.ip}</td>
                        <td class="port-number">${result.port}</td>
                        <td><span class="service-badge">${result.service}</span></td>
                        <td>${result.banner ? result.banner.substring(0, 50) : 'N/A'}</td>
                    </tr>`;
                });
                
                html += '</table>';
                document.getElementById('results').innerHTML = html;
            } catch (error) {
                console.error('Error loading results:', error);
            }
        }
        
        async function refreshHistory() {
            try {
                const response = await fetch('/api/history?limit=5');
                const data = await response.json();
                
                if (!data.history || data.history.length === 0) {
                    document.getElementById('history').innerHTML = 
                        '<div class="empty">No scan history</div>';
                    return;
                }
                
                let html = '<table>';
                html += '<tr><th>Scan ID</th><th>Status</th><th>Time</th><th>Results</th><th>New</th></tr>';
                
                data.history.forEach(item => {
                    html += `<tr>
                        <td><code>${item.scan_id.substring(0, 8)}</code></td>
                        <td>${item.status}</td>
                        <td>${new Date(item.timestamp).toLocaleString()}</td>
                        <td>${item.total_results}</td>
                        <td><strong>${item.new_results}</strong></td>
                    </tr>`;
                });
                
                html += '</table>';
                document.getElementById('history').innerHTML = html;
            } catch (error) {
                console.error('Error loading history:', error);
            }
        }
        
        async function startScan() {
            if (!confirm('Start new scan now?')) return;
            
            try {
                const response = await fetch('/api/scan', { method: 'POST' });
                const data = await response.json();
                alert(data.message);
                setTimeout(() => {
                    refreshStats();
                    refreshResults();
                    refreshHistory();
                }, 2000);
            } catch (error) {
                alert('Failed to start scan: ' + error.message);
            }
        }
        
        // Загрузить при открытии страницы
        refreshStats();
        refreshResults();
        refreshHistory();
        
        // Обновлять каждые 30 секунд
        setInterval(refreshStats, 30000);
        setInterval(refreshResults, 30000);
    </script>
</body>
</html>
"""


# ======================== МАРШРУТЫ ========================

@app.route('/')
def index():
    """Главная страница дашборда"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/stats')
def api_stats():
    """API: Получить статистику"""
    try:
        stats = storage.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/results')
def api_results():
    """API: Получить последние результаты"""
    try:
        limit = request.args.get('limit', 50, type=int)
        all_results = storage.get_all_results()
        
        results = [
            {
                'ip': r.ip,
                'port': r.port,
                'service': r.service,
                'banner': r.banner,
                'is_new': r.is_new,
                'timestamp': r.timestamp.isoformat() if r.timestamp else None,
            }
            for r in all_results[:limit]
        ]
        
        return jsonify({'results': results})
    except Exception as e:
        logger.error(f"Error getting results: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/history')
def api_history():
    """API: Получить историю сканирований"""
    try:
        limit = request.args.get('limit', 10, type=int)
        sessions = storage.get_scan_history(limit)
        
        history = [
            {
                'scan_id': s.id,
                'status': s.status.value,
                'timestamp': s.start_time.isoformat(),
                'total_results': s.total_results,
                'new_results': s.new_results,
                'duration': s.duration_seconds(),
            }
            for s in sessions
        ]
        
        return jsonify({'history': history})
    except Exception as e:
        logger.error(f"Error getting history: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API: Запустить новое сканирование"""
    try:
        # Запустить сканирование в фоне
        from main import PortScannerApplication
        import threading
        
        app_instance = PortScannerApplication()
        
        def run_scan():
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(app_instance.run_scan())
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
        return jsonify({'message': 'Scan started', 'status': 'running'})
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    """Обработчик 404"""
    return jsonify({'error': 'Not found'}), 404


# ======================== ЗАПУСК ========================

if __name__ == '__main__':
    from utils import setup_logging
    
    setup_logging(log_file='dashboard.log')
    
    logger.info("Starting Port Scanner Dashboard...")
    logger.info(f"Host: {config.dashboard.host}")
    logger.info(f"Port: {config.dashboard.port}")
    
    app.run(
        host=config.dashboard.host,
        port=config.dashboard.port,
        debug=config.dashboard.debug
    )
