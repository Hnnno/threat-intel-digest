"""
dashboard.py
Dashboard web opcional para visualizar el reporte de threat intelligence
en el navegador. Sirve el ultimo reporte generado en formato HTML.

Uso:
    python src/dashboard.py
    Luego abri http://localhost:5000 en tu navegador.

Requiere:
    pip install flask
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, jsonify
from dotenv import load_dotenv

load_dotenv()

# Importaciones del pipeline
import sys
sys.path.insert(0, str(Path(__file__).parent))
from collectors import rss_collector, api_collector
from processors import filter as article_filter, summarizer

app = Flask(__name__)
logger = logging.getLogger(__name__)

CACHE_PATH = Path(__file__).parent.parent / "cache" / "last_report.json"
CACHE_PATH.parent.mkdir(exist_ok=True)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intel Digest — Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
        }
        header {
            border-bottom: 1px solid #30363d;
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }
        header h1 { font-size: 1.4rem; color: #58a6ff; letter-spacing: 2px; }
        header p  { font-size: 0.8rem; color: #8b949e; margin-top: 4px; }
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
        .panel {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1.2rem;
        }
        .panel h2 {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            color: #8b949e;
            margin-bottom: 1rem;
            border-bottom: 1px solid #21262d;
            padding-bottom: 0.5rem;
        }
        .article {
            border-left: 3px solid #30363d;
            padding: 0.6rem 0.8rem;
            margin-bottom: 0.8rem;
        }
        .article.critical { border-color: #f85149; }
        .article.high     { border-color: #e3b341; }
        .article.medium   { border-color: #388bfd; }
        .badge {
            display: inline-block;
            font-size: 0.65rem;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            margin-bottom: 4px;
            text-transform: uppercase;
        }
        .badge.critical { background: #3d1a1a; color: #f85149; }
        .badge.high     { background: #2d2207; color: #e3b341; }
        .badge.medium   { background: #0d2045; color: #388bfd; }
        .article a {
            color: #c9d1d9;
            text-decoration: none;
            font-size: 0.85rem;
            font-weight: bold;
            display: block;
            margin-bottom: 4px;
        }
        .article a:hover { color: #58a6ff; }
        .article p { font-size: 0.78rem; color: #8b949e; line-height: 1.5; }
        .ip-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid #21262d;
            font-size: 0.8rem;
        }
        .ip-row:last-child { border-bottom: none; }
        .ip-addr { color: #f85149; }
        .ip-meta { color: #8b949e; font-size: 0.72rem; text-align: right; }
        .pulse-row {
            padding: 0.5rem 0;
            border-bottom: 1px solid #21262d;
            font-size: 0.8rem;
        }
        .pulse-row:last-child { border-bottom: none; }
        .pulse-row a { color: #58a6ff; text-decoration: none; }
        .pulse-row a:hover { text-decoration: underline; }
        .pulse-meta { color: #8b949e; font-size: 0.72rem; margin-top: 2px; }
        .stat-bar {
            display: flex;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .stat {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem 1.5rem;
            flex: 1;
            text-align: center;
        }
        .stat .value { font-size: 2rem; color: #58a6ff; font-weight: bold; }
        .stat .label { font-size: 0.7rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
        .refresh-btn {
            background: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 6px 14px;
            border-radius: 4px;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.8rem;
            float: right;
        }
        .refresh-btn:hover { background: #30363d; }
        .empty { color: #8b949e; font-size: 0.8rem; font-style: italic; }
        .full-width { grid-column: 1 / -1; }
    </style>
</head>
<body>
    <header>
        <h1>THREAT INTEL DIGEST</h1>
        <p>Ultima actualizacion: <span id="last-update">Cargando...</span></p>
        <button class="refresh-btn" onclick="loadData()">Actualizar</button>
    </header>

    <div class="stat-bar" id="stats"></div>

    <div class="grid" id="content"></div>

    <script>
        async function loadData() {
            const res = await fetch('/api/report');
            const data = await res.json();

            document.getElementById('last-update').textContent = data.generated_at || 'Desconocido';

            const articles = data.articles || [];
            const ips      = data.top_abusive_ips || [];
            const pulses   = data.otx_pulses || [];

            const critical = articles.filter(a => a.severity === 'critical').length;
            const high     = articles.filter(a => a.severity === 'high').length;
            const medium   = articles.filter(a => a.severity === 'medium').length;

            document.getElementById('stats').innerHTML = `
                <div class="stat"><div class="value">${critical}</div><div class="label">Criticos</div></div>
                <div class="stat"><div class="value">${high}</div><div class="label">Altos</div></div>
                <div class="stat"><div class="value">${medium}</div><div class="label">Medios</div></div>
                <div class="stat"><div class="value">${ips.length}</div><div class="label">IPs abusivas</div></div>
                <div class="stat"><div class="value">${pulses.length}</div><div class="label">Pulsos OTX</div></div>
            `;

            const articlesHtml = articles.length === 0
                ? '<p class="empty">No se encontraron articulos relevantes.</p>'
                : articles.map(a => `
                    <div class="article ${a.severity}">
                        <span class="badge ${a.severity}">${a.severity}</span>
                        <a href="${a.url}" target="_blank">${a.title}</a>
                        <p>${a.ai_summary || a.summary || ''}</p>
                    </div>`).join('');

            const ipsHtml = ips.length === 0
                ? '<p class="empty">No hay datos de AbuseIPDB.</p>'
                : ips.map(ip => `
                    <div class="ip-row">
                        <span class="ip-addr">${ip.ip}</span>
                        <span class="ip-meta">Score: ${ip.abuse_confidence_score} | ${ip.country} | ${ip.total_reports} reportes</span>
                    </div>`).join('');

            const pulsesHtml = pulses.length === 0
                ? '<p class="empty">No hay datos de AlienVault OTX.</p>'
                : pulses.map(p => `
                    <div class="pulse-row">
                        <a href="${p.url}" target="_blank">${p.name}</a>
                        <div class="pulse-meta">IOCs: ${p.ioc_count} | Autor: ${p.author}</div>
                    </div>`).join('');

            document.getElementById('content').innerHTML = `
                <div class="panel full-width">
                    <h2>Articulos por severidad</h2>
                    ${articlesHtml}
                </div>
                <div class="panel">
                    <h2>IPs mas reportadas — AbuseIPDB</h2>
                    ${ipsHtml}
                </div>
                <div class="panel">
                    <h2>Campanas recientes — AlienVault OTX</h2>
                    ${pulsesHtml}
                </div>
            `;
        }

        loadData();
    </script>
</body>
</html>
"""


def generate_report() -> dict:
    """
    Ejecuta el pipeline y guarda el resultado en cache.
    Retorna el reporte como diccionario.
    """
    rss_articles      = rss_collector.collect_all()
    api_data          = api_collector.collect_all()
    relevant          = article_filter.filter_and_classify(rss_articles)
    summarized        = summarizer.summarize_all(relevant)

    report = {
        "generated_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "articles":        summarized,
        "top_abusive_ips": api_data.get("top_abusive_ips", []),
        "otx_pulses":      api_data.get("otx_pulses", []),
    }

    with open(CACHE_PATH, "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


def load_cached_report() -> dict:
    """
    Carga el ultimo reporte desde cache si existe.
    Si no existe, genera uno nuevo.
    """
    if CACHE_PATH.exists():
        with open(CACHE_PATH) as f:
            return json.load(f)
    return generate_report()


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/report")
def api_report():
    return jsonify(load_cached_report())


@app.route("/api/refresh")
def api_refresh():
    report = generate_report()
    return jsonify({"status": "ok", "generated_at": report["generated_at"]})


if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", 5000))
    logger.info(f"Dashboard disponible en http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)