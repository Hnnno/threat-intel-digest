"""
telegram_notifier.py
Envia el reporte diario de threat intelligence a un canal o chat de Telegram.
"""

import os
import logging
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

SEVERITY_LABELS = {
    "critical": "[CRITICO]",
    "high": "[ALTO]",
    "medium": "[MEDIO]",
}


def build_message(articles: list[dict], api_data: dict) -> str:
    """
    Construye el texto del mensaje de Telegram a partir de los articulos
    clasificados y los datos de APIs de threat intel.
    """
    today = datetime.now().strftime("%Y-%m-%d")
    lines = [
        f"THREAT INTEL DIGEST — {today}",
        "=" * 36,
        "",
    ]

    if not articles:
        lines.append("No se encontraron items relevantes en las ultimas 24 horas.")
    else:
        for article in articles:
            label = SEVERITY_LABELS.get(article.get("severity", "medium"), "[INFO]")
            lines.append(f"{label} {article['title']}")
            lines.append(article.get("ai_summary", article.get("summary", "")))
            if article.get("url"):
                lines.append(article["url"])
            lines.append("")

    top_ips = api_data.get("top_abusive_ips", [])
    if top_ips:
        lines.append("IPs mas reportadas (AbuseIPDB):")
        for entry in top_ips:
            lines.append(
                f"  {entry['ip']} — Score: {entry['abuse_confidence_score']} "
                f"| Reportes: {entry['total_reports']} | Pais: {entry['country']}"
            )
        lines.append("")

    lines.append("=" * 36)
    lines.append(f"Items procesados: {len(articles)}")

    return "\n".join(lines)


def send(articles: list[dict], api_data: dict) -> bool:
    """
    Envia el reporte por Telegram.
    Retorna True si el envio fue exitoso, False en caso contrario.
    """
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not bot_token or not chat_id:
        logger.error("TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID no configurados.")
        return False

    message = build_message(articles, api_data)

    # Telegram tiene un limite de 4096 caracteres por mensaje
    chunks = [message[i:i+4096] for i in range(0, len(message), 4096)]

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    for chunk in chunks:
        payload = {
            "chat_id": chat_id,
            "text": chunk,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f"Error al enviar mensaje a Telegram: {e}")
            return False

    logger.info("Reporte enviado exitosamente por Telegram.")
    return True
