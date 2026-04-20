"""
email_notifier.py
Envia el reporte diario de threat intelligence por email usando SMTP.
Compatible con Gmail usando contrasenas de aplicacion.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logger = logging.getLogger(__name__)

SEVERITY_LABELS = {
    "critical": "[CRITICO]",
    "high": "[ALTO]",
    "medium": "[MEDIO]",
}


def build_html_body(articles: list[dict], api_data: dict) -> str:
    """
    Construye el cuerpo HTML del email con los articulos clasificados
    y datos de threat intelligence de APIs externas.
    """
    today = datetime.now().strftime("%Y-%m-%d")

    rows = ""
    if not articles:
        rows = "<p>No se encontraron items relevantes en las ultimas 24 horas.</p>"
    else:
        for article in articles:
            label = SEVERITY_LABELS.get(article.get("severity", "medium"), "[INFO]")
            summary = article.get("ai_summary", article.get("summary", ""))
            url = article.get("url", "#")
            rows += f"""
            <div style="margin-bottom:20px; border-left:4px solid #333; padding-left:12px;">
                <strong>{label}</strong> <a href="{url}">{article['title']}</a><br>
                <span style="color:#555;">{summary}</span>
            </div>
            """

    top_ips_html = ""
    top_ips = api_data.get("top_abusive_ips", [])
    if top_ips:
        top_ips_html = "<h3>IPs mas reportadas (AbuseIPDB)</h3><ul>"
        for entry in top_ips:
            top_ips_html += (
                f"<li>{entry['ip']} — Score: {entry['abuse_confidence_score']} "
                f"| Reportes: {entry['total_reports']} | Pais: {entry['country']}</li>"
            )
        top_ips_html += "</ul>"

    return f"""
    <html><body style="font-family:Arial,sans-serif;max-width:700px;margin:auto;">
        <h2>Threat Intel Digest — {today}</h2>
        <hr>
        {rows}
        {top_ips_html}
        <hr>
        <small>Generado automaticamente por Threat Intel Digest.</small>
    </body></html>
    """


def send(articles: list[dict], api_data: dict) -> bool:
    """
    Envia el reporte por email.
    Retorna True si el envio fue exitoso, False en caso contrario.
    """
    sender = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_PASSWORD")
    recipient = os.getenv("EMAIL_RECIPIENT")

    if not all([sender, password, recipient]):
        logger.error("Credenciales de email incompletas en .env.")
        return False

    today = datetime.now().strftime("%Y-%m-%d")
    subject = f"Threat Intel Digest — {today}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    html_body = build_html_body(articles, api_data)
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
        logger.info("Reporte enviado exitosamente por email.")
        return True

    except smtplib.SMTPException as e:
        logger.error(f"Error al enviar email: {e}")
        return False
