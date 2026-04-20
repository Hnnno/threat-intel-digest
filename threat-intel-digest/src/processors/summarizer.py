"""
summarizer.py
Resume articulos de ciberseguridad usando Claude (Anthropic API).
Extrae los puntos criticos de cada item de forma concisa.
"""

import os
import logging
import anthropic

logger = logging.getLogger(__name__)


def summarize_article(article: dict) -> str:
    """
    Recibe un articulo y retorna un resumen de 2-3 oraciones
    enfocado en el impacto de seguridad y acciones recomendadas.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("ANTHROPIC_API_KEY no configurada. Usando resumen original.")
        return article.get("summary", "Sin resumen disponible.")

    client = anthropic.Anthropic(api_key=api_key)

    prompt = f"""Eres un analista de ciberseguridad. Resume el siguiente articulo en 2-3 oraciones claras y concisas.
Enfocate en: que sistema o software esta afectado, cual es el riesgo concreto, y si hay alguna accion recomendada.
No uses emojis ni formato markdown. Responde solo con el resumen, sin introduccion.

Titulo: {article.get('title', '')}
Contenido: {article.get('summary', '')}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text.strip()

    except Exception as e:
        logger.error(f"Error al resumir articulo '{article.get('title')}': {e}")
        return article.get("summary", "Sin resumen disponible.")


def summarize_all(articles: list[dict]) -> list[dict]:
    """
    Agrega un campo 'ai_summary' a cada articulo con el resumen generado por IA.
    """
    for article in articles:
        article["ai_summary"] = summarize_article(article)
        logger.debug(f"Resumido: {article['title']}")
    return articles
