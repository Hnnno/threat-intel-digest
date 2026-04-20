"""
filter.py
Filtra y clasifica articulos por nivel de severidad
usando las palabras clave definidas en sources.yaml.
"""

import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "sources.yaml"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_keywords() -> dict:
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)
    return config.get("keywords", {})


def classify_article(article: dict, keywords: dict) -> str:
    """
    Asigna un nivel de severidad a un articulo basandose en palabras clave
    encontradas en el titulo o resumen.
    Retorna: 'critical', 'high', 'medium' o 'low'.
    """
    text = (article.get("title", "") + " " + article.get("summary", "")).lower()

    for level in ["critical", "high", "medium"]:
        for kw in keywords.get(level, []):
            if kw.lower() in text:
                return level

    return "low"


def filter_and_classify(articles: list[dict]) -> list[dict]:
    """
    Recibe la lista de articulos crudos y retorna solo los relevantes
    (severidad critical, high o medium), ordenados por severidad.
    """
    keywords = load_keywords()
    classified = []

    for article in articles:
        severity = classify_article(article, keywords)
        if severity == "low":
            continue
        article["severity"] = severity
        classified.append(article)

    classified.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 99))

    logger.info(f"Articulos relevantes tras filtrado: {len(classified)} / {len(articles)}")
    return classified
